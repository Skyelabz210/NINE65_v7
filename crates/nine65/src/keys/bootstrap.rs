//! Bootstrap Key and Key-Switch Key for Clockwork Bootstrap
//!
//! Generates the cryptographic material needed for bootstrapping:
//! - `BootstrapKey`: working secret key encrypted under bootstrap parameters
//! - `KeySwitchKey`: converts ciphertexts from boot key to working key

use crate::entropy::{require_secure_rng, FheRng, SecureRng};
use crate::errors::{Nine65Error, Nine65Result};
use crate::ops::rns_fhe::{
    DualRNSCiphertext, DualRNSEvalKey, DualRNSFullKeySet, DualRNSPoly, DualRNSPublicKey,
    DualRNSSecretKey, RNSFHEContext,
};
use crate::params::security_estimator::{CostModel, LatticeSecurityEstimator, SecretDistribution};
use crate::params::FHEConfig;
use zeroize::{Zeroize, Zeroizing};

/// NTT-friendly primes for the bootstrap modulus chain.
/// With q_small = t, bootstrap depth drops to ~1.
///
/// Ordering: work primes form a prefix (matching secure_128 → secure_256),
/// followed by extra primes for modswitch headroom. None may collide with
/// anchor primes [2013265921, 2281701377, 2483027969].
pub const BOOTSTRAP_PRIMES: [u64; 8] = [
    998244353,  // 2^23 * 7 * 17 + 1    (work prime 1-3)
    985661441,  // NTT-friendly 30-bit
    754974721,  // NTT-friendly 30-bit
    469762049,  // 2^26 * 7 + 1          (work prime 4, secure_128_deep)
    167772161,  // 2^25 * 5 + 1          (work prime 5, secure_192)
    1811939329, // 27 * 2^26 + 1         (extra for secure_192 modswitch)
    595591169,  // NTT-friendly 30-bit   (work prime 6, secure_256)
    645922817,  // NTT-friendly 30-bit   (extra for secure_256 modswitch)
];

/// Number of anchor primes for K-Elimination in bootstrap context.
pub const BOOTSTRAP_ANCHOR_COUNT: usize = 3;

/// Validate bootstrap primes meet the STRUCTURAL requirements a boot chain
/// needs before any security question is even meaningful to ask.
///
/// # Requirements
/// 1. NTT compatibility: (q - 1) % (2N) == 0 for all primes
/// 2. Pairwise coprimality: gcd(p_i, p_j) == 1 for all i ≠ j
///
/// # This is deliberately NOT a security check
///
/// Earlier revisions of this function took a `target_security` parameter and
/// refused the chain when `log2(product) < target_security`. GitHub issue
/// #83 found that call site (`BootstrapKey::generate`) computed
/// `target_security` FROM `boot_ctx.config.primes` — the very primes being
/// validated — via the same summed-per-lane-width formula this step then
/// re-derived and compared against itself. The check was satisfied by
/// construction for any nonempty prime list, regardless of the actual
/// declared security claim. See [`screen_bootstrap_security`] for the real
/// check: an exact-bit-length, dual-cost-model, factorization-aware screen
/// against a target the CALLER supplies (the work config's own claim, never
/// this function's own input).
///
/// # Arguments
/// - `primes`: Bootstrap prime moduli
/// - `n`: Polynomial degree (ring dimension)
///
/// # Errors
/// - `NTTConfigError` if any prime is not congruent to 1 mod 2N
/// - `NotCoprime` if any prime pair shares a factor
///
/// # Theorem Reference
/// - NTT: Requires q ≡ 1 (mod 2N) for primitive root existence
/// - CRT: Requires pairwise coprimality for unique reconstruction
pub fn validate_bootstrap_primes(primes: &[u64], n: usize) -> Nine65Result<()> {
    if primes.is_empty() {
        return Err(Nine65Error::InvalidParameter {
            message: "Bootstrap primes array is empty".to_string(),
        });
    }

    let two_n = 2 * n as u64;

    // 1. NTT compatibility check: (q - 1) % 2N == 0
    for (idx, &q) in primes.iter().enumerate() {
        if q == 0 {
            return Err(Nine65Error::NTTConfigError {
                message: format!("Bootstrap prime[{}] is zero", idx),
            });
        }

        if (q - 1) % two_n != 0 {
            return Err(Nine65Error::NTTConfigError {
                message: format!(
                    "Bootstrap prime[{}]={} not NTT-compatible: (q-1)%2N = {} (expected 0)",
                    idx,
                    q,
                    (q - 1) % two_n
                ),
            });
        }
    }

    // 2. Pairwise coprimality check
    for i in 0..primes.len() {
        for j in (i + 1)..primes.len() {
            let p_i = primes[i];
            let p_j = primes[j];
            let g = gcd_u64(p_i, p_j);

            if g != 1 {
                return Err(Nine65Error::NotCoprime {
                    m: p_i,
                    a: p_j,
                    gcd: g,
                });
            }
        }
    }

    Ok(())
}

/// Independent security screen for a bootstrap modulus chain (`Q_boot`).
///
/// This is the requirement-bearing fix for issue #83's tautology, split out
/// from [`validate_bootstrap_primes`] (structural-only) so the security
/// question and the structural question can never again be answered by the
/// same self-referential arithmetic:
///
/// 1. **Exact bit length, not summed lane widths.** `log_q_boot` is the
///    exact bit length of the boot chain's prime product (via
///    `LatticeSecurityEstimator::dual_estimate_with_factorization`'s
///    limb-multiplication accounting), not a sum of per-prime
///    `64 - leading_zeros()` widths. The two differ on real production
///    chains — see
///    `screen_bootstrap_security_uses_exact_product_bit_length_not_summed_widths`
///    for a concrete case using the actual `secure_128` boot chain.
/// 2. **Target independent of `Q_boot`.** `claimed_security` is whatever the
///    caller passes; this function never derives it from `primes`. The one
///    production call site (`BootstrapKey::generate`) passes the WORK
///    config's own `security_bits`, never a value computed from the boot
///    chain itself.
/// 3. **Both in-tree cost models, factorization-aware.** Reuses
///    `LatticeSecurityEstimator::dual_estimate_with_factorization` — the
///    crate's existing factorization-aware Core-SVP/MATZOV screen (see the
///    "STRUCTURAL MODULUS SCREEN" section of `params::security_estimator`'s
///    module doc), rather than re-implementing a second copy of it. Note
///    this is NOT what `SecureConfig::screened_security_dual` calls for
///    work chains today: that method uses the bit-width-only
///    `dual_estimate` (log_q in, no factorization, so it cannot refuse a
///    manufactured or composite modulus). This bootstrap screen is the
///    first production call site of the factorization-aware primitive;
///    migrating work chains onto it is a separate, not-yet-done change.
///
/// Every numeric field on [`BootstrapSecurityScreen`] is a SCREENING result
/// from the in-tree deterministic integer models, never an independent
/// lattice-security certificate — the same distinction
/// `params::secure_configs`'s module doc and
/// `SecureConfig::screened_security_dual` draw for work chains. Nothing here
/// is externally attested.
///
/// # Errors
/// Returns `Nine65Error::BootstrapSecurityUnscreenable` — a typed refusal,
/// never a guessed number — when the factorization-aware screen cannot
/// speak to this chain at all: a non-prime lane, a lane narrower than the
/// in-tree model's calibration floor, a repeated/non-coprime lane, or an
/// unreadable factorization. This does **not** return an error merely
/// because the chain screens below `claimed_security` — that is reported
/// via [`BootstrapSecurityScreen::meets_claim_under_both`] instead, the same
/// way `SecureConfig::secure_256` documents (rather than hard-fails on) its
/// own work-chain shortfall under MATZOV. Silently guessing a number would
/// be worse than an honest "below claim"; hard-failing key generation on it
/// would change which named configs can bootstrap today, which this change
/// does not do.
pub fn screen_bootstrap_security(
    primes: &[u64],
    n: usize,
    claimed_security: u32,
) -> Nine65Result<BootstrapSecurityScreen> {
    let factors: Vec<(u64, u32)> = primes.iter().map(|&p| (p, 1)).collect();
    let dual = LatticeSecurityEstimator::new(CostModel::CoreSVP).dual_estimate_with_factorization(
        n,
        &factors,
        SecretDistribution::Ternary,
        claimed_security,
    );

    let (core_svp_bits, matzov_bits) =
        match (dual.core_svp.effective_bits(), dual.matzov.effective_bits()) {
            (Some(core), Some(matzov)) => (core, matzov),
            _ => {
                return Err(Nine65Error::BootstrapSecurityUnscreenable {
                    reason: format!(
                        "boot chain {:?} (n={}) is outside the regime the in-tree \
                         security models are calibrated on: {}",
                        primes, n, dual.core_svp.analysis,
                    ),
                });
            }
        };

    Ok(BootstrapSecurityScreen {
        claimed_security,
        log_q_boot: dual.core_svp.total_log_q,
        core_svp_bits,
        matzov_bits,
        binding_bits: core_svp_bits.min(matzov_bits),
        meets_claim_under_both: dual.meets_both,
    })
}

/// Result of [`screen_bootstrap_security`]. See that function's doc for what
/// each field does and does not claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapSecurityScreen {
    /// The target this was screened against — the CALLER's declared claim,
    /// independent of `log_q_boot`.
    pub claimed_security: u32,
    /// Exact bit length of the boot chain's prime product.
    pub log_q_boot: u32,
    /// Core-SVP (conservative) screened bits, factorization-aware.
    pub core_svp_bits: u32,
    /// MATZOV (aggressive) screened bits, factorization-aware.
    pub matzov_bits: u32,
    /// The binding (minimum) of the two models above.
    pub binding_bits: u32,
    /// Whether `claimed_security` is met under BOTH in-tree models.
    pub meets_claim_under_both: bool,
}

/// Commit this build was compiled from (`git rev-parse HEAD`, captured by
/// `build.rs`). `"unknown"` when git was unavailable at build time (e.g. a
/// source tarball with no `.git`) — that is a provenance gap to report, not
/// a reason to fail the build.
pub const BUILD_COMMIT_SHA: &str = env!("NINE65_COMMIT_SHA");

/// Deterministic archival identity for one bootstrap-relevant modulus tuple:
/// ordered primes, ring dimension, plaintext modulus, error width, the
/// active feature set, and the commit this was computed from.
///
/// This is an identity/dedup key, not a security screen — see
/// [`screen_bootstrap_security`] for the number. `digest` is a 64-bit
/// FNV-1a hash (integer-only, no floats) over the canonical byte encoding of
/// `primes`, `n`, `t`, `eta` and `features`, deliberately EXCLUDING
/// `commit_sha`: the same mathematical tuple must fingerprint identically
/// across commits, with `commit_sha` recording only when that particular
/// computation was taken, not folded into the identity itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapTupleFingerprint {
    /// Ordered boot-chain primes (main RNS chain only; K-Elimination anchor
    /// primes are a separate structure and not part of `Q_boot`).
    pub primes: Vec<u64>,
    pub n: usize,
    pub t: u64,
    pub eta: usize,
    /// Active Cargo feature flags that can affect bootstrap-relevant
    /// arithmetic or sampling, in one fixed declared order.
    pub features: Vec<&'static str>,
    pub commit_sha: &'static str,
    pub digest: u64,
}

const FNV_OFFSET_BASIS_64: u64 = 0xcbf29ce484222325;
const FNV_PRIME_64: u64 = 0x0000_0100_0000_01b3;

/// FNV-1a over raw bytes. Integer-only, no floats; deterministic for a given
/// byte sequence regardless of platform, process, or call order.
fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET_BASIS_64;
    for &byte in bytes {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME_64);
    }
    hash
}

/// Cargo features that can change bootstrap-relevant arithmetic or sampling,
/// in one fixed declared order — never a `HashSet`/`HashMap` iteration
/// order, which is not guaranteed stable across runs.
fn active_bootstrap_features() -> Vec<&'static str> {
    let mut features = Vec::new();
    if cfg!(feature = "ntt_fft") {
        features.push("ntt_fft");
    }
    if cfg!(feature = "reference_ntt") {
        features.push("reference_ntt");
    }
    if cfg!(feature = "parallel") {
        features.push("parallel");
    }
    if cfg!(feature = "clockwork") {
        features.push("clockwork");
    }
    if cfg!(feature = "exact_rational") {
        features.push("exact_rational");
    }
    if cfg!(feature = "shadow-entropy") {
        features.push("shadow-entropy");
    }
    if cfg!(feature = "adaptive-threading") {
        features.push("adaptive-threading");
    }
    if cfg!(feature = "accelerated") {
        features.push("accelerated");
    }
    if cfg!(feature = "deterministic_rng") {
        features.push("deterministic_rng");
    }
    if cfg!(feature = "allow_insecure") {
        features.push("allow_insecure");
    }
    features
}

/// Compute the archival fingerprint for one bootstrap-relevant tuple.
///
/// Deterministic and reproducible: the same `(primes, n, t, eta)` on the
/// same build always produces the same `digest`, regardless of call order,
/// process, or how many times it is called — pinned by
/// `bootstrap_tuple_fingerprint_is_deterministic_across_calls`.
pub fn bootstrap_tuple_fingerprint(
    primes: &[u64],
    n: usize,
    t: u64,
    eta: usize,
) -> BootstrapTupleFingerprint {
    let features = active_bootstrap_features();

    let mut bytes = Vec::with_capacity(primes.len() * 8 + 64);
    bytes.extend_from_slice(&(primes.len() as u64).to_le_bytes());
    for &p in primes {
        bytes.extend_from_slice(&p.to_le_bytes());
    }
    bytes.extend_from_slice(&(n as u64).to_le_bytes());
    bytes.extend_from_slice(&t.to_le_bytes());
    bytes.extend_from_slice(&(eta as u64).to_le_bytes());
    bytes.extend_from_slice(&(features.len() as u64).to_le_bytes());
    for feature in &features {
        bytes.extend_from_slice(&(feature.len() as u64).to_le_bytes());
        bytes.extend_from_slice(feature.as_bytes());
    }

    BootstrapTupleFingerprint {
        primes: primes.to_vec(),
        n,
        t,
        eta,
        features,
        commit_sha: BUILD_COMMIT_SHA,
        digest: fnv1a_64(&bytes),
    }
}

/// GCD using Euclidean algorithm for u64.
fn gcd_u64(a: u64, b: u64) -> u64 {
    if b == 0 {
        a
    } else {
        gcd_u64(b, a % b)
    }
}

/// Upper bound on the bit length of the product of `primes`, computed as an
/// integer sum of individual bit lengths (`sum(64 - p.leading_zeros())`).
///
/// This never underestimates: `bitlen(a*b) <= bitlen(a) + bitlen(b)`, so the
/// sum is a safe (if occasionally loose, by up to `primes.len() - 1` bits)
/// upper bound on `bitlen(product)`, computed with plain `u32` arithmetic
/// that cannot itself overflow or panic. Used to typed-refuse full-width
/// sampling contexts *before* ever constructing the exact `U256` product,
/// so an oversized `Q_boot` returns a typed error instead of risking a panic
/// deep inside `U256` multiplication/shift code that assumes the product
/// fits in 256 bits.
pub(crate) fn q_boot_bit_upper_bound(primes: &[u64]) -> u32 {
    primes
        .iter()
        .map(|&p| if p == 0 { 0 } else { 64 - p.leading_zeros() })
        .sum()
}

/// `U256::product_u64s` / `U256::mul_u64` assume (and `assert!`/panic if not)
/// that the true product fits in 256 bits, and the exact rejection sampler's
/// two-limb draw additionally needs a strict `< 256`-bit modulus for its
/// high-limb mask shift to stay in `u128`'s valid `0..128` shift range (see
/// `RNSFHEContext::sample_uniform_dual_poly`). Refuse, with a typed error,
/// any boot prime set whose product this sampler cannot represent, rather
/// than reaching either of those panics. Every shipped `BOOTSTRAP_PRIMES`
/// prefix (up to all 8 primes, each <= 31 bits) sums to well under 256 bits,
/// so this only fires for a boot chain configuration that does not exist
/// yet.
pub(crate) fn ensure_q_boot_representable(primes: &[u64]) -> Nine65Result<()> {
    let bits = q_boot_bit_upper_bound(primes);
    if bits >= 256 {
        return Err(Nine65Error::BootstrapOverflow {
            operation: format!(
                "Q_boot bit-length upper bound {} >= 256-bit full-width sampler capacity \
                 (primes={:?}); this boot prime set cannot be sampled exactly by \
                 the current uniform rejection sampler",
                bits, primes
            ),
        });
    }
    Ok(())
}

/// Bootstrap key: working secret key encrypted under bootstrap parameters.
///
/// Since s has ternary coefficients {-1, 0, 1}, encrypting it introduces
/// minimal noise — exactly what we want for tight bootstrap noise budget.
pub struct BootstrapKey {
    /// Encryption of working secret key under bootstrap parameters.
    pub enc_s: DualRNSCiphertext,
    /// Evaluation key for relinearization within bootstrap circuit.
    pub eval_key: DualRNSEvalKey,
    /// Bootstrap public key.
    pub public_key: DualRNSPublicKey,
    /// Working plaintext modulus t (= q_small in our scheme).
    pub t_work: u64,
    /// Q_min: product of first 2 working primes (bootstrap trigger point).
    pub q_min: u128,
}

/// Key-switch key: converts ciphertext under s_boot to s_work.
/// Follows same gadget decomposition pattern as GaloisKey.
///
/// ksk[l] = (b_l, a_l) where b_l = -a_l*s_work + e_l + s_boot*base^l
pub struct KeySwitchKey {
    /// Key-switch components: ksk[l] = (b_l, a_l)
    pub ksk: Vec<(DualRNSPoly, DualRNSPoly)>,
    /// Decomposition base
    pub decomp_base: u64,
    /// Number of decomposition digits
    pub num_digits: usize,
}

/// Complete bootstrap key material (BSK + KSK + boot secret key for testing)
pub struct BootstrapKeySet {
    pub bsk: BootstrapKey,
    pub ksk: KeySwitchKey,
    /// Boot secret key — needed for testing/verification only.
    /// In production, this should be discarded after KSK generation.
    pub boot_sk: DualRNSSecretKey,
}

impl BootstrapKey {
    /// Generate bootstrap key material using the OS CSPRNG. This is the
    /// production entry point.
    pub fn generate_secure(
        work_config: &FHEConfig,
        boot_ctx: &RNSFHEContext,
        boot_keys: &DualRNSFullKeySet,
        work_sk: &DualRNSSecretKey,
    ) -> Nine65Result<Self> {
        let mut rng = SecureRng::new();
        Self::generate(work_config, boot_ctx, boot_keys, work_sk, &mut rng)
    }

    /// Generate bootstrap key material.
    ///
    /// 1. Validates bootstrap primes meet cryptographic requirements
    /// 2. Creates boot config with BOOTSTRAP_PRIMES
    /// 3. Generates boot key pair
    /// 4. Encodes work sk as Z_t polynomial: {-1,0,1} -> {t-1,0,1}
    /// 5. Encrypts encoded sk under boot pk
    ///
    /// `enc_s` is literally `Enc(work_sk)` -- the working secret key,
    /// encrypted. Generic over `FheRng`; `require_secure_rng` below rejects
    /// a non-secure RNG at this entry point outside test/debug builds and
    /// the `allow_insecure` feature. Prefer [`Self::generate_secure`] unless
    /// you have a specific, documented reason to inject a different RNG.
    pub fn generate<R: FheRng>(
        work_config: &FHEConfig,
        boot_ctx: &RNSFHEContext,
        boot_keys: &DualRNSFullKeySet,
        work_sk: &DualRNSSecretKey,
        rng: &mut R,
    ) -> Nine65Result<Self> {
        require_secure_rng(rng, "BootstrapKey::generate");

        let t = work_config.t;
        let n = work_config.n;

        // Structural validation: NTT compatibility and pairwise coprimality
        // of the boot chain. Deliberately not a security check -- see below.
        validate_bootstrap_primes(&boot_ctx.config.primes, n)?;

        // Security screening (issue #83 fix). The OLD code computed a
        // "target" from `boot_ctx.config.primes` -- the very primes under
        // test -- via the same summed-lane-width formula this validated
        // against, so it was satisfied by construction regardless of what
        // was actually claimed. The target here is instead
        // `work_config.security_bits`, the caller's OWN declared claim,
        // entirely independent of `Q_boot`'s width. This can only return an
        // error when the chain cannot be screened at all (a structural /
        // out-of-regime problem, e.g. a non-prime or too-narrow lane); it
        // does not fail closed merely because the boot chain screens below
        // the claim, so it does not change which named configs can generate
        // bootstrap key material today. See `screen_bootstrap_security`'s
        // doc and `every_shipped_config_boot_chain_screens_against_its_own_claim`
        // (in this module's tests) for the one shipped config where that
        // distinction currently matters.
        let _boot_security_screen = screen_bootstrap_security(
            &boot_ctx.config.primes,
            n,
            work_config.security_bits as u32,
        )?;

        // Encode working secret key for Z_t plaintext space.
        // Ternary {-1, 0, 1} -> {t-1, 0, 1} mod t.
        // The sk main[0] coefficients are in {0, 1, p-1} where p-1 represents -1.
        let work_s_coeffs = &work_sk.s.main[0];
        let first_work_prime = work_config.primes[0];

        // We need to encode s as a single scalar per coefficient for encrypt_dual.
        // encrypt_dual takes a single u64 message. We need poly encryption.
        // Instead, we'll build the encoded polynomial and use trivial + noise approach.
        //
        // For the bootstrap key, we encrypt the full polynomial representing s.
        // We'll do this coefficient-by-coefficient is not efficient; instead we
        // use the RNSFHEContext's polynomial-level encrypt.
        //
        // Approach: encrypt m=0, then add Δ_boot * s_encoded into c0.
        // This gives Enc_boot(s_work) with proper noise characteristics.

        // Step 1: Create an encryption of 0 under boot pk
        let ct_zero = boot_ctx.encrypt_dual_with_rng(0, &boot_keys.public_key, rng);

        // Step 2: Add Δ_boot * s_encoded into c0 (coefficient by coefficient)
        let mut c0_main = ct_zero.c0.main.clone();
        let mut c0_anchor = ct_zero.c0.anchor.clone();

        for j in 0..n {
            let coeff = work_s_coeffs[j];
            // Map from mod-p representation to signed: 0->0, 1->1, p-1->-1
            let s_val: i64 = if coeff == 0 {
                0
            } else if coeff == 1 {
                1
            } else if coeff == first_work_prime - 1 {
                -1
            } else {
                // Non-ternary coefficient — shouldn't happen with proper key gen
                0
            };

            // Encode as Z_t value: -1 -> t-1, 0 -> 0, 1 -> 1
            let s_encoded = if s_val < 0 {
                t - ((-s_val) as u64)
            } else {
                s_val as u64
            };

            // Add Δ_boot * s_encoded to c0[j] for each boot prime
            for (i, &bp) in boot_ctx.config.primes.iter().enumerate() {
                let delta_i = boot_ctx.delta_rns[i];
                let contribution = (delta_i as u128 * s_encoded as u128) % bp as u128;
                c0_main[i][j] = ((c0_main[i][j] as u128 + contribution) % bp as u128) as u64;
            }

            // Same for anchor primes
            for (i, &ap) in boot_ctx.dual_rns.anchor.primes.iter().enumerate() {
                // Compute Δ_boot mod anchor_prime
                // Δ_boot = Q_boot / t, we need Δ mod ap
                let q_boot_mod_ap: u128 = boot_ctx.config.primes.iter().fold(1u128, |acc, &p| {
                    (acc * (p as u128 % ap as u128)) % ap as u128
                });
                let t_inv_ap = mod_inverse_u128(t as u128, ap as u128).unwrap_or(0);
                let delta_anchor = (q_boot_mod_ap * t_inv_ap) % ap as u128;

                let contribution = (delta_anchor * s_encoded as u128) % ap as u128;
                c0_anchor[i][j] = ((c0_anchor[i][j] as u128 + contribution) % ap as u128) as u64;
            }
        }

        let enc_s = DualRNSCiphertext {
            c0: DualRNSPoly {
                main: c0_main,
                anchor: c0_anchor,
                n,
            },
            c1: ct_zero.c1,
            level: ct_zero.level,
        };

        // Q_min: product of first 2 working primes
        let q_min = work_config.primes[0] as u128 * work_config.primes[1] as u128;

        Ok(Self {
            enc_s,
            eval_key: boot_keys.eval_key.clone(),
            public_key: boot_keys.public_key.clone(),
            t_work: t,
            q_min,
        })
    }
}

impl KeySwitchKey {
    /// Generate key-switch key: converts Enc_{s_boot} -> Enc_{s_work}.
    ///
    /// Follows the same gadget decomposition pattern as GaloisKey generation.
    /// For each digit l: ksk[l] = (-a_l*s_work + e_l + s_boot*base^l, a_l)
    pub fn generate<R: FheRng>(
        boot_sk: &DualRNSSecretKey,
        work_sk: &DualRNSSecretKey,
        boot_ctx: &RNSFHEContext,
        rng: &mut R,
    ) -> Nine65Result<Self> {
        let n = boot_ctx.n;
        let decomp_base: u64 = 1u64 << 10; // Smaller base for less noise
        let q_bits = boot_ctx.q_bits;
        let base_bits = decomp_base.trailing_zeros() as usize;
        let num_digits = q_bits.div_ceil(base_bits);

        let num_main = boot_ctx.config.primes.len();
        let num_anchor = boot_ctx.dual_rns.anchor.primes.len();

        // The gadget mask `a_l` must be exact full-width uniform on
        // [0, Q_boot), not a per-lane independent draw -- typed-refuse
        // before sampling if this boot chain's Q_boot exceeds what the
        // rejection sampler can represent (see `ensure_q_boot_representable`).
        ensure_q_boot_representable(&boot_ctx.config.primes)?;

        // Get the ternary representation from work_sk.
        // work_sk.s.main[0] has coefficients mod work_primes[0].
        // For a ternary key, they are in {0, 1, work_primes[0]-1}.
        // We need to re-encode under each boot prime. This is the working
        // secret key in a bare Vec -- zeroize the temporary on drop.
        let work_s_signed: Zeroizing<Vec<i64>> = Zeroizing::new(
            work_sk.s.main[0]
                .iter()
                .map(|&c| {
                    if c == 0 {
                        0i64
                    } else if c == 1 {
                        1i64
                    } else {
                        -1i64 // p-1 represents -1 for ternary
                    }
                })
                .collect(),
        );

        // Encode work_sk under boot primes
        let work_sk_boot_main: Vec<Vec<u64>> = boot_ctx
            .config
            .primes
            .iter()
            .map(|&bp| {
                work_s_signed
                    .iter()
                    .map(|&v| if v >= 0 { v as u64 } else { bp - ((-v) as u64) })
                    .collect()
            })
            .collect();
        let work_sk_boot_anchor: Vec<Vec<u64>> = boot_ctx
            .dual_rns
            .anchor
            .primes
            .iter()
            .map(|&ap| {
                work_s_signed
                    .iter()
                    .map(|&v| if v >= 0 { v as u64 } else { ap - ((-v) as u64) })
                    .collect()
            })
            .collect();
        let mut work_sk_boot = DualRNSPoly {
            main: work_sk_boot_main,
            anchor: work_sk_boot_anchor,
            n,
        };

        let mut ksk_pairs = Vec::with_capacity(num_digits);

        // power_of_base[i] = base^l mod each prime
        let mut power_main: Vec<u64> = boot_ctx.config.primes.iter().map(|_| 1u64).collect();
        let mut power_anchor: Vec<u64> = boot_ctx
            .dual_rns
            .anchor
            .primes
            .iter()
            .map(|_| 1u64)
            .collect();

        for _l in 0..num_digits {
            // a_l: exact full-width rejection sampling uniform on
            // [0, Q_boot), reduced independently into every main/anchor
            // lane so both tracks describe the same integer. Previously
            // each lane was sampled independently mod its own prime, so
            // main and anchor did not even encode the same value, let
            // alone one uniform over the full boot modulus -- the same
            // narrow-support class of bug issue #82 found in the circular
            // bootstrap PK mask (`ClockworkBootstrap::generate_circular_pk`).
            let a_l = boot_ctx.sample_uniform_dual_poly(rng, &boot_ctx.config.primes);

            // e_l = small error (CBD eta=3)
            let e_signed: Vec<i64> = (0..n)
                .map(|_| {
                    let eta = boot_ctx.config.eta;
                    let mut sum: i64 = 0;
                    for _ in 0..eta {
                        let a = (rng.next_u64() & 1) as i64;
                        let b = (rng.next_u64() & 1) as i64;
                        sum += a - b;
                    }
                    sum
                })
                .collect();

            // b_l = -a_l * s_work + e_l + s_boot * base^l
            // All computations mod each prime
            let mut b_main: Vec<Vec<u64>> = vec![vec![0u64; n]; num_main];
            let mut b_anchor: Vec<Vec<u64>> = vec![vec![0u64; n]; num_anchor];

            // Main primes
            for i in 0..num_main {
                let p = boot_ctx.config.primes[i];
                let p128 = p as u128;

                // NTT multiply: a_l * s_work
                let a_s_work =
                    boot_ctx.ntt_engines[i].multiply(&a_l.main[i], &work_sk_boot.main[i]);

                for j in 0..n {
                    // -a*s_work
                    let neg_as = if a_s_work[j] == 0 {
                        0u64
                    } else {
                        p - a_s_work[j]
                    };

                    // + e_l
                    let e_mod = if e_signed[j] >= 0 {
                        e_signed[j] as u64
                    } else {
                        p - ((-e_signed[j]) as u64)
                    };

                    // + s_boot * base^l
                    let s_boot_val = boot_sk.s.main[i][j] as u128;
                    let power_val = power_main[i] as u128;
                    let s_boot_contrib = ((s_boot_val * power_val) % p128) as u64;

                    b_main[i][j] =
                        ((neg_as as u128 + e_mod as u128 + s_boot_contrib as u128) % p128) as u64;
                }
            }

            // Anchor primes
            for i in 0..num_anchor {
                let p = boot_ctx.dual_rns.anchor.primes[i];
                let p128 = p as u128;

                let a_s_work = boot_ctx.dual_rns.anchor.ntt_engines[i]
                    .multiply(&a_l.anchor[i], &work_sk_boot.anchor[i]);

                for j in 0..n {
                    let neg_as = if a_s_work[j] == 0 {
                        0u64
                    } else {
                        p - a_s_work[j]
                    };
                    let e_mod = if e_signed[j] >= 0 {
                        e_signed[j] as u64
                    } else {
                        p - ((-e_signed[j]) as u64)
                    };
                    let s_boot_val = boot_sk.s.anchor[i][j] as u128;
                    let power_val = power_anchor[i] as u128;
                    let s_boot_contrib = ((s_boot_val * power_val) % p128) as u64;

                    b_anchor[i][j] =
                        ((neg_as as u128 + e_mod as u128 + s_boot_contrib as u128) % p128) as u64;
                }
            }

            let b_l = DualRNSPoly {
                main: b_main,
                anchor: b_anchor,
                n,
            };

            ksk_pairs.push((b_l, a_l));

            // Update powers: power *= base mod each prime
            for i in 0..num_main {
                let p = boot_ctx.config.primes[i];
                power_main[i] = ((power_main[i] as u128 * decomp_base as u128) % p as u128) as u64;
            }
            for i in 0..num_anchor {
                let p = boot_ctx.dual_rns.anchor.primes[i];
                power_anchor[i] =
                    ((power_anchor[i] as u128 * decomp_base as u128) % p as u128) as u64;
            }
        }

        // work_sk_boot holds the working secret key re-encoded under boot
        // primes; it is no longer needed once the gadget pairs are built.
        work_sk_boot.zeroize();

        Ok(Self {
            ksk: ksk_pairs,
            decomp_base,
            num_digits,
        })
    }
}

/// Modular inverse via extended GCD for u128. Zero floating-point.
pub fn mod_inverse_u128(a: u128, m: u128) -> Option<u128> {
    let (g, x, _) = extended_gcd_i128(a as i128, m as i128);
    if g != 1 {
        return None;
    }
    Some(((x % m as i128 + m as i128) % m as i128) as u128)
}

fn extended_gcd_i128(a: i128, b: i128) -> (i128, i128, i128) {
    if a == 0 {
        return (b, 0, 1);
    }
    let (g, x1, y1) = extended_gcd_i128(b % a, a);
    (g, y1 - (b / a) * x1, x1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::bootstrap::crt_reconstruct_2;

    #[test]
    fn test_crt_reconstruct_2_boundary_values() {
        let p0 = BOOTSTRAP_PRIMES[0] as u128;
        let p1 = BOOTSTRAP_PRIMES[1] as u128;
        let p0_inv = mod_inverse_u128(p0, p1).expect("Inverse exists");
        let prod = p0 * p1;

        for x in [0u128, 1, p0 - 1, p0, p0 + 1, prod / 2, prod - 1] {
            let r0 = x % p0;
            let r1 = x % p1;
            let reconstructed = crt_reconstruct_2(r0, r1, p0, p1, p0_inv);
            assert_eq!(reconstructed, x, "CRT boundary failed for x={}", x);
        }
    }

    #[test]
    fn test_crt_reconstruct_2_all_bootstrap_prime_pairs() {
        for i in 0..BOOTSTRAP_PRIMES.len() {
            for j in (i + 1)..BOOTSTRAP_PRIMES.len() {
                let p0 = BOOTSTRAP_PRIMES[i] as u128;
                let p1 = BOOTSTRAP_PRIMES[j] as u128;
                let p0_inv = mod_inverse_u128(p0, p1)
                    .unwrap_or_else(|| panic!("No inverse for ({}, {})", p0, p1));

                let test_vals = [0u128, 1, 42, p0 - 1, p0, p0 * p1 - 1];
                for &x in &test_vals {
                    let r0 = x % p0;
                    let r1 = x % p1;
                    let result = crt_reconstruct_2(r0, r1, p0, p1, p0_inv);
                    assert_eq!(result, x, "CRT pair ({},{}) failed for x={}", p0, p1, x);
                }
            }
        }
    }

    #[test]
    fn test_mod_inverse_known_answers() {
        // inv(3, 7) = 5 because 3*5 = 15 ≡ 1 (mod 7)
        assert_eq!(mod_inverse_u128(3, 7), Some(5));
        // inv(1, p) = 1 for any p
        for &p in &BOOTSTRAP_PRIMES {
            assert_eq!(mod_inverse_u128(1, p as u128), Some(1));
        }
        // inv(p-1, p) = p-1 because (p-1)*(p-1) = p²-2p+1 ≡ 1 (mod p)
        for &p in &BOOTSTRAP_PRIMES {
            let p128 = p as u128;
            assert_eq!(mod_inverse_u128(p128 - 1, p128), Some(p128 - 1));
        }
    }

    #[test]
    fn test_mod_inverse_no_inverse_exists() {
        assert_eq!(mod_inverse_u128(0, 7), None);
        assert_eq!(mod_inverse_u128(4, 8), None);
        assert_eq!(mod_inverse_u128(6, 9), None);
    }

    #[test]
    fn test_mod_inverse_identity_and_self_inverse() {
        // inv(1, m) = 1 for all m > 1
        for m in [3u128, 7, 13, 997, 65537, BOOTSTRAP_PRIMES[0] as u128] {
            assert_eq!(mod_inverse_u128(1, m), Some(1), "inv(1, {}) should be 1", m);
        }
        // inv(p-1, p) = p-1 for all primes
        for &p in &BOOTSTRAP_PRIMES {
            let p128 = p as u128;
            let inv = mod_inverse_u128(p128 - 1, p128).expect("Inverse exists for p-1 mod p");
            assert_eq!(inv, p128 - 1, "inv(p-1, p) should be p-1 for p={}", p);
        }
    }

    #[test]
    fn test_crt_reconstruct_2_commutativity() {
        let p0 = BOOTSTRAP_PRIMES[0] as u128;
        let p1 = BOOTSTRAP_PRIMES[1] as u128;
        let p0_inv = mod_inverse_u128(p0, p1).expect("Inverse");
        let p1_inv = mod_inverse_u128(p1, p0).expect("Inverse");

        for x in [0u128, 42, 123456789, p0 * p1 / 3, p0 * p1 - 1] {
            let r0 = x % p0;
            let r1 = x % p1;
            let result_01 = crt_reconstruct_2(r0, r1, p0, p1, p0_inv);
            let result_10 = crt_reconstruct_2(r1, r0, p1, p0, p1_inv);
            assert_eq!(result_01, result_10, "CRT commutativity failed for x={}", x);
        }
    }

    #[test]
    fn test_crt_reconstruct_2_large_values() {
        let p0 = BOOTSTRAP_PRIMES[0] as u128;
        let p1 = BOOTSTRAP_PRIMES[1] as u128;
        let p0_inv = mod_inverse_u128(p0, p1).expect("Inverse");
        let prod = p0 * p1;

        // Test values near the upper boundary
        for offset in [0u128, 1, 2, 100, p0, p1] {
            let x = prod - 1 - offset;
            let r0 = x % p0;
            let r1 = x % p1;
            let result = crt_reconstruct_2(r0, r1, p0, p1, p0_inv);
            assert_eq!(result, x, "CRT large value failed for x={}", x);
        }
    }

    #[test]
    fn test_mod_inverse_all_bootstrap_primes() {
        // Every pair of BOOTSTRAP_PRIMES should have valid modular inverses
        for i in 0..BOOTSTRAP_PRIMES.len() {
            for j in 0..BOOTSTRAP_PRIMES.len() {
                if i == j {
                    continue;
                }
                let a = BOOTSTRAP_PRIMES[i] as u128;
                let m = BOOTSTRAP_PRIMES[j] as u128;
                let inv = mod_inverse_u128(a, m);
                assert!(
                    inv.is_some(),
                    "No inverse for BOOTSTRAP_PRIMES[{}]={} mod BOOTSTRAP_PRIMES[{}]={}",
                    i,
                    a,
                    j,
                    m
                );
                let inv_val = inv.unwrap();
                assert_eq!(
                    (a * inv_val) % m,
                    1,
                    "a*inv != 1 mod m for a={}, m={}, inv={}",
                    a,
                    m,
                    inv_val
                );
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // BOOTSTRAP PRIME VALIDATION TESTS
    // ═══════════════════════════════════════════════════════════════════

    #[ignore = "VESTIGIAL: asserts validate_bootstrap_primes accepts BOOTSTRAP_PRIMES at N=4096. The validator and the constant it validates exist only to gate bootstrap key material. NOTE: the NTT-compatibility and coprimality checks inside it are generic and live; if BOOTSTRAP_PRIMES is retired, re-express those checks against the work basis under a non-bootstrap name rather than restoring this test. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_validate_bootstrap_primes_valid_set() {
        // BOOTSTRAP_PRIMES should pass validation for N=4096
        let result = validate_bootstrap_primes(&BOOTSTRAP_PRIMES, 4096);
        assert!(
            result.is_ok(),
            "BOOTSTRAP_PRIMES should be valid: {:?}",
            result.err()
        );
    }

    #[ignore = "VESTIGIAL: asserts validate_bootstrap_primes rejects a prime not congruent to 1 mod 2N with NTTConfigError — bootstrap-basis validation. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_validate_bootstrap_primes_ntt_incompatible() {
        // Prime not congruent to 1 mod 2N should fail
        let bad_primes = [17u64]; // 17 is prime but (17-1) % (2*4096) != 0
        let result = validate_bootstrap_primes(&bad_primes, 4096);

        assert!(result.is_err(), "Non-NTT-compatible prime should fail");
        match result.err().unwrap() {
            Nine65Error::NTTConfigError { message } => {
                assert!(message.contains("not NTT-compatible"));
            }
            other => panic!("Expected NTTConfigError, got {:?}", other),
        }
    }

    #[ignore = "VESTIGIAL: asserts validate_bootstrap_primes rejects gcd(9, 21) = 3 with NotCoprime — bootstrap-basis validation. Coprimality itself remains architecturally live; only its application to the bootstrap prime set is quarantined. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_validate_bootstrap_primes_not_coprime() {
        // Use NTT-compatible composites that share a factor
        // For N=2: 2N=4, so we need q ≡ 1 (mod 4)
        // 9 = 3*3, 21 = 3*7, both ≡ 1 (mod 4), gcd(9, 21) = 3
        let not_coprime = [9u64, 21u64]; // gcd(9, 21) = 3
        let result = validate_bootstrap_primes(&not_coprime, 2);

        assert!(result.is_err(), "Non-coprime values should fail");
        match result.err().unwrap() {
            Nine65Error::NotCoprime { m, a, gcd } => {
                assert_eq!(gcd, 3);
                assert!((m == 9 && a == 21) || (m == 21 && a == 9));
            }
            other => panic!("Expected NotCoprime, got {:?}", other),
        }
    }

    #[ignore = "VESTIGIAL: asserts validate_bootstrap_primes rejects an empty bootstrap prime array with InvalidParameter. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_validate_bootstrap_primes_empty_array() {
        let empty: &[u64] = &[];
        let result = validate_bootstrap_primes(empty, 4096);

        assert!(result.is_err(), "Empty prime array should fail");
        match result.err().unwrap() {
            Nine65Error::InvalidParameter { message } => {
                assert!(message.contains("empty"));
            }
            other => panic!("Expected InvalidParameter, got {:?}", other),
        }
    }

    #[ignore = "VESTIGIAL: asserts validate_bootstrap_primes rejects a zero entry in the bootstrap prime array with NTTConfigError. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_validate_bootstrap_primes_zero_prime() {
        let with_zero = [0u64, 998244353];
        let result = validate_bootstrap_primes(&with_zero, 4096);

        assert!(result.is_err(), "Zero prime should fail");
        match result.err().unwrap() {
            Nine65Error::NTTConfigError { message } => {
                assert!(message.contains("zero"));
            }
            other => panic!("Expected NTTConfigError, got {:?}", other),
        }
    }

    #[ignore = "VESTIGIAL: asserts BOOTSTRAP_PRIMES either validate or fail only with NTTConfigError across N in [1024, 2048, 4096, 8192]. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_validate_bootstrap_primes_multiple_degrees() {
        // Test that BOOTSTRAP_PRIMES work for various N values
        for &n in &[1024, 2048, 4096, 8192] {
            let result = validate_bootstrap_primes(&BOOTSTRAP_PRIMES, n);
            // Note: May fail for smaller N if (q-1) % 2N != 0
            // The actual BOOTSTRAP_PRIMES are designed for specific N ranges
            if result.is_err() {
                // This is expected - not all primes work for all N
                match result.err().unwrap() {
                    Nine65Error::NTTConfigError { .. } => {
                        // Expected for incompatible N
                    }
                    other => panic!("Unexpected error for N={}: {:?}", n, other),
                }
            }
        }
    }

    // The two tests that used to live here --
    // `test_validate_bootstrap_primes_insufficient_security` and
    // `test_validate_bootstrap_primes_first_two_only` -- asserted that
    // `validate_bootstrap_primes` itself refused a chain for being too
    // narrow against a `target_security` argument. That behavior moved to
    // `screen_bootstrap_security` (issue #83): `validate_bootstrap_primes`
    // is now structural-only and no longer takes a security target at all,
    // so those two tests no longer describe anything the function does.
    // Their replacements are the WR-5B block below, which is not
    // `#[ignore]`d: unlike the bootstrap circuit's own roundtrip suites,
    // these test pure validation/screening arithmetic, not the (VESTIGIAL)
    // bootstrap circuit itself.

    #[test]
    fn test_gcd_u64_basic() {
        assert_eq!(gcd_u64(48, 18), 6);
        assert_eq!(gcd_u64(17, 13), 1);
        assert_eq!(gcd_u64(100, 25), 25);
        assert_eq!(gcd_u64(7, 0), 7);
        assert_eq!(gcd_u64(0, 11), 11);
    }

    #[test]
    fn test_gcd_u64_bootstrap_primes_coprime() {
        // All bootstrap primes should be pairwise coprime
        for i in 0..BOOTSTRAP_PRIMES.len() {
            for j in (i + 1)..BOOTSTRAP_PRIMES.len() {
                let g = gcd_u64(BOOTSTRAP_PRIMES[i], BOOTSTRAP_PRIMES[j]);
                assert_eq!(
                    g, 1,
                    "BOOTSTRAP_PRIMES[{}]={} and [{}]={} should be coprime",
                    i, BOOTSTRAP_PRIMES[i], j, BOOTSTRAP_PRIMES[j]
                );
            }
        }
    }

    #[ignore = "VESTIGIAL: asserts BootstrapKey::generate succeeds against a config built from BOOTSTRAP_PRIMES — generation of bootstrap key material itself. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
    #[test]
    fn test_bootstrap_key_generation_validates_primes() {
        use crate::entropy::ShadowHarvester;
        use crate::ops::rns_fhe::RNSFHEContext;
        use crate::params::SecureConfig;

        // Create a secure config (this will use BOOTSTRAP_PRIMES internally)
        let config = SecureConfig::secure_128();
        let work_config = config.config;

        // Create bootstrap context with valid primes
        let boot_config = FHEConfig {
            n: work_config.n,
            primes: BOOTSTRAP_PRIMES.to_vec(),
            q: BOOTSTRAP_PRIMES[0], // Use first prime as representative
            t: work_config.t,
            eta: work_config.eta,
            security_bits: 128,
            name: "test_boot_config",
        };
        let boot_ctx = RNSFHEContext::new(&boot_config);

        // Generate keys
        let mut rng = ShadowHarvester::new();
        let boot_keys = boot_ctx.generate_keys_dual_full(&mut rng);
        let work_keys = boot_ctx.generate_keys_dual_full(&mut rng);

        // This should succeed - primes are valid
        let result = BootstrapKey::generate(
            &work_config,
            &boot_ctx,
            &boot_keys,
            &work_keys.secret_key,
            &mut rng,
        );

        assert!(
            result.is_ok(),
            "BootstrapKey generation should succeed with valid primes: {:?}",
            result.err()
        );
    }

    // Note: Integration test for NTT validation is not included here because
    // RNSFHEContext::new() already panics on invalid NTT configuration during
    // NTT engine initialization. The unit test `test_validate_bootstrap_primes_ntt_incompatible`
    // validates the validation function itself. The system has defense-in-depth:
    // 1. NTT engine creation fails early (panics in arithmetic/ntt_fft.rs)
    // 2. validate_bootstrap_primes() provides explicit validation (returns Result)
    // 3. Both checks ensure NTT compatibility before any cryptographic operations.

    // ═══════════════════════════════════════════════════════════════════
    // WR-5B: EXACT BOOTSTRAP SECURITY VALIDATION (issue #83)
    // ═══════════════════════════════════════════════════════════════════
    //
    // These are NOT part of the VESTIGIAL/RETIRED bootstrap roundtrip
    // suites above and are deliberately not `#[ignore]`d: they exercise
    // pure, always-live validation/screening arithmetic (structural checks,
    // the security screen, and the tuple fingerprint), none of which runs
    // the bootstrap circuit itself.

    #[test]
    fn validate_bootstrap_primes_is_purely_structural_now() {
        // Regression for issue #83: the function no longer takes, or is
        // gated by, a security target at all.
        let result = validate_bootstrap_primes(&BOOTSTRAP_PRIMES, 4096);
        assert!(result.is_ok(), "{:?}", result.err());
    }

    #[test]
    fn screen_bootstrap_security_uses_exact_product_bit_length_not_summed_widths() {
        // Direct regression for issue #83 requirement 1, using the REAL
        // 5-prime production boot chain secure_128/secure_128_deep build
        // (`boot_prime_count` in `params::secure_configs`, mirrored by
        // `ClockworkBootstrap::new`). Summed per-lane widths overcount the
        // exact product bit length by one bit here -- exactly the class of
        // approximation error issue #83 flags, and the same class CLAUDE.md
        // already documents having been fixed once for work chains
        // (`exact_product_bit_length` vs the old floor-sum estimator
        // baseline). This is that fix's bootstrap-side counterpart.
        let primes = &BOOTSTRAP_PRIMES[..5];
        let summed_widths: u32 = primes
            .iter()
            .map(|&p| if p == 0 { 0 } else { 64 - p.leading_zeros() })
            .sum();
        let screen = screen_bootstrap_security(primes, 8192, 1).expect("screenable");

        assert_eq!(summed_widths, 147, "fixture assumption changed");
        assert_eq!(
            screen.log_q_boot, 146,
            "exact product bit length for BOOTSTRAP_PRIMES[..5]"
        );
        assert!(
            screen.log_q_boot < summed_widths,
            "exact bit length ({}) must be strictly tighter than the summed lane \
             widths ({}) for this chain",
            screen.log_q_boot,
            summed_widths,
        );
    }

    #[test]
    fn screen_bootstrap_security_exact_bit_length_matches_known_prefixes() {
        // Independently verified via exact big-integer multiplication
        // outside this crate. One entry per BOOTSTRAP_PRIMES prefix length
        // a shipped config's boot chain actually uses (5, 6, 7 primes) plus
        // the full 8-prime chain, which crosses the u128 boundary (128
        // bits) partway through the range -- the exact bit length must stay
        // exact on both sides of that boundary, since the underlying
        // accounting is limb-wise (`u64` limbs via `u128` products), never
        // a fixed-width `u128`/`U256` value that could wrap.
        let expected = [(5usize, 146u32), (6, 177), (7, 206), (8, 235)];
        for (count, bits) in expected {
            let primes = &BOOTSTRAP_PRIMES[..count];
            let screen = screen_bootstrap_security(primes, 16384, 1).expect("screenable");
            assert_eq!(
                screen.log_q_boot, bits,
                "BOOTSTRAP_PRIMES[..{}] exact bit length",
                count
            );
        }
    }

    #[test]
    fn screen_bootstrap_security_target_is_independent_of_q_boot() {
        // Regression for issue #83 requirements 2 and 5: the target this
        // screens against is whatever the caller passes -- never derived
        // from the boot chain's own width. The SAME chain screened against
        // two different targets must report the SAME log_q_boot /
        // core_svp_bits / matzov_bits and differ only in
        // meets_claim_under_both.
        let primes = &BOOTSTRAP_PRIMES[..5];
        let low_target = screen_bootstrap_security(primes, 8192, 64).expect("screenable");
        let high_target = screen_bootstrap_security(primes, 8192, 250).expect("screenable");

        assert_eq!(low_target.log_q_boot, high_target.log_q_boot);
        assert_eq!(low_target.core_svp_bits, high_target.core_svp_bits);
        assert_eq!(low_target.matzov_bits, high_target.matzov_bits);
        assert_eq!(low_target.claimed_security, 64);
        assert_eq!(high_target.claimed_security, 250);
        assert!(low_target.meets_claim_under_both);
        assert!(!high_target.meets_claim_under_both);
    }

    #[test]
    fn screen_bootstrap_security_refuses_typed_not_a_guess_for_an_unscreenable_chain() {
        // A single narrow prime (t = 65537, 17 bits, below the in-tree
        // model's calibration floor) must come back as a typed refusal,
        // never a guessed number -- issue #83 requirement 5.
        let result = screen_bootstrap_security(&[65537], 8192, 1);
        assert!(
            matches!(
                result,
                Err(Nine65Error::BootstrapSecurityUnscreenable { .. })
            ),
            "{:?}",
            result
        );
    }

    #[test]
    fn screen_bootstrap_security_refuses_a_non_prime_lane() {
        // A composite "prime" is not something the factorization-aware
        // screen can vouch for the internal structure of; it must refuse
        // rather than silently screening a manufactured/composite modulus
        // as if it were a hunted NTT prime.
        let composite = 998244353u64 * 3; // not prime, not in BOOTSTRAP_PRIMES
        let result = screen_bootstrap_security(&[composite], 8192, 1);
        assert!(
            matches!(
                result,
                Err(Nine65Error::BootstrapSecurityUnscreenable { .. })
            ),
            "{:?}",
            result
        );
    }

    #[test]
    fn every_shipped_config_boot_chain_screens_against_its_own_claim() {
        use crate::ops::bootstrap::ClockworkBootstrap;
        use crate::params::SecureConfig;

        for (name, work) in [
            ("secure_128", SecureConfig::secure_128().into_config()),
            (
                "secure_128_deep",
                SecureConfig::secure_128_deep().into_config(),
            ),
            ("secure_192", SecureConfig::secure_192().into_config()),
            ("secure_256", SecureConfig::secure_256().into_config()),
        ] {
            let boot = ClockworkBootstrap::new(&work).unwrap_or_else(|e| panic!("{name}: {e}"));
            let claim = work.security_bits as u32;
            let screen =
                screen_bootstrap_security(&boot.boot_config.primes, boot.boot_config.n, claim)
                    .unwrap_or_else(|e| panic!("{name}: boot chain must be screenable: {e}"));

            assert_eq!(
                screen.claimed_security, claim,
                "{name}: target must be the work config's own claim"
            );
            assert!(screen.log_q_boot > 0, "{name}");

            // Archived as a fact, not asserted as a requirement: secure_256's
            // own WORK chain already documents a MATZOV shortfall against
            // its 256-bit name (see `SecureConfig::secure_256`'s doc); its
            // much shorter boot chain (7 primes, 206 bits vs the work
            // chain's 175) screens even lower under both models. Recorded
            // here so a further regression cannot happen silently, without
            // this change pretending every config's boot chain clears its
            // own name (it does not) or hard-failing bootstrap key
            // generation for a config that could generate it before this
            // change (see the test below).
            if name == "secure_256" {
                assert!(
                    !screen.meets_claim_under_both,
                    "{name}: expected the documented boot-chain shortfall; if this now \
                     passes, update this test and its comment together with the doc on \
                     SecureConfig::secure_256"
                );
            } else {
                assert!(
                    screen.meets_claim_under_both,
                    "{name}: boot chain unexpectedly fails to screen at its own claim \
                     (core_svp={}, matzov={})",
                    screen.core_svp_bits, screen.matzov_bits
                );
            }
        }
    }

    #[test]
    fn bootstrap_key_generation_still_succeeds_for_every_admitted_config() {
        // Regression for "no change to public bootstrap availability": the
        // new screen must not newly refuse key generation for any config
        // that could generate bootstrap key material before this change --
        // including secure_256, whose boot chain screens below its own
        // 256-bit claim (see the test above). A refusal here is reserved
        // for structural/unscreenable chains, never for "screens below
        // claim".
        use crate::entropy::ShadowHarvester;
        use crate::ops::bootstrap::ClockworkBootstrap;
        use crate::params::SecureConfig;

        for (name, secure_config) in [
            ("secure_128", SecureConfig::secure_128()),
            ("secure_128_deep", SecureConfig::secure_128_deep()),
            ("secure_192", SecureConfig::secure_192()),
            ("secure_256", SecureConfig::secure_256()),
        ] {
            let work_config = secure_config.into_config();
            let boot = ClockworkBootstrap::new(&work_config)
                .unwrap_or_else(|e| panic!("{name}: boot ctx: {e}"));
            let mut rng = ShadowHarvester::new();
            let boot_keys = boot.boot_ctx.generate_keys_dual_full(&mut rng);
            let work_keys = boot.boot_ctx.generate_keys_dual_full(&mut rng);

            let result = BootstrapKey::generate(
                &work_config,
                &boot.boot_ctx,
                &boot_keys,
                &work_keys.secret_key,
                &mut rng,
            );
            assert!(result.is_ok(), "{name}: {:?}", result.err());
        }
    }

    #[test]
    fn bootstrap_tuple_fingerprint_is_deterministic_across_calls() {
        let primes = &BOOTSTRAP_PRIMES[..5];
        let fp1 = bootstrap_tuple_fingerprint(primes, 8192, 65537, 3);
        let fp2 = bootstrap_tuple_fingerprint(primes, 8192, 65537, 3);

        assert_eq!(fp1, fp2);
        assert_eq!(fp1.digest, fp2.digest);
        assert_eq!(fp1.primes, primes);
        assert_eq!(fp1.commit_sha, BUILD_COMMIT_SHA);
        assert!(!fp1.commit_sha.is_empty());
    }

    #[test]
    fn bootstrap_tuple_fingerprint_differs_for_different_tuples() {
        let fp_5 = bootstrap_tuple_fingerprint(&BOOTSTRAP_PRIMES[..5], 8192, 65537, 3);
        let fp_6 = bootstrap_tuple_fingerprint(&BOOTSTRAP_PRIMES[..6], 8192, 65537, 3);
        let fp_n = bootstrap_tuple_fingerprint(&BOOTSTRAP_PRIMES[..5], 16384, 65537, 3);
        let fp_t = bootstrap_tuple_fingerprint(&BOOTSTRAP_PRIMES[..5], 8192, 12289, 3);
        let fp_eta = bootstrap_tuple_fingerprint(&BOOTSTRAP_PRIMES[..5], 8192, 65537, 4);

        let digests = [
            fp_5.digest,
            fp_6.digest,
            fp_n.digest,
            fp_t.digest,
            fp_eta.digest,
        ];
        for i in 0..digests.len() {
            for j in (i + 1)..digests.len() {
                assert_ne!(
                    digests[i], digests[j],
                    "fingerprints at indices {i} and {j} collided"
                );
            }
        }
    }

    #[test]
    fn every_shipped_config_maps_to_its_exact_boot_tuple_and_fingerprint() {
        use crate::ops::bootstrap::ClockworkBootstrap;
        use crate::params::SecureConfig;

        for (name, work) in [
            ("secure_128", SecureConfig::secure_128().into_config()),
            (
                "secure_128_deep",
                SecureConfig::secure_128_deep().into_config(),
            ),
            ("secure_192", SecureConfig::secure_192().into_config()),
            ("secure_256", SecureConfig::secure_256().into_config()),
        ] {
            let boot = ClockworkBootstrap::new(&work).unwrap_or_else(|e| panic!("{name}: {e}"));

            // The boot chain must be an exact ordered prefix of
            // BOOTSTRAP_PRIMES -- this is what "the exact boot tuple
            // ClockworkBootstrap::new actually builds" means operationally.
            assert_eq!(
                boot.boot_config.primes,
                BOOTSTRAP_PRIMES[..boot.boot_config.primes.len()],
                "{name}: boot chain is not an ordered BOOTSTRAP_PRIMES prefix"
            );

            let fp = bootstrap_tuple_fingerprint(
                &boot.boot_config.primes,
                boot.boot_config.n,
                boot.boot_config.t,
                boot.boot_config.eta,
            );
            assert_eq!(fp.primes, boot.boot_config.primes, "{name}");
            assert_eq!(fp.n, boot.boot_config.n, "{name}");
            assert_eq!(fp.t, boot.boot_config.t, "{name}");
            assert_eq!(fp.eta, boot.boot_config.eta, "{name}");

            // Recomputing from the same inputs reproduces the same digest.
            let fp_again = bootstrap_tuple_fingerprint(
                &boot.boot_config.primes,
                boot.boot_config.n,
                boot.boot_config.t,
                boot.boot_config.eta,
            );
            assert_eq!(
                fp.digest, fp_again.digest,
                "{name}: fingerprint not reproducible"
            );
        }
    }
}
