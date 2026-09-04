//! Audited production parameter configurations for NINE65.
//!
//! All arithmetic in this module is exact integer arithmetic. The internal
//! security estimator is a deterministic screening gate, not an independent
//! lattice-security certificate. Every release that carries a named security
//! claim must archive an external lattice-estimator result for the exact tuple
//! `(N, Q, t, secret distribution, error distribution)`.
//!
//! `log2(q)` below is the exact bit length of the prime product
//! (`exact_product_bit_length`), and the two screen columns are what the
//! in-tree estimator returns for the tuple — measured 2026-08-22 by
//! `params::secure_configs::tests::screened_levels_for_named_configs`, not
//! quoted from an older parameter set. "Public refresh" is whether the chain
//! can carry `ClockworkBootstrap::bootstrap`; see the
//! PUBLIC-REFRESH ADMISSIBILITY section below.
//!
//! | Config | N | RNS chain | log2(q) | Claim | Core-SVP | MATZOV | Public refresh |
//! |--------|---|-----------|---------|-------|----------|--------|----------------|
//! | `secure_128` | 8192 | 3 NTT primes | 90 | 128 bits | 259 | 233 | refused |
//! | `secure_128_deep` | 8192 | 4 NTT primes | 119 | 128 bits | 196 | 176 | yes |
//! | `secure_192` | 16384 | 5 NTT primes | 146 | 192 bits | 320 | 288 | yes |
//! | `secure_256` | 16384 | 6 NTT primes | 175 | 256 bits | 267 | **240** | yes |
//!
//! `secure_256` is the one name that its own screen does not fully support:
//! it clears 256 under Core-SVP (the model the constructor gates on) and falls
//! 16 bits short under MATZOV. The constructor is left in place rather than
//! renamed; the gap is documented on `secure_256` itself and readable at
//! runtime via `SecureConfig::screened_security_dual`.

use super::security_estimator::{
    CostModel, HEStandardBounds, LatticeSecurityEstimator, SecretDistribution,
};
use super::{gcd, is_ntt_compatible, is_prime, FHEConfig};
use crate::errors::{Nine65Error, Nine65Result};
use crate::noise::budget::NoiseBudget;

/// Exact bit length of the product of the supplied RNS primes.
fn exact_product_bit_length(primes: &[u64]) -> u32 {
    let mut limbs = [0_u64; 8];
    limbs[0] = 1;

    for &factor in primes {
        let mut carry = 0_u128;
        for limb in &mut limbs {
            let product = *limb as u128 * factor as u128 + carry;
            *limb = product as u64;
            carry = product >> 64;
        }
        assert_eq!(
            carry, 0,
            "RNS product exceeds the 512-bit security-accounting capacity"
        );
    }

    for index in (0..limbs.len()).rev() {
        let limb = limbs[index];
        if limb != 0 {
            return index as u32 * 64 + (64 - limb.leading_zeros());
        }
    }
    0
}

// =============================================================================
// PUBLIC-REFRESH ADMISSIBILITY
// =============================================================================
//
// A *public* refresh is `ClockworkBootstrap::bootstrap` /
// `bootstrap_with_ksk`: the evaluator refreshes a ciphertext using only public
// bootstrap key material (BSK/KSK) and never touches a secret key. It is the
// path an untrusted caller reaches. The *symmetric* refresh
// (`SymmetricBootstrap::bootstrap`) takes the secret key and is a different,
// single-party path — none of the predicates below apply to it.
//
// MEASURED EVIDENCE (`cargo test -p nine65 --lib --release
// diag_measure_noise_growth -- --nocapture`, defined in `ops::bootstrap`'s test
// module, seed 20260822). It encrypts `7` under each config, runs the three
// refresh phases with THIS gate bypassed — otherwise the gate would be its own
// evidence — decrypts, then squares the refreshed ciphertext through the public
// eval-key multiply and decrypts again:
//
//   secure_128       3 lanes  refresh(7)   -> 7      correct
//                             refresh(7)^2 -> 34037, expected 49   WRONG
//   secure_128_deep  4 lanes  refresh(7)   -> 7      correct
//                             refresh(7)^2 -> 49     correct
//   secure_192       5 lanes  refresh(7)   -> 7      correct
//                             refresh(7)^2 -> 49     correct
//
// CORRECTION (2026-08-22, integration pass). Earlier revisions of this block,
// of README.md, of CLAUDE.md and of the runtime refusal string below stated
// that a `secure_128` refresh returns `encrypt(7)` as `8`. That is NOT what the
// diagnostic measures, and the diagnostic it cited did not exist when the claim
// was written. The refresh output itself decrypts correctly on all three
// configs. What `secure_128` cannot do is survive the FIRST MULTIPLY after the
// refresh — which is precisely the bar `post_refresh_required_bits` encodes, so
// the corrected measurement supports the gate's derivation more directly than
// the withdrawn one did. The failure is still silent: no error is raised
// anywhere in the pipeline, which is why the gate is fail-closed at the refresh
// rather than a warning at the multiply.
//
// The refusal predicate below is derived from the noise ledger, not from that
// table and not from a name match — the table is what it is checked against.
//
// Derivation. Let `Delta = floor(Q / t)` be the exact BFV scaling factor, whose
// bit length is `exact_delta_bit_length`. A refreshed ciphertext decrypts
// correctly only while its noise stays under `Delta / 2`, and it is only *useful*
// if what remains can still fund the smallest unit of work a caller performs
// after a refresh: one ciphertext-ciphertext multiply plus its relinearization
// (`NoiseBudget::mul_ct_cost + NoiseBudget::relin_cost`).
//
// The refresh's own noise deposit is the load-bearing term. Phase 2 of the
// public refresh (`ClockworkBootstrap::homomorphic_inner_product`) is an
// `n`-term homomorphic accumulation, so worst case its noise grows by a factor
// of `n` — `log2(n)` bits. `noise::budget::bootstrap_noise_bit_bound` instead
// charges `sqrt(n)` (`root_n_bits`), the averaged/heuristic growth. That
// difference is exactly what decides this question: under the averaged bound
// secure_128 is predicted to clear the bar with 49 bits against a 47-bit
// requirement, and the decryption oracle above says it does not. Under the
// worst-case bound it is 42 bits against 47 and is correctly refused, while
// every 4+-lane config still clears by 23 bits or more. The worst-case bound is
// therefore what this gate uses; the averaged bound stays where it is, for the
// budget ledger's own purposes.
//
// The predicate is a headroom inequality in exact bits. It reads no config
// name, so a new tuple is admitted or refused on its own arithmetic.

/// Bit length of a `u64` value (`0` for zero).
fn scalar_bit_length(value: u64) -> u32 {
    if value == 0 {
        0
    } else {
        64 - value.leading_zeros()
    }
}

/// Exact bit length of `Delta = floor(Q / t)`, where `Q` is the product of the
/// config's main RNS primes. Integer-only: big-integer long division over `u64`
/// limbs, no floating point and no `log` approximation.
pub fn exact_delta_bit_length(config: &FHEConfig) -> u32 {
    // Q as little-endian u64 limbs.
    let mut limbs: Vec<u64> = vec![1];
    for &prime in &config.primes {
        let mut carry: u128 = 0;
        for limb in &mut limbs {
            let product = *limb as u128 * prime as u128 + carry;
            *limb = product as u64;
            carry = product >> 64;
        }
        if carry != 0 {
            limbs.push(carry as u64);
        }
    }

    // floor(Q / t) by schoolbook long division over the limbs.
    let divisor = config.t.max(1) as u128;
    let mut quotient = vec![0_u64; limbs.len()];
    let mut remainder: u128 = 0;
    for index in (0..limbs.len()).rev() {
        let numerator = (remainder << 64) | limbs[index] as u128;
        quotient[index] = (numerator / divisor) as u64;
        remainder = numerator % divisor;
    }

    for index in (0..quotient.len()).rev() {
        if quotient[index] != 0 {
            return index as u32 * 64 + (64 - quotient[index].leading_zeros());
        }
    }
    0
}

/// Worst-case noise, in bits, that one public refresh deposits in its output.
///
/// `t_bits + eta_bits + log2(n)`: the plaintext modulus scales each accumulated
/// term, the error distribution contributes `eta`, and Phase 2's `n`-term
/// accumulation contributes at most a factor of `n`. See the module-level
/// derivation above for why `log2(n)` and not `sqrt(n)`.
///
/// # On `eta_bits = scalar_bit_length(eta)`, which looks tight and is not
///
/// `FHEConfig::initial_noise_budget_millibits` (`params::mod`) uses
/// `eta_bits = self.eta + 1` — 4 bits for `eta = 3`, against the 2 bits here.
/// The two are not both conventions for the same quantity, and this one is the
/// one that matches the sampler.
///
/// `entropy::secure::try_secure_cbd` sums `eta` independent draws of
/// `a - b ∈ {-1, 0, 1}`, so its support is exactly `[-eta, eta]` and
/// `||e||_inf <= eta`. The bit width of that magnitude bound is
/// `scalar_bit_length(eta)`: 2 bits for `eta = 3`, since `3 < 2^2`. The
/// `eta + 1` form is the bound you would want if `eta` named a *bit width*
/// (support `[-2^eta, 2^eta]`), which it does not here — it would assert
/// `||e|| <= 15` for a sampler that cannot exceed 3. `noise::budget` uses the
/// same `scalar_bit_length` form, so this gate and the ledger agree; the
/// `eta + 1` site is the outlier, and it errs toward a smaller budget, which is
/// the safe direction, so it is left alone rather than churned.
///
/// Pinned by `tests::error_width_bits_bound_the_sampler_that_produces_them`.
pub fn public_refresh_noise_bits(config: &FHEConfig) -> u32 {
    let t_bits = scalar_bit_length(config.t);
    let eta_bits = scalar_bit_length(config.eta as u64).max(1);
    let n_bits = config.n.trailing_zeros();
    t_bits + eta_bits + n_bits
}

/// Bits of `Delta` headroom left in a ciphertext after one public refresh.
/// Negative means the refresh output is already past the decryption boundary.
pub fn public_refresh_headroom_bits(config: &FHEConfig) -> i64 {
    exact_delta_bit_length(config) as i64 - public_refresh_noise_bits(config) as i64
}

/// Number of boot primes `ClockworkBootstrap::new` allocates for a work config.
///
/// Mirrors that constructor exactly: `required = max(bootstrap_depth + 2,
/// work_primes + 1)` with `bootstrap_depth = 2`, capped by the length of
/// `keys::bootstrap::BOOTSTRAP_PRIMES`. Kept in step by
/// `tests::ksk_bound_tracks_the_boot_chain_clockwork_actually_builds`.
fn boot_prime_count(config: &FHEConfig) -> usize {
    let required = 4_usize.max(config.primes.len() + 1);
    required.min(crate::keys::bootstrap::BOOTSTRAP_PRIMES.len())
}

/// Gadget decomposition base used by `KeySwitchKey::generate`, in bits
/// (`decomp_base = 1 << 10`).
const KSK_DECOMP_BASE_BITS: u32 = 10;

/// Worst-case noise, in bits, that the Phase 3a **key switch** of
/// [`ClockworkBootstrap::bootstrap_with_ksk`] deposits, on top of the refresh
/// circuit's own deposit.
///
/// `key_switch` CRT-reconstructs `c1` over the boot chain and decomposes it into
/// `ell = ceil(q_boot_bits / 10)` base-`2^10` digits, then accumulates
/// `sum_l digit_l * ksk_l` where each `ksk_l` carries a fresh CBD error
/// (`||e_l|| <= eta`). Ring expansion gives
/// `||v_ks|| <= ell * n * 2^10 * eta`, i.e.
/// `ell_bits + n_bits + 10 + eta_bits`.
///
/// No credit is taken for the Phase 3b division by the extra boot prime.
///
/// [`ClockworkBootstrap::bootstrap_with_ksk`]: crate::ops::bootstrap::ClockworkBootstrap::bootstrap_with_ksk
pub fn public_refresh_key_switch_noise_bits(config: &FHEConfig) -> u32 {
    let boot_primes = &crate::keys::bootstrap::BOOTSTRAP_PRIMES[..boot_prime_count(config)];
    let q_boot_bits = exact_product_bit_length(boot_primes);
    let digits = q_boot_bits.div_ceil(KSK_DECOMP_BASE_BITS).max(1);

    scalar_bit_length(digits as u64)
        + config.n.trailing_zeros()
        + KSK_DECOMP_BASE_BITS
        + scalar_bit_length(config.eta as u64).max(1)
}

/// Worst-case noise, in bits, that one **non-circular (KSK)** public refresh
/// deposits in its output.
///
/// The two deposits are additive, so `v_total <= v_phase2 + v_ks <=
/// 2 * max(v_phase2, v_ks)`: one bit above the larger of the two.
///
/// # Why this is not simply [`public_refresh_noise_bits`]
///
/// `bootstrap_with_ksk` was previously gated by the identical predicate as the
/// circular path, justified by "a chain that cannot carry the circular path
/// cannot carry this one either". That is true and beside the point. A
/// fail-closed gate's job is to reject chains that CAN carry the circular path
/// but CANNOT carry the noisier KSK path, and a bound with no key-switch term
/// cannot do that: a tuple sitting exactly at `headroom == required` would be
/// admitted on the KSK entry point with zero margin for the key-switch deposit.
/// The named configs all clear by 20+ bits so nothing misfires today, but
/// `SecureConfig::custom` admits arbitrary user tuples, and a bound documented
/// as worst-case must be a worst-case bound on the path it actually guards.
pub fn public_refresh_ksk_noise_bits(config: &FHEConfig) -> u32 {
    public_refresh_noise_bits(config).max(public_refresh_key_switch_noise_bits(config)) + 1
}

/// Bits of `Delta` headroom left after one non-circular (KSK) public refresh.
pub fn public_refresh_ksk_headroom_bits(config: &FHEConfig) -> i64 {
    exact_delta_bit_length(config) as i64 - public_refresh_ksk_noise_bits(config) as i64
}

/// Whether this config's chain can carry a **non-circular (KSK)** public
/// refresh (`ClockworkBootstrap::bootstrap_with_ksk`) and still decrypt.
///
/// Strictly stronger than [`supports_public_refresh`]: the KSK bound is at
/// least one bit larger than the circular bound by construction, so anything
/// this admits the circular predicate admits too.
pub fn supports_public_refresh_with_ksk(config: &FHEConfig) -> bool {
    public_refresh_ksk_headroom_bits(config) >= post_refresh_required_bits(config)
}

/// Typed refusal for configs whose chain cannot carry a non-circular (KSK)
/// public refresh. Counterpart of [`ensure_public_refresh_supported`], wired
/// into `ClockworkBootstrap::bootstrap_with_ksk`.
pub fn ensure_public_refresh_with_ksk_supported(config: &FHEConfig) -> Nine65Result<()> {
    let headroom = public_refresh_ksk_headroom_bits(config);
    let required = post_refresh_required_bits(config);
    if headroom >= required {
        return Ok(());
    }
    Err(Nine65Error::BootstrapConfigMismatch {
        reason: format!(
            "config '{}' cannot carry a non-circular (KSK) public refresh: its \
             {}-prime chain leaves {} bits of Delta headroom after the refresh \
             circuit's worst-case {}-bit noise deposit (refresh circuit {} bits, \
             Phase 3a key switch {} bits; Delta is {} bits), but {} bits are \
             required to fund one ct x ct multiply plus relinearization \
             afterwards. The failure is silent — the refresh output still \
             decrypts, and the first multiply after it does not. Use a config \
             with a longer main chain (e.g. SecureConfig::secure_128_deep), or \
             use the symmetric secret-key refresh path.",
            config.name,
            config.primes.len(),
            headroom,
            public_refresh_ksk_noise_bits(config),
            public_refresh_noise_bits(config),
            public_refresh_key_switch_noise_bits(config),
            exact_delta_bit_length(config),
            required,
        ),
    })
}

/// Bits a refreshed ciphertext must retain to fund the smallest unit of work a
/// caller performs after a refresh: one ct x ct multiply plus relinearization.
pub fn post_refresh_required_bits(config: &FHEConfig) -> i64 {
    (NoiseBudget::mul_ct_cost(config) + NoiseBudget::relin_cost(config)) / 1000
}

/// Whether this config's chain can carry a **public** refresh
/// (`ClockworkBootstrap::bootstrap` / `bootstrap_with_ksk`) and still decrypt.
pub fn supports_public_refresh(config: &FHEConfig) -> bool {
    public_refresh_headroom_bits(config) >= post_refresh_required_bits(config)
}

/// Typed refusal for configs whose chain cannot carry a public refresh.
///
/// Returns `Nine65Error::BootstrapConfigMismatch` — never panics — mirroring
/// how the security screen refuses a failing tuple. Wired into
/// `ClockworkBootstrap::bootstrap` and `ClockworkBootstrap::bootstrap_with_ksk`
/// so the refusal fires at the operation that would otherwise return a
/// wrong-but-plausible plaintext, rather than being left to a report.
pub fn ensure_public_refresh_supported(config: &FHEConfig) -> Nine65Result<()> {
    let headroom = public_refresh_headroom_bits(config);
    let required = post_refresh_required_bits(config);
    if headroom >= required {
        return Ok(());
    }
    Err(Nine65Error::BootstrapConfigMismatch {
        reason: format!(
            "config '{}' cannot carry a public refresh: its {}-prime chain leaves \
             {} bits of Delta headroom after the refresh circuit's worst-case \
             {}-bit noise deposit (Delta is {} bits), but {} bits are required to \
             fund one ct x ct multiply plus relinearization afterwards. The \
             refresh output still decrypts, but the first multiply after it \
             returns a wrong-but-plausible plaintext with no error raised \
             anywhere in the pipeline (measured: refresh(encrypt(7)) decrypts to \
             7, then squaring it decrypts to 34037 instead of 49 — see \
             ops::bootstrap::tests::diag_measure_noise_growth). Use a config \
             with a longer main chain (e.g. SecureConfig::secure_128_deep, which \
             carries the same 128-bit claim with 4 primes), or use the symmetric \
             secret-key refresh path.",
            config.name,
            config.primes.len(),
            headroom,
            public_refresh_noise_bits(config),
            exact_delta_bit_length(config),
            required,
        ),
    })
}

fn validate_class_f_chain(n: usize, primes: &[u64]) {
    for (index, &prime) in primes.iter().enumerate() {
        assert!(
            is_prime(prime),
            "CLASS-F RNS lane {index} must be prime, got {prime}"
        );
        assert!(
            is_ntt_compatible(prime, n),
            "CLASS-F RNS lane {prime} is not NTT-compatible for N={n}"
        );
        for &prior in &primes[..index] {
            assert_ne!(prior, prime, "duplicate CLASS-F RNS prime {prime}");
            assert_eq!(
                gcd(prior, prime),
                1,
                "CLASS-F RNS lanes {prior} and {prime} are not coprime"
            );
        }
    }
}

/// Dual-cost-model screening result for a named configuration.
///
/// Every field is a *screening* number produced by the in-tree integer
/// estimator. None of them is an independent lattice-security certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScreenedSecurity {
    /// Effective bits under the conservative Core-SVP model.
    pub core_svp_bits: u32,
    /// Effective bits under the aggressive MATZOV model.
    pub matzov_bits: u32,
    /// The binding result: `min(core_svp_bits, matzov_bits)`.
    pub binding_bits: u32,
    /// Whether the named claim is met under *both* models.
    pub meets_claim_under_both: bool,
}

/// Secure FHE configuration with an explicit claim and internal screening data.
#[derive(Clone, Debug)]
pub struct SecureConfig {
    /// Underlying FHE configuration.
    pub config: FHEConfig,
    /// Named security claim that this configuration must satisfy.
    pub claimed_security: u32,
    /// Internal classical screening result in bits.
    pub classical_security: u32,
    /// Internal hybrid-attack screening result in bits.
    pub hybrid_security: u32,
    /// Internal quantum-cost screening result in bits.
    pub quantum_security: u32,
    /// Whether the tuple is within the HE Standard modulus bound.
    pub he_standard_compliant: bool,
}

impl SecureConfig {
    fn new_verified(
        n: usize,
        primes: Vec<u64>,
        t: u64,
        eta: usize,
        claimed_security: u32,
        name: &'static str,
    ) -> Self {
        assert!(n.is_power_of_two(), "N must be a power of two");
        assert!(!primes.is_empty(), "at least one RNS prime is required");
        assert!(t >= 2, "plaintext modulus must be at least two");
        assert!(
            primes.iter().all(|&prime| t < prime),
            "plaintext modulus must be smaller than every RNS prime"
        );

        let q = primes[0];
        let log_q = exact_product_bit_length(&primes);
        let estimator = LatticeSecurityEstimator::new(CostModel::CoreSVP);
        let estimate = estimator.estimate(n, log_q, SecretDistribution::Ternary, claimed_security);
        let he_standard_compliant = HEStandardBounds::is_compliant(n, log_q, claimed_security);

        // Fail closed. A named claim must pass the complete internal screen;
        // Fail closed for real claims. Configs explicitly marked insecure
        // (test/benchmark tier, name ends `_insecure`) are permitted to
        // construct with their shortfall RECORDED in `he_standard_compliant`
        // and the screened bits; `is_production_safe` / `verify_production_safety`
        // reject them at use time. No 90%-of-claim relaxation is accepted.
        let is_insecure_tier = name.ends_with("_insecure");
        assert!(
            is_insecure_tier || estimate.effective_bits >= claimed_security,
            "SECURITY ERROR: config '{}' claims {} bits but screens at {} bits.\n{}",
            name,
            claimed_security,
            estimate.effective_bits,
            estimate.analysis,
        );
        assert!(
            is_insecure_tier || he_standard_compliant,
            "SECURITY ERROR: config '{}' exceeds the HE Standard bound",
            name
        );
        // Conservative production floor: any >= 128-bit security claim
        // requires N >= 8192: the lattice estimator blesses smaller N, but the
        // audited N >= 8192 floor governs production claims. Insecure test
        // tiers are exempt.
        assert!(
            is_insecure_tier || claimed_security < 128 || n >= 8192,
            "SECURITY ERROR: config '{}' claims {}-bit security but dimension N={} is below the 8192 floor",
            name,
            claimed_security,
            n
        );

        let config = FHEConfig {
            n,
            primes,
            q,
            t,
            eta,
            // This field carries the named claim. Screening results remain in
            // SecureConfig and must not silently replace the public contract.
            security_bits: claimed_security as usize,
            name,
        };

        Self {
            config,
            claimed_security,
            classical_security: estimate.classical_bits,
            hybrid_security: estimate.hybrid_bits,
            quantum_security: estimate.quantum_bits,
            he_standard_compliant,
        }
    }

    /// Returns true only when the named claim, HE bound, and audited dimension
    /// floor are all satisfied.
    pub fn is_production_safe(&self) -> bool {
        self.hybrid_security >= self.claimed_security
            && self.he_standard_compliant
            && (self.claimed_security < 128 || self.config.n >= 8192)
    }

    pub fn into_config(self) -> FHEConfig {
        self.config
    }

    /// Exact bit length of the product of this config's main RNS primes.
    pub fn log_q(&self) -> u32 {
        exact_product_bit_length(&self.config.primes)
    }

    /// Whether this config's chain can carry a **public** (evaluator-side,
    /// secret-key-free) refresh. See [`supports_public_refresh`].
    pub fn supports_public_refresh(&self) -> bool {
        supports_public_refresh(&self.config)
    }

    /// The level this tuple actually **screens** at under the conservative
    /// Core-SVP cost model — the honest number, as distinct from the level the
    /// constructor *name* asserts (`claimed_security`).
    ///
    /// This reproduces `SecurityEstimate::effective_bits`, the binding
    /// constraint `min(classical, hybrid)`, which is the quantity
    /// `new_verified` gates on. Call it whenever you need to report what a
    /// config screens at rather than what it is called; the two can differ,
    /// and where they do the smaller number governs.
    ///
    /// The in-tree estimator is a deterministic integer *screen*, not an
    /// independent lattice-security certificate (see the module header and
    /// `security_estimator`'s own module doc). Numbers from this method are
    /// screening results, never a certified security level.
    pub fn screened_security_bits(&self) -> u32 {
        self.classical_security.min(self.hybrid_security)
    }

    /// Screen this tuple under **both** in-tree cost models and return the
    /// binding (minimum) result.
    ///
    /// `new_verified` gates on Core-SVP alone. MATZOV is the more aggressive
    /// model and is routinely the smaller of the two, so a config can carry a
    /// name it meets under Core-SVP and misses under MATZOV. That gap is a
    /// labelling fact and is documented per-config rather than hidden.
    pub fn screened_security_dual(&self) -> ScreenedSecurity {
        let log_q = self.log_q();
        let dual = LatticeSecurityEstimator::new(CostModel::CoreSVP).dual_estimate(
            self.config.n,
            log_q,
            SecretDistribution::Ternary,
            self.claimed_security,
        );
        ScreenedSecurity {
            core_svp_bits: dual.core_svp.effective_bits,
            matzov_bits: dual.matzov.effective_bits,
            binding_bits: dual.binding_bits,
            meets_claim_under_both: dual.meets_both,
        }
    }

    /// Audited 128-bit production candidate.
    ///
    /// N was raised from 4096 to 8192 after the July 2026 independent audit
    /// assessed the former tuple below its 128-bit claim.
    ///
    /// Re-cut 2026-08-26 (see `docs/OPEN_WORK_2026-08-26.md` A3) from three
    /// main primes to four: at N=8192 the three-prime chain was
    /// under-provisioned rather than incapable, and left only 42 bits of
    /// post-refresh `Delta` headroom against the 47 a single subsequent
    /// multiply needs — [`ensure_public_refresh_supported`] refused it, and
    /// the decryption oracle confirmed the corruption directly (refresh
    /// output still decrypted to `7`, but squaring it silently produced
    /// `34037` instead of `49`). The fourth prime is the same one
    /// `secure_128_deep` already carried; this chain is now that tuple.
    ///
    /// Screened 2026-08-22 (pre-recut, three primes): Core-SVP 259 bits,
    /// MATZOV 233 bits. Screened for the four-prime chain: Core-SVP 196 bits,
    /// MATZOV 176 bits — both still clear the 128-bit name, at less margin
    /// than the retired three-prime tuple in exchange for carrying a public
    /// refresh (71 bits of post-refresh `Delta` headroom against a 47-bit
    /// requirement).
    pub fn secure_128() -> Self {
        Self::new_verified(
            8192,
            vec![998244353, 985661441, 754974721, 469762049],
            65537,
            3,
            128,
            "secure_128",
        )
    }

    /// 128-bit candidate with a four-prime chain for deeper leveled work.
    ///
    /// Since the 2026-08-26 re-cut (`docs/OPEN_WORK_2026-08-26.md` A3) this is
    /// numerically identical to [`SecureConfig::secure_128`] — both use the
    /// same four-prime chain. Kept as a distinct named entry point for
    /// call sites that spell out "deep" explicitly; prefer `secure_128` in new
    /// code.
    ///
    /// Screened 2026-08-22: Core-SVP 196 bits, MATZOV 176 bits — both clear the
    /// 128-bit name. This is the shortest chain that carries a **public**
    /// refresh (71 bits of post-refresh `Delta` headroom against a 47-bit
    /// requirement), verified against the decryption oracle.
    pub fn secure_128_deep() -> Self {
        Self::new_verified(
            8192,
            vec![998244353, 985661441, 754974721, 469762049],
            65537,
            3,
            128,
            "secure_128_deep",
        )
    }

    /// 192-bit production candidate.
    ///
    /// Screened 2026-08-22: Core-SVP 320 bits, MATZOV 288 bits — the widest
    /// margin over its name of any config here. Carries a public refresh
    /// (96 bits of post-refresh `Delta` headroom against a 49-bit requirement).
    pub fn secure_192() -> Self {
        Self::new_verified(
            16384,
            vec![998244353, 985661441, 754974721, 469762049, 167772161],
            65537,
            4,
            192,
            "secure_192",
        )
    }

    /// 256-bit production candidate.
    ///
    /// # The name and the screen (measured 2026-08-22)
    ///
    /// | model | effective bits | vs the 256-bit name |
    /// |---|---|---|
    /// | Core-SVP (conservative, what `new_verified` gates on) | 267 | clears |
    /// | MATZOV (aggressive) | 240 | **16 bits short** |
    ///
    /// `n = 16384`, `log2(q) = 175`. The name is not an overclaim under the
    /// model this module screens with, so it is kept as-is — but the binding
    /// number across both in-tree models is **240**, not 256. Read it with
    /// [`SecureConfig::screened_security_dual`] rather than inferring it from
    /// the constructor name, and quote 240 wherever the more aggressive model
    /// is the relevant one.
    ///
    /// A previous parameter set for this name did fall materially short: at
    /// `log2(q) = 203` it screened at 226/227 bits. That chain was replaced on
    /// 2026-02-25 (see `docs/LATTICE_ESTIMATOR_BASELINE_2026-02-25.md`); the
    /// 226/227 figure does not describe the tuple above and must not be quoted
    /// against it.
    ///
    /// Neither number is an independent lattice-security certificate. Per the
    /// module header, an external estimator run against this exact tuple is
    /// still owed.
    pub fn secure_256() -> Self {
        Self::new_verified(
            16_384,
            vec![
                998244353, 985661441, 754974721, 469762049, 167772161, 595591169,
            ],
            65_537,
            5,
            256,
            "secure_256",
        )
    }

    // =========================================================================
    // TEST/BENCHMARK CONFIGURATIONS (NOT FOR PRODUCTION)
    // =========================================================================

    /// Fast test configuration. Never deploy with sensitive data.
    #[cfg(any(test, debug_assertions, feature = "allow_insecure"))]
    pub fn test_fast_insecure() -> Self {
        Self::new_verified(1024, vec![998_244_353], 65_537, 2, 40, "test_fast_insecure")
    }

    /// Medium test configuration. Never deploy with sensitive data.
    #[cfg(any(test, debug_assertions, feature = "allow_insecure"))]
    pub fn test_medium_insecure() -> Self {
        Self::new_verified(
            2048,
            vec![998_244_353, 985_661_441],
            65_537,
            2,
            80,
            "test_medium_insecure",
        )
    }
}

/// Marker trait used by release-path guards.
pub trait ProductionSafe {
    fn require_production_safe(&self);
}

impl ProductionSafe for SecureConfig {
    fn require_production_safe(&self) {
        #[cfg(not(any(test, debug_assertions, feature = "allow_insecure")))]
        assert!(
            self.is_production_safe(),
            "SECURITY ERROR: config '{}' does not satisfy its {}-bit production contract",
            self.config.name,
            self.claimed_security,
        );
    }
}

#[inline]
pub fn assert_production_safe(config: &SecureConfig) {
    config.require_production_safe();
}

/// The raw production-safety predicate, with no `test`/`debug_assertions`/
/// `allow_insecure` bypass.
///
/// This is the fallible primitive: the three checks are the same ones
/// [`assert_production_safe_fhe_config`] used to run through `assert!`, but
/// here every violation returns a typed [`Nine65Error`] instead of
/// panicking. It is unconditional (always evaluates the checks) so it is
/// independently testable in a normal `cargo test` build, where
/// [`verify_production_safe_fhe_config`]'s environment bypass would
/// otherwise make every violation branch unreachable.
pub fn production_safety_checks(config: &FHEConfig) -> Nine65Result<()> {
    let required_security = (config.security_bits as u32).max(128);
    let log_q = exact_product_bit_length(&config.primes);

    if config.n < 8192 {
        return Err(Nine65Error::ConfigError {
            message: format!(
                "PRODUCTION SECURITY VIOLATION: N={} is below the audited floor N=8192",
                config.n
            ),
        });
    }

    let estimator = LatticeSecurityEstimator::new(CostModel::CoreSVP);
    let estimate = estimator.estimate(
        config.n,
        log_q,
        SecretDistribution::Ternary,
        required_security,
    );
    if estimate.effective_bits < required_security {
        return Err(Nine65Error::SecurityLevelNotMet {
            bits: estimate.effective_bits,
            required: required_security,
        });
    }

    if !HEStandardBounds::is_compliant(config.n, log_q, required_security) {
        return Err(Nine65Error::ConfigError {
            message: format!(
                "PRODUCTION SECURITY VIOLATION: config '{}' exceeds the HE Standard modulus bound",
                config.name
            ),
        });
    }

    Ok(())
}

/// Validate a raw `FHEConfig` against its declared claim, with a 128-bit
/// minimum on production paths, returning a typed error instead of
/// panicking.
///
/// This is what every `try_*` constructor that accepts caller-supplied
/// configuration must call: an invalid/unverified production config is
/// caller input, not an internal invariant, so it must produce a `Result`,
/// never abort the process (see issue #85 — with `panic = "abort"` in the
/// release profile, a reachable `assert!` here is process termination, not a
/// typed configuration failure).
///
/// Outside production builds (`test`, `debug_assertions`, or the
/// `allow_insecure` feature) this always returns `Ok(())`, matching the
/// panicking version's behavior of being a no-op there. Use
/// [`production_safety_checks`] directly to exercise the underlying
/// predicate without that bypass (e.g. from tests).
pub fn verify_production_safe_fhe_config(config: &FHEConfig) -> Nine65Result<()> {
    if cfg!(any(test, debug_assertions, feature = "allow_insecure")) {
        return Ok(());
    }
    production_safety_checks(config)
}

/// Validate a raw `FHEConfig` against its declared claim, with a 128-bit
/// minimum on production paths.
///
/// # Panics
///
/// Panics (via `assert!`) on any of the three production-safety violations
/// [`verify_production_safe_fhe_config`] detects. The `assert_` prefix makes
/// that panic contract explicit in the name: this wrapper exists only for
/// call sites that have deliberately chosen an infallible, abort-on-invalid
/// API. Fallible call sites — every `try_*` constructor included — must call
/// [`verify_production_safe_fhe_config`] directly and propagate the error
/// with `?` instead.
pub fn assert_production_safe_fhe_config(config: &FHEConfig) {
    if let Err(error) = verify_production_safe_fhe_config(config) {
        panic!("{error}");
    }
}

/// Return a detailed error rather than panicking.
pub fn verify_production_safety(config: &SecureConfig) -> Result<(), String> {
    if config.config.n < 8192 && config.claimed_security >= 128 {
        return Err(format!(
            "N={} is below the audited production floor N=8192",
            config.config.n
        ));
    }
    if config.hybrid_security < config.claimed_security {
        return Err(format!(
            "internal hybrid screen={} bits, claim={} bits",
            config.hybrid_security, config.claimed_security
        ));
    }
    if !config.he_standard_compliant {
        return Err("not HE Standard compliant".to_string());
    }
    Ok(())
}

#[cfg(not(any(test, debug_assertions, feature = "allow_insecure")))]
pub fn get_production_config() -> SecureConfig {
    let config = SecureConfig::secure_128();
    verify_production_safety(&config).expect("default production config must be safe");
    config
}

#[cfg(any(test, debug_assertions, feature = "allow_insecure"))]
pub fn get_production_config() -> SecureConfig {
    SecureConfig::secure_128()
}

#[cfg(test)]
mod tests {
    use super::*;

    // =====================================================================
    // PUBLIC-REFRESH ADMISSIBILITY
    // =====================================================================

    /// The predicate must split the named configs exactly where the decryption
    /// oracle splits them.
    ///
    /// Ground truth is `ops::bootstrap::tests::diag_measure_noise_growth`
    /// (`cargo test -p nine65 --lib --release diag_measure_noise_growth --
    /// --nocapture`), which runs the refresh phases with this gate bypassed and
    /// checks the result against the decryption oracle. Historically (pre the
    /// 2026-08-26 `secure_128` re-cut, `docs/OPEN_WORK_2026-08-26.md` A3), the
    /// three-prime `secure_128` refreshed `encrypt(7)` back to `7` but then
    /// squared it to `34037` instead of `49`. That chain has since been removed
    /// from the tree. This test pins the predicate's verdicts for the named
    /// configs that remain.
    ///
    /// This test pins the predicate against that split. It is deliberately
    /// sensitive to the noise ledger it reads (`NoiseBudget::mul_ct_cost`,
    /// `relin_cost`): if those change enough to move a config across the line,
    /// this fails loudly instead of silently re-admitting a corrupting path.
    #[test]
    fn public_refresh_predicate_matches_the_decryption_oracle() {
        struct Case {
            config: FHEConfig,
            expect_supported: bool,
        }

        let cases = [
            Case {
                config: SecureConfig::secure_128().into_config(),
                expect_supported: true,
            },
            Case {
                config: SecureConfig::secure_128_deep().into_config(),
                expect_supported: true,
            },
            Case {
                config: SecureConfig::secure_192().into_config(),
                expect_supported: true,
            },
            Case {
                config: SecureConfig::secure_256().into_config(),
                expect_supported: true,
            },
        ];

        for case in &cases {
            let headroom = public_refresh_headroom_bits(&case.config);
            let required = post_refresh_required_bits(&case.config);
            println!(
                "{:16} lanes={} delta={:3} bits, refresh noise={:2} bits, \
                 headroom={:3} bits, required={:3} bits -> supported={}",
                case.config.name,
                case.config.primes.len(),
                exact_delta_bit_length(&case.config),
                public_refresh_noise_bits(&case.config),
                headroom,
                required,
                supports_public_refresh(&case.config),
            );

            assert_eq!(
                supports_public_refresh(&case.config),
                case.expect_supported,
                "{}: predicate disagrees with the measured decryption oracle \
                 (headroom {} bits, required {} bits)",
                case.config.name,
                headroom,
                required,
            );

            let outcome = ensure_public_refresh_supported(&case.config);
            assert_eq!(
                outcome.is_ok(),
                case.expect_supported,
                "{}: ensure_public_refresh_supported disagrees with \
                 supports_public_refresh",
                case.config.name
            );

            if !case.expect_supported {
                let message = outcome.unwrap_err().to_string();
                assert!(
                    message.contains("cannot carry a public refresh"),
                    "{}: refusal must say what it refuses, got: {}",
                    case.config.name,
                    message
                );
            }
        }
    }

    /// The predicate reads arithmetic, not names: the refusal is driven by the
    /// chain, so lengthening a chain admits it and shortening one refuses it,
    /// whatever the config is called. Both cases are built by editing a named
    /// config's chain rather than by naming a short config, because no short
    /// named config exists.
    #[test]
    fn public_refresh_predicate_is_not_a_name_match() {
        let mut lengthened = SecureConfig::secure_128().into_config();
        lengthened.primes.push(167_772_161);
        assert!(
            supports_public_refresh(&lengthened),
            "a lengthened chain must be admitted on its arithmetic, not its name"
        );

        let mut shortened = SecureConfig::secure_128_deep().into_config();
        shortened.primes.pop();
        assert!(
            !supports_public_refresh(&shortened),
            "a shortened chain must be refused even while still named secure_128_deep"
        );
    }

    /// Wiring proof: the refusal actually fires at
    /// `ClockworkBootstrap::bootstrap` / `bootstrap_with_ksk`, not merely in the
    /// predicate. Keys are structurally empty on purpose — the gate runs before
    /// any of them is read, so reaching a *different* error proves the gate did
    /// not fire.
    #[test]
    fn public_refresh_refusal_fires_at_the_bootstrap_entry_points() {
        use crate::keys::bootstrap::{BootstrapKey, KeySwitchKey};
        use crate::ops::bootstrap::ClockworkBootstrap;
        use crate::ops::rns_fhe::{
            DualRNSCiphertext, DualRNSEvalKey, DualRNSPoly, DualRNSPublicKey,
        };

        fn empty_poly(n: usize) -> DualRNSPoly {
            DualRNSPoly {
                main: Vec::new(),
                anchor: Vec::new(),
                n,
            }
        }
        fn empty_ct(n: usize) -> DualRNSCiphertext {
            DualRNSCiphertext {
                c0: empty_poly(n),
                c1: empty_poly(n),
                level: 0,
            }
        }
        fn empty_bsk(n: usize) -> BootstrapKey {
            BootstrapKey {
                enc_s: empty_ct(n),
                eval_key: DualRNSEvalKey {
                    rlk: Vec::new(),
                    decomp_base: 1024,
                    num_digits: 0,
                },
                public_key: DualRNSPublicKey {
                    pk0: empty_poly(n),
                    pk1: empty_poly(n),
                },
                t_work: 0,
                q_min: 0,
            }
        }
        fn empty_ksk() -> KeySwitchKey {
            KeySwitchKey {
                ksk: Vec::new(),
                decomp_base: 1024,
                num_digits: 0,
            }
        }

        const REFUSAL: &str = "cannot carry a public refresh";

        // A chain deliberately too short to carry a public refresh: both entry
        // points must refuse it. Built ad hoc by shortening secure_128, NOT by
        // naming a config -- no short named config exists, and this exists only
        // to prove the gate fires, never as a usable chain. Three lanes is the
        // shortest ClockworkBootstrap::new will build a context for (it wants
        // exactly one extra boot prime).
        let mut refused = SecureConfig::secure_128().into_config();
        refused.primes.truncate(3);
        let boot = ClockworkBootstrap::new(&refused).expect("bootstrap context");
        let ct = empty_ct(refused.n);
        let bsk = empty_bsk(refused.n);
        let ksk = empty_ksk();

        let circular = boot
            .bootstrap(&ct, &bsk, &ksk)
            .expect_err("a short chain's public refresh must be refused");
        assert!(
            circular.to_string().contains(REFUSAL),
            "short chain bootstrap() returned the wrong error: {circular}"
        );

        // The KSK entry point refuses through its OWN, strictly stronger
        // predicate — the one that carries a Phase 3a key-switch term. The
        // distinct needle is what proves the two gates are not the same gate.
        const KSK_REFUSAL: &str = "cannot carry a non-circular (KSK) public refresh";
        let non_circular = boot
            .bootstrap_with_ksk(&ct, &bsk, &ksk)
            .expect_err("a short chain's non-circular public refresh must be refused");
        assert!(
            non_circular.to_string().contains(KSK_REFUSAL),
            "short chain bootstrap_with_ksk() returned the wrong error: {non_circular}"
        );

        // secure_128_deep (4 lanes): the gate must NOT fire. The empty
        // ciphertext still fails later, in Phase 1's own limb check — a
        // different error, which is exactly what "the gate did not fire" looks
        // like here.
        let admitted = SecureConfig::secure_128_deep().into_config();
        let boot_deep = ClockworkBootstrap::new(&admitted).expect("bootstrap context");
        let deep_ct = empty_ct(admitted.n);
        let deep_bsk = empty_bsk(admitted.n);

        let deep_outcome = boot_deep.bootstrap(&deep_ct, &deep_bsk, &empty_ksk());
        match deep_outcome {
            Ok(_) => panic!("an empty ciphertext cannot bootstrap successfully"),
            Err(error) => assert!(
                !error.to_string().contains(REFUSAL),
                "secure_128_deep must not be refused by the public-refresh gate, got: {error}"
            ),
        }

        let deep_ksk_outcome = boot_deep.bootstrap_with_ksk(&deep_ct, &deep_bsk, &empty_ksk());
        match deep_ksk_outcome {
            Ok(_) => panic!("an empty ciphertext cannot bootstrap successfully"),
            Err(error) => assert!(
                !error.to_string().contains(KSK_REFUSAL),
                "secure_128_deep must not be refused by the KSK gate, got: {error}"
            ),
        }
    }

    /// The `eta_bits` term in the refresh bound must actually bound the
    /// sampler that produces the error it stands for.
    ///
    /// `public_refresh_noise_bits` uses `scalar_bit_length(eta)` — 2 bits at
    /// `eta = 3`. That is only sound if the CBD sampler's support really is
    /// `[-eta, eta]`. This draws from the sampler and checks it, rather than
    /// trusting the docstring: if anyone ever widens `try_secure_cbd` (to
    /// `[-2^eta, 2^eta]`, say), this fails and takes the whole
    /// public-refresh gate's error term with it, instead of the gate silently
    /// becoming optimistic.
    #[test]
    fn error_width_bits_bound_the_sampler_that_produces_them() {
        use crate::entropy::{FheRng, ShadowHarvester};

        for eta in [2_usize, 3, 5] {
            let mut rng = ShadowHarvester::with_seed(0xE7A_u64.wrapping_add(eta as u64));
            let claimed_bits = scalar_bit_length(eta as u64).max(1);
            let mut observed_max = 0_i64;

            for _ in 0..20_000 {
                let sample = rng.cbd(eta);
                observed_max = observed_max.max(sample.abs());
                assert!(
                    sample.abs() <= eta as i64,
                    "CBD({eta}) produced {sample}, outside its documented \
                     support [-{eta}, {eta}]; public_refresh_noise_bits's \
                     eta_bits term is derived from that support"
                );
            }

            assert!(
                (eta as i64) < (1_i64 << claimed_bits),
                "eta={eta} does not fit in the {claimed_bits} bits the refresh \
                 bound charges for it"
            );
            // The bound must be tight enough to be meaningful: the sampler
            // should actually reach into the top bit it is charged for.
            assert!(
                observed_max > (1_i64 << claimed_bits) / 4,
                "eta={eta}: observed max |e| = {observed_max} over 20k draws is \
                 far below the {claimed_bits}-bit charge; either the sampler \
                 changed or the charge is measuring the wrong thing"
            );
        }
    }

    /// The KSK gate must be strictly stronger than the circular gate, and its
    /// key-switch term must describe the boot chain `ClockworkBootstrap`
    /// actually builds.
    ///
    /// Two failure modes this closes:
    ///
    /// 1. The KSK path reusing the circular predicate, which has no term for
    ///    the Phase 3a gadget key switch it performs. A bound documented as
    ///    worst-case must bound the path it guards.
    /// 2. `boot_prime_count` here drifting from
    ///    `ClockworkBootstrap::new`'s allocation, silently changing `ell` and
    ///    with it the key-switch term. Asserted against the real constructor,
    ///    not against a copied constant.
    #[test]
    fn ksk_bound_tracks_the_boot_chain_clockwork_actually_builds() {
        use crate::ops::bootstrap::ClockworkBootstrap;

        let configs = [
            SecureConfig::secure_128(),
            SecureConfig::secure_128_deep(),
            SecureConfig::secure_192(),
            SecureConfig::secure_256(),
        ];

        println!(
            "\n{:<18} {:>6} {:>10} {:>10} {:>10} {:>9} {:>9}",
            "config", "lanes", "circ_noise", "ks_noise", "ksk_noise", "ksk_head", "required"
        );

        for secure in configs {
            let config = secure.into_config();
            let boot = ClockworkBootstrap::new(&config).expect("bootstrap context");

            // 1. The boot chain modelled here is the boot chain built there.
            assert_eq!(
                boot_prime_count(&config),
                boot.boot_config.primes.len(),
                "{}: boot_prime_count drifted from ClockworkBootstrap::new",
                config.name
            );

            let circular = public_refresh_noise_bits(&config);
            let key_switch = public_refresh_key_switch_noise_bits(&config);
            let ksk = public_refresh_ksk_noise_bits(&config);

            println!(
                "{:<18} {:>6} {:>10} {:>10} {:>10} {:>9} {:>9}",
                config.name,
                config.primes.len(),
                circular,
                key_switch,
                ksk,
                public_refresh_ksk_headroom_bits(&config),
                post_refresh_required_bits(&config),
            );

            // 2. The KSK bound is STRICTLY larger than the circular bound, so
            //    the KSK gate can refuse a tuple the circular gate admits.
            assert!(
                ksk > circular,
                "{}: KSK bound ({ksk}) must exceed the circular bound ({circular}); \
                 a gate that cannot be stricter than the one it wraps is not a \
                 separate gate",
                config.name
            );

            // 3. The key-switch term is real, not a rounding artefact.
            assert!(
                key_switch >= 20,
                "{}: key-switch term {key_switch} is implausibly small; \
                 ell*n*2^10*eta cannot be under 2^20 for any supported config",
                config.name
            );

            // 4. Admissibility is monotone: KSK admitted implies circular
            //    admitted. Never the reverse by accident.
            assert!(
                !supports_public_refresh_with_ksk(&config) || supports_public_refresh(&config),
                "{}: KSK admitted a config the circular gate refuses",
                config.name
            );

            // 5. The named configs must not have moved across the line. The
            //    KSK term costs at most a couple of bits on these tuples, and
            //    if it ever costs enough to flip one, that is a finding, not a
            //    number to quietly update.
            assert_eq!(
                supports_public_refresh_with_ksk(&config),
                supports_public_refresh(&config),
                "{}: adding the key-switch term flipped this config's verdict. \
                 That is a real change in what the library will refresh — \
                 report it, do not relax this assertion.",
                config.name
            );
        }
    }

    /// Measurement, not assertion-of-a-hoped-for-number: prints what every
    /// named config actually screens at under both in-tree cost models.
    ///
    /// Run with:
    ///   cargo test -p nine65 --release --lib \
    ///     params::secure_configs::tests::screened_levels_for_named_configs \
    ///     -- --nocapture
    ///
    /// The only assertions here are invariants that must hold whatever the
    /// numbers are: MATZOV never screens above Core-SVP, and the binding
    /// result is the minimum of the two.
    #[test]
    fn screened_levels_for_named_configs() {
        let configs = [
            SecureConfig::secure_128(),
            SecureConfig::secure_128_deep(),
            SecureConfig::secure_192(),
            SecureConfig::secure_256(),
        ];

        println!(
            "\n| config | n | lanes | log2(q) | claimed | Core-SVP | MATZOV | binding | classical | hybrid | quantum |"
        );
        println!("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");
        for config in &configs {
            let dual = config.screened_security_dual();
            println!(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
                config.config.name,
                config.config.n,
                config.config.primes.len(),
                config.log_q(),
                config.claimed_security,
                dual.core_svp_bits,
                dual.matzov_bits,
                dual.binding_bits,
                config.classical_security,
                config.hybrid_security,
                config.quantum_security,
            );
        }
        println!();

        for config in &configs {
            let dual = config.screened_security_dual();
            assert_eq!(
                config.screened_security_bits(),
                dual.core_svp_bits,
                "{}: screened_security_bits must equal the Core-SVP effective bits",
                config.config.name
            );
            assert!(
                dual.matzov_bits <= dual.core_svp_bits,
                "{}: MATZOV {} screened above Core-SVP {}",
                config.config.name,
                dual.matzov_bits,
                dual.core_svp_bits
            );
            assert_eq!(
                dual.binding_bits,
                dual.core_svp_bits.min(dual.matzov_bits),
                "{}: binding bits must be the minimum of the two models",
                config.config.name
            );
        }

        // ------------------------------------------------------------------
        // THE NUMBERS THEMSELVES, PINNED.
        //
        // The three invariants above are true BY CONSTRUCTION and cannot
        // catch a parameter regression: `dual_estimate` computes
        // `binding_bits` as the min, and MATZOV's model factor (900/1000) is
        // strictly below Core-SVP's (1000/1000), so MATZOV can never exceed
        // Core-SVP. A change that halved a screened level would have passed
        // every one of them while this test reported ok -- and README.md and
        // CLAUDE.md both cite THIS test as the source of their published
        // security tables.
        //
        // So pin the published table. These are screening numbers from a
        // deterministic integer heuristic, not lattice-security certificates
        // (see the module header and item 5 of
        // docs/CLAIM_SURFACE_AND_LIMITS_2026-08-22.md) -- but they are what is
        // published, and a published number that no test reproduces is a
        // number nobody is holding.
        //
        // Measured 2026-08-22, secure_128 re-cut 2026-08-26 (name, n, lanes,
        // log2 q, Core-SVP, MATZOV). secure_128 now carries the four-prime
        // chain previously exclusive to secure_128_deep -- see the 2026-08-26
        // secure_128 re-cut, docs/OPEN_WORK_2026-08-26.md A3.
        let expected: &[(&str, usize, usize, u32, u32, u32)] = &[
            ("secure_128", 8192, 4, 119, 196, 176),
            ("secure_128_deep", 8192, 4, 119, 196, 176),
            ("secure_192", 16384, 5, 146, 320, 288),
            ("secure_256", 16384, 6, 175, 267, 240),
        ];
        assert_eq!(
            configs.len(),
            expected.len(),
            "a named config was added or removed without updating the pinned              screening table"
        );
        for (config, &(name, n, lanes, log_q, core_svp, matzov)) in configs.iter().zip(expected) {
            assert_eq!(config.config.name, name, "config order changed");
            assert_eq!(config.config.n, n, "{name}: ring degree moved");
            assert_eq!(
                config.config.primes.len(),
                lanes,
                "{name}: lane count moved"
            );
            assert_eq!(config.log_q(), log_q, "{name}: log2(q) moved");

            let dual = config.screened_security_dual();
            assert_eq!(
                dual.core_svp_bits, core_svp,
                "{name}: Core-SVP screened level moved from {core_svp} to {}.                  README.md and CLAUDE.md publish the old number. Re-measure and                  update all three together.",
                dual.core_svp_bits
            );
            assert_eq!(
                dual.matzov_bits, matzov,
                "{name}: MATZOV screened level moved from {matzov} to {}.                  README.md and CLAUDE.md publish the old number. Re-measure and                  update all three together.",
                dual.matzov_bits
            );
        }

        // The disclosed shortfall, asserted rather than merely written down.
        //
        // `secure_256` is the one name its own screen does not fully support:
        // it clears 256 under Core-SVP (the model the constructor gates on)
        // and falls short under MATZOV. `named_production_configs_meet_their_
        // internal_claims` checks the Core-SVP hybrid figure only, so without
        // this the gap lived in prose alone.
        let s256 = SecureConfig::secure_256();
        let s256_dual = s256.screened_security_dual();
        assert!(
            s256_dual.core_svp_bits >= s256.claimed_security,
            "secure_256 no longer clears its own name even under Core-SVP              ({} < {})",
            s256_dual.core_svp_bits,
            s256.claimed_security
        );
        assert!(
            s256_dual.matzov_bits < s256.claimed_security,
            "secure_256 now CLEARS 256 bits under MATZOV ({} >= {}). That is              good news and it invalidates the documented shortfall in the              module header, README.md and CLAUDE.md -- update them rather than              deleting this assertion.",
            s256_dual.matzov_bits,
            s256.claimed_security
        );
    }

    #[test]
    fn secure_128_uses_audited_dimension_floor() {
        let config = SecureConfig::secure_128();
        assert_eq!(config.config.n, 8192);
        assert_eq!(config.claimed_security, 128);
        assert!(config.hybrid_security >= config.claimed_security);
        assert!(config.is_production_safe());
    }

    #[test]
    fn named_production_configs_meet_their_internal_claims() {
        for config in [
            SecureConfig::secure_128(),
            SecureConfig::secure_128_deep(),
            SecureConfig::secure_192(),
            SecureConfig::secure_256(),
        ] {
            // Each named production config must clear its own claimed bar.
            assert!(
                config.hybrid_security >= config.claimed_security,
                "{}: hybrid {} < claimed {}",
                config.config.name,
                config.hybrid_security,
                config.claimed_security
            );
            assert!(
                config.is_production_safe(),
                "{} is not production-safe",
                config.config.name
            );
        }
    }

    #[test]
    fn every_production_prime_is_ntt_compatible() {
        for config in [
            SecureConfig::secure_128(),
            SecureConfig::secure_128_deep(),
            SecureConfig::secure_192(),
            SecureConfig::secure_256(),
        ] {
            for (index, &prime) in config.config.primes.iter().enumerate() {
                assert!(
                    is_ntt_compatible(prime, config.config.n),
                    "{} is not NTT-compatible for N={} ({})",
                    prime,
                    config.config.n,
                    config.config.name
                );
                for &prior in &config.config.primes[..index] {
                    assert_ne!(prior, prime);
                    assert_eq!(gcd(prior, prime), 1);
                }
            }
        }
    }

    #[test]
    fn test_configs_are_not_production_safe() {
        assert!(!SecureConfig::test_fast_insecure().is_production_safe());
        assert!(!SecureConfig::test_medium_insecure().is_production_safe());
    }

    #[test]
    fn exact_product_bit_length_matches_known_chains() {
        assert_eq!(
            exact_product_bit_length(&[998244353, 985661441, 754974721, 469762049]),
            119
        );
        assert!(
            exact_product_bit_length(&[
                998244353, 985661441, 754974721, 469762049, 167772161, 595591169,
            ]) > 128
        );
    }

    #[test]
    fn security_summary_table_is_consistent() {
        let configs = [
            ("test_fast", SecureConfig::test_fast_insecure()),
            ("test_medium", SecureConfig::test_medium_insecure()),
            ("secure_128", SecureConfig::secure_128()),
            ("secure_192", SecureConfig::secure_192()),
        ];

        for (name, config) in configs {
            let log_q: u32 = config
                .config
                .primes
                .iter()
                .map(|&p| 64 - p.leading_zeros())
                .sum();
            // The hybrid estimate never exceeds the classical estimate, and the
            // quantum estimate never exceeds the hybrid one (screening invariant).
            assert!(
                config.classical_security >= config.hybrid_security,
                "{name}: classical {} < hybrid {}",
                config.classical_security,
                config.hybrid_security
            );
            assert!(
                config.hybrid_security >= config.quantum_security,
                "{name}: hybrid {} < quantum {}",
                config.hybrid_security,
                config.quantum_security
            );
            assert!(log_q > 0, "{name}: empty modulus chain");
        }
    }

    #[test]
    fn test_production_safety_verification() {
        // Production configs should pass
        let secure_128 = SecureConfig::secure_128();
        assert!(verify_production_safety(&secure_128).is_ok());

        let secure_192 = SecureConfig::secure_192();
        assert!(verify_production_safety(&secure_192).is_ok());

        let secure_256 = SecureConfig::secure_256();
        assert!(verify_production_safety(&secure_256).is_ok());

        // Test configs should fail
        let test_fast = SecureConfig::test_fast_insecure();
        assert!(verify_production_safety(&test_fast).is_err());

        let test_medium = SecureConfig::test_medium_insecure();
        assert!(verify_production_safety(&test_medium).is_err());
    }

    #[test]
    fn test_production_safe_trait() {
        // This should not panic in test mode
        let config = SecureConfig::secure_128();
        config.require_production_safe();

        // Test configs have the trait but will panic in release
        let test_config = SecureConfig::test_fast_insecure();
        // In test mode, this will not panic
        test_config.require_production_safe();
    }

    // =====================================================================
    // ISSUE #85 — `try_new` MUST RETURN, NOT PANIC, ON INVALID CONFIG
    // =====================================================================
    //
    // `production_safety_checks` is the raw predicate with no
    // test/debug_assertions/allow_insecure bypass, so — unlike
    // `verify_production_safe_fhe_config`, which is deliberately a no-op
    // under `cfg(test)` — these violation branches are reachable and
    // assertable from a normal `cargo test` run. This is what
    // `RNSFHEContext::try_new` calls (via `verify_production_safe_fhe_config`
    // outside test/debug builds), so pinning the exact `Nine65Error` here
    // pins `try_new`'s release-mode contract without needing a
    // release-without-test-cfg build to observe it directly.

    #[test]
    fn production_safety_checks_rejects_dimension_below_the_audited_floor() {
        let mut config = SecureConfig::secure_128().into_config();
        config.n = 4096; // below the audited N=8192 floor

        let error = production_safety_checks(&config)
            .expect_err("N=4096 must be rejected, not silently accepted");
        match error {
            Nine65Error::ConfigError { message } => {
                assert!(message.contains("N=4096"), "message was: {message}");
                assert!(message.contains("8192"), "message was: {message}");
            }
            other => panic!("expected ConfigError for dimension floor, got {other:?}"),
        }
    }

    #[test]
    fn production_safety_checks_rejects_a_config_that_screens_below_its_claim() {
        // N clears the 8192 floor, but claiming 256-bit security on a
        // 3-prime, ~90-bit-modulus chain (the actual secure_128 tuple) is
        // nowhere near sufficient: the CoreSVP screen must reject it.
        let mut config = SecureConfig::secure_128().into_config();
        config.security_bits = 256;

        let error = production_safety_checks(&config)
            .expect_err("an unmet security claim must be rejected, not silently accepted");
        match error {
            Nine65Error::SecurityLevelNotMet { bits, required } => {
                assert_eq!(required, 256);
                assert!(
                    bits < required,
                    "screened bits ({bits}) should be below the claim ({required})"
                );
            }
            other => panic!("expected SecurityLevelNotMet, got {other:?}"),
        }
    }

    #[test]
    fn production_safety_checks_rejects_a_modulus_over_the_he_standard_bound() {
        // n=8192 with a 128-bit claim allows log2(q) <= 218
        // (`HEStandardBounds::max_log_q(8192, 128)`). Stack enough NTT-valid
        // 30-bit primes to blow well past that bound while keeping the
        // CoreSVP screen from being the branch that fires first: a bigger Q
        // at fixed N raises the CoreSVP estimate's assumed attack advantage
        // less steeply than the linear standard-table bound does, so a
        // moderate overshoot trips the table before it trips CoreSVP.
        let base = SecureConfig::secure_256().into_config(); // 6 NTT-valid primes, log2(q)=175
        let mut primes = base.primes.clone();
        primes.extend(base.primes.iter().copied()); // duplicate: log2(q) ~= 350
        let config = FHEConfig {
            n: 8192,
            primes,
            q: base.q,
            t: base.t,
            eta: base.eta,
            security_bits: 128,
            name: "test_he_standard_bound_violation",
        };

        let error = production_safety_checks(&config)
            .expect_err("a modulus far past the HE Standard bound must be rejected");
        // Whichever screen catches it first (CoreSVP or the HE Standard
        // table), it must be a typed error, never a panic — that is the
        // property this test exists to pin. Both branches are legitimate
        // rejections of the same oversized-Q config.
        assert!(matches!(
            error,
            Nine65Error::SecurityLevelNotMet { .. } | Nine65Error::ConfigError { .. }
        ));
    }

    #[test]
    fn production_safety_checks_accepts_every_named_secure_config() {
        for config in [
            SecureConfig::secure_128().into_config(),
            SecureConfig::secure_128_deep().into_config(),
            SecureConfig::secure_192().into_config(),
            SecureConfig::secure_256().into_config(),
        ] {
            assert!(
                production_safety_checks(&config).is_ok(),
                "named config '{}' must pass its own production-safety screen",
                config.name
            );
        }
    }

    #[test]
    fn verify_production_safe_fhe_config_never_panics_on_hostile_input() {
        // The behavioral contract `try_new` depends on: no matter how
        // invalid the config, the fallible path returns `Err`, and the
        // process stays alive to receive it (no `assert!`/`panic!`
        // reachable). Under `cfg(test)` this is a deliberate no-op — see
        // the doc comment on `verify_production_safe_fhe_config` — but that
        // no-op is itself part of the contract under test: this call must
        // not panic either way.
        let mut hostile = SecureConfig::secure_128().into_config();
        hostile.n = 1;
        hostile.primes = vec![0];
        hostile.security_bits = usize::MAX;
        assert!(verify_production_safe_fhe_config(&hostile).is_ok());

        // And the constructor built on top of it must likewise return
        // `Err`, never abort, when given the same hostile config directly.
        assert!(crate::ops::rns_fhe::RNSFHEContext::try_new(&hostile).is_err());
    }
}
