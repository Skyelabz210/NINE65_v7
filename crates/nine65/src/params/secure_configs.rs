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
//! | `secure_128` | 8192 | 4 NTT primes | 119 | 128 bits | 196 | 176 | yes |
//! | `secure_128_deep` | 8192 | 4 NTT primes | 119 | 128 bits | 196 | 176 | yes |
//! | `secure_192` | 16384 | 5 NTT primes | 146 | 192 bits | 320 | 288 | yes |
//! | `secure_256` | 16384 | 6 NTT primes | 175 | 256 bits | 267 | **240** | yes |
//!
//! CORRECTION (WR-7, 2026-09-03): this table previously listed `secure_128`
//! at 3 NTT primes / log2(q)=90 / Core-SVP 259 / MATZOV 233 / refused. That
//! described the tuple BEFORE the 2026-08-26 re-cut
//! (`docs/OPEN_WORK_2026-08-26.md` A3), which gave `secure_128` the same
//! four-prime chain `secure_128_deep` already carried -- it is now
//! numerically identical to `secure_128_deep` (same tuple, same screen, same
//! admission below); the two remain separate named entry points only for
//! call sites that spell out "deep" explicitly, see the constructors' own
//! doc comments. The per-constructor doc comments on `secure_128`/
//! `secure_128_deep` below, and the pinned numbers in
//! `tests::screened_levels_for_named_configs`, already reflected the
//! four-prime chain; only this header table had drifted. `CLAUDE.md`'s
//! Security Configs table and Bootstrap Paths section carried the same stale
//! three-prime description and have since been corrected separately (see
//! `docs/PUBLIC_REFRESH_CORRUPTS_ADMITTED_CONFIGS_2026-09-03.md` for the
//! finding that prompted it); this header is corrected here because it is a
//! doc comment inside the file WR-7 touches, and it disagreed with the
//! code's own pinned test in the same file.
//!
//! `secure_256` is the one name that its own screen does not fully support:
//! it clears 256 under Core-SVP (the model the constructor gates on) and falls
//! 16 bits short under MATZOV. The constructor is left in place rather than
//! renamed (issue #76 is resolved as a typed admission distinction, not a
//! rename -- see [`SecurityAdmissionState`] and
//! [`SecureConfig::is_production_safe_under_all_models`]); the gap is
//! documented on `secure_256` itself and readable at runtime via
//! `SecureConfig::screened_security_dual`.
//!
//! # Factorization-aware admission (WR-7)
//!
//! Every named constructor below also runs its exact ordered prime list
//! through [`security_estimator::LatticeSecurityEstimator::dual_estimate_with_factorization`]
//! -- the structural screen that can see modulus SHAPE (narrow lanes, prime
//! powers, powers of two, malformed factorizations), not just bit width --
//! under both Core-SVP and MATZOV, and fails closed (never falls back to the
//! width-only number) if either model's structural screen REFUSES the
//! shape. For every tuple shipped today this reproduces the width-only
//! numbers exactly (`security_estimator::tests::factored_screen_leaves_every_secure_config_unchanged`),
//! because every shipped lane is a distinct prime well above the modelled
//! floor; the screen only bites on shapes the width-only model cannot see.
//! [`SecureConfig::custom_screened`] runs the identical policy, fallibly,
//! for caller-supplied tuples.

use super::security_estimator::{
    CostModel, FactoredDualEstimate, HEStandardBounds, LatticeSecurityEstimator, SecretDistribution,
};
use super::FHEConfig;
// `gcd`/`is_ntt_compatible` are now exercised only by
// `every_production_prime_is_ntt_compatible` below (their production caller,
// `validate_class_f_chain`, was dead code and has been removed) -- gate the
// import so a release build doesn't warn them as unused.
#[cfg(test)]
use super::{gcd, is_ntt_compatible};
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

/// The programmatically distinguishable state a [`SecureConfig`]'s security
/// number is actually in. Issues #87/#88 both require this: a caller must be
/// able to TELL, at the type level, whether a config's number is a bare
/// claim, a fully agreed-upon screen, a screen with a known model gap, or a
/// test-only tier -- never infer it from prose or from `claimed_security`
/// alone.
///
/// Every non-insecure-tier [`SecureConfig`] is guaranteed, by construction,
/// to be in one of the `Screened*` states: [`SecureConfig::try_new_verified`]
/// (via [`SecureConfig::new_verified`]/[`SecureConfig::custom_screened`])
/// fails closed -- returns `Err`/panics -- rather than construct a
/// `SecureConfig` whose factorization-aware structural screen was refused or
/// whose binding number misses its own claim. `StructurallyRefused` and
/// `BelowClaim` exist as typed states for completeness and for the insecure
/// test tier (which is permitted to construct despite either), not because a
/// production `SecureConfig` can reach them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityAdmissionState {
    /// Screened under both Core-SVP and MATZOV, structural and width-only
    /// agree, and the claim is met under BOTH models. The strongest state
    /// this module can certify without an external attestation.
    ScreenedFullModelAgreement,
    /// Screened; meets the claim under Core-SVP (the model construction
    /// gates on) but NOT under the more aggressive MATZOV model.
    /// `secure_256` is the one shipped config in this state -- see issue
    /// #76. `matzov_bits` is the MATZOV binding result and `shortfall_bits`
    /// is `claimed_security - matzov_bits`.
    ScreenedModelGap {
        matzov_bits: u32,
        shortfall_bits: u32,
    },
    /// The factorization-aware structural screen declined outright (narrow
    /// lane, prime power, power of two, non-coprime lanes, or a malformed
    /// factorization) under at least one cost model. Unreachable for a
    /// non-insecure-tier `SecureConfig`; kept as a typed state rather than
    /// collapsed into a panic path, so a future fallible caller
    /// (`custom_screened`) has somewhere honest to land if this invariant is
    /// ever relaxed.
    StructurallyRefused,
    /// Screened by both models, structural screen did not refuse, but the
    /// binding result still falls below the claim. Reachable only by the
    /// `_insecure` test/benchmark tier, which is explicitly exempted from
    /// the fail-closed claim check.
    BelowClaim { core_svp_bits: u32 },
    /// Explicit non-production test/benchmark tier (`..._insecure` naming
    /// convention). Never eligible for production regardless of what it
    /// screens at -- see [`SecureConfig::is_production_safe`].
    InsecureTier,
}

/// Exact fingerprint of a parameter tuple `(N, ordered main-lane primes, t,
/// eta)`.
///
/// Frozen so an external lattice-estimator attestation ([`ExternalAttestation`])
/// can be bound to the PRECISE tuple it was run against, rather than to a
/// config *name* whose tuple can be redefined underneath it -- exactly what
/// happened to `secure_128` on 2026-08-26
/// (`docs/OPEN_WORK_2026-08-26.md` A3): the name kept its 128-bit claim
/// across a change from three main primes to four, which would have silently
/// invalidated a name-keyed attestation.
///
/// Integer-only 64-bit FNV-1a over the exact scalar fields and the ordered
/// prime list -- no floats, no truncation, no saturation/sentinel value
/// standing in for "no fingerprint" (there is no such state; every tuple
/// fingerprints). This is NOT a cryptographic hash and makes no
/// collision-resistance claim: it exists to catch accidental tuple drift
/// between a constructor and an archived attestation, never to defeat an
/// adversary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ParameterFingerprint(pub u64);

impl ParameterFingerprint {
    const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    fn fold_u64(hash: u64, value: u64) -> u64 {
        let mut hash = hash;
        for byte in value.to_le_bytes() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(Self::FNV_PRIME);
        }
        hash
    }

    /// Fingerprint the exact tuple an [`FHEConfig`] carries: `n`, the lane
    /// count, every main lane in order, `t`, and `eta`. Deliberately
    /// excludes `security_bits` and `name` -- those are labels, not the
    /// modulus, and relabeling the same arithmetic tuple must not change its
    /// fingerprint.
    pub fn of(config: &FHEConfig) -> Self {
        let mut hash = Self::FNV_OFFSET_BASIS;
        hash = Self::fold_u64(hash, config.n as u64);
        hash = Self::fold_u64(hash, config.primes.len() as u64);
        for &prime in &config.primes {
            hash = Self::fold_u64(hash, prime);
        }
        hash = Self::fold_u64(hash, config.t);
        hash = Self::fold_u64(hash, config.eta as u64);
        Self(hash)
    }
}

/// A record of an EXTERNAL lattice-estimator run (e.g. the Albrecht et al.
/// `lattice-estimator`, SageMath) against one exact tuple.
///
/// This type only ACCEPTS and archives such a result; nothing in this crate
/// runs an external estimator (issue #75 /
/// `docs/CLAIM_SURFACE_AND_LIMITS_2026-08-22.md`). No shipped config has one
/// of these recorded today -- constructing an `ExternalAttestation` with
/// fabricated data to make a config LOOK independently attested would be
/// exactly the overclaim WR-7 exists to prevent, so every field here must be
/// supplied from a real external run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalAttestation {
    /// Fingerprint of the exact tuple the external run covered.
    pub fingerprint: ParameterFingerprint,
    /// Free-text name/version of the external tool, e.g.
    /// `"lattice-estimator @ <commit-or-release>"`. Free-form because this
    /// crate never invokes the tool and cannot normalize a versioning scheme
    /// it has never run.
    pub estimator_name: String,
    /// The run's own reported bit-security number, when it reports one
    /// scalar per model. `None` when only the raw output is meaningful.
    pub reported_bits: Option<u32>,
    /// Verbatim raw output, or a stable reference to where it is archived
    /// (e.g. a doc path). Never truncated or reformatted by this type.
    pub raw_output_reference: String,
    /// Free-text date/provenance of the run; this crate does not parse it.
    pub run_date: String,
}

impl ExternalAttestation {
    /// Bind this attestation to a live [`SecureConfig`]: `Ok(())` only when
    /// the fingerprints agree exactly. A mismatch means the attestation was
    /// run against a DIFFERENT tuple than the one asking to use it -- never
    /// treated as advisory, because "close enough" is exactly how a
    /// redefinition like the 2026-08-26 `secure_128` re-cut would silently
    /// keep a stale attestation attached to a new tuple.
    pub fn verify_binds_to(&self, config: &SecureConfig) -> Result<(), String> {
        let live = config.fingerprint();
        if self.fingerprint != live {
            return Err(format!(
                "external attestation fingerprint {:?} does not match config '{}''s live \
                 fingerprint {:?} -- the tuple changed since this attestation was recorded, or \
                 the attestation was recorded against a different tuple entirely. Re-run the \
                 external estimator against the current tuple before trusting this result.",
                self.fingerprint, config.config.name, live,
            ));
        }
        Ok(())
    }
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
    /// The typed admission state this tuple actually landed in -- see
    /// [`SecurityAdmissionState`]. WR-7 / issue #88: callers must be able to
    /// tell programmatically which state a config is in, not just read prose.
    pub admission_state: SecurityAdmissionState,
}

impl SecureConfig {
    /// Fallible core of every constructor in this module. Named production
    /// constructors (`secure_128`, ...) call this through
    /// [`Self::new_verified`], which unwraps with a panic -- appropriate for
    /// a fixed compile-time literal, where a failure is a programmer error
    /// caught the moment the binary starts. Caller-supplied tuples must
    /// never panic on bad input, so [`Self::custom_screened`] returns this
    /// method's `Result` directly.
    ///
    /// Runs, in order: basic shape validation (power-of-two N, distinct
    /// prime NTT-compatible lanes, valid plaintext modulus) with typed
    /// errors; the width-only estimator (`LatticeSecurityEstimator::estimate`,
    /// what `is_production_safe`'s Core-SVP contract has always gated on);
    /// and -- WR-7 / issue #87 -- the factorization-aware structural screen
    /// under BOTH Core-SVP and MATZOV
    /// (`dual_estimate_with_factorization`), which fails closed on a
    /// `Refused` verdict rather than silently falling back to the
    /// width-only number. Configs explicitly marked insecure (test/
    /// benchmark tier, name ends `_insecure`) are exempt from every
    /// fail-closed check below; their shortfall is instead RECORDED in
    /// [`SecurityAdmissionState::BelowClaim`]/`StructurallyRefused`, and
    /// `is_production_safe`/`verify_production_safety` reject them at use
    /// time. No partial-credit relaxation is accepted for a real claim.
    fn try_new_verified(
        n: usize,
        primes: Vec<u64>,
        t: u64,
        eta: usize,
        claimed_security: u32,
        name: &'static str,
    ) -> Nine65Result<Self> {
        if !n.is_power_of_two() {
            return Err(Nine65Error::InvalidParameter {
                message: format!("N must be a power of two, got {n}"),
            });
        }
        if primes.is_empty() {
            return Err(Nine65Error::InvalidParameter {
                message: "at least one RNS prime is required".to_string(),
            });
        }
        if t < 2 {
            return Err(Nine65Error::InvalidParameter {
                message: "plaintext modulus must be at least two".to_string(),
            });
        }
        if !primes.iter().all(|&prime| t < prime) {
            return Err(Nine65Error::InvalidParameter {
                message: "plaintext modulus must be smaller than every RNS prime".to_string(),
            });
        }
        // Every declared lane must actually BE a distinct, NTT-compatible
        // prime -- correctness preconditions for the RNS/NTT pipeline, not
        // security screening (a composite or non-NTT-compatible lane simply
        // breaks the arithmetic). The structural security screen below only
        // sees what is passed to it; this is what stops a caller handing it
        // something that was never a valid CLASS-F chain to begin with.
        for (index, &prime) in primes.iter().enumerate() {
            if !is_prime(prime) {
                return Err(Nine65Error::InvalidParameter {
                    message: format!("RNS lane {index} ({prime}) is not prime"),
                });
            }
            if !is_ntt_compatible(prime, n) {
                return Err(Nine65Error::InvalidParameter {
                    message: format!("RNS lane {prime} is not NTT-compatible for N={n}"),
                });
            }
            for &prior in &primes[..index] {
                if prior == prime || gcd(prior, prime) != 1 {
                    return Err(Nine65Error::InvalidParameter {
                        message: format!("RNS lanes {prior} and {prime} are not coprime"),
                    });
                }
            }
        }

        let q = primes[0];
        let log_q = exact_product_bit_length(&primes);
        let estimator = LatticeSecurityEstimator::new(CostModel::CoreSVP);
        let estimate = estimator.estimate(n, log_q, SecretDistribution::Ternary, claimed_security);
        let he_standard_compliant = HEStandardBounds::is_compliant(n, log_q, claimed_security);

        // WR-7 / issue #87: factorization-aware structural screen, both cost
        // models, bound to the min (`dual_estimate_with_factorization`'s own
        // `binding_bits`). For every tuple shipped today this reproduces the
        // width-only numbers exactly -- every shipped lane is a distinct
        // prime well above the modelled floor -- but it is what actually
        // catches a narrow/prime-power/power-of-two/malformed shape the
        // width-only model above cannot see at all.
        let factors: Vec<(u64, u32)> = primes.iter().map(|&p| (p, 1)).collect();
        let structural: FactoredDualEstimate = estimator.dual_estimate_with_factorization(
            n,
            &factors,
            SecretDistribution::Ternary,
            claimed_security,
        );

        let is_insecure_tier = name.ends_with("_insecure");

        // Fail closed (#87 requirement 3): a REFUSED structural verdict
        // refuses a real claim outright. It never falls back to the
        // width-only `estimate` above, even though that number exists and
        // even though it might individually meet the claim.
        if !is_insecure_tier && structural.binding_bits.is_none() {
            return Err(Nine65Error::SecurityScreenRefused {
                reason: format!(
                    "config '{name}': the factorization-aware structural screen REFUSED this \
                     modulus shape under at least one cost model -- no production security \
                     number may be asserted for it.\nCore-SVP: {}\nMATZOV: {}",
                    structural.core_svp.analysis, structural.matzov.analysis,
                ),
            });
        }
        if !is_insecure_tier && estimate.effective_bits < claimed_security {
            return Err(Nine65Error::SecurityLevelNotMet {
                bits: estimate.effective_bits,
                required: claimed_security,
            });
        }
        if !is_insecure_tier && !he_standard_compliant {
            return Err(Nine65Error::ConfigError {
                message: format!("config '{name}' exceeds the HE Standard bound"),
            });
        }
        // Conservative production floor: any >= 128-bit security claim
        // requires N >= 8192: the lattice estimator blesses smaller N, but the
        // audited N >= 8192 floor governs production claims. Insecure test
        // tiers are exempt.
        if !is_insecure_tier && claimed_security >= 128 && n < 8192 {
            return Err(Nine65Error::ConfigError {
                message: format!(
                    "config '{name}' claims {claimed_security}-bit security but dimension \
                     N={n} is below the 8192 floor"
                ),
            });
        }

        // WR-7 / issue #88: the typed admission state a caller can inspect
        // instead of re-deriving from the raw bit counts. Every non-insecure
        // branch above already returned `Err` on exactly the conditions that
        // would otherwise land here as `StructurallyRefused`/`BelowClaim`,
        // so those two states are reachable only via the insecure tier.
        let admission_state = if is_insecure_tier {
            SecurityAdmissionState::InsecureTier
        } else {
            match structural.binding_bits {
                None => SecurityAdmissionState::StructurallyRefused,
                // `binding_bits` is `Some` only when BOTH models' structural
                // screens are `Screened` (`FactoredDualEstimate`'s own doc:
                // "a refusal is structural, so both models always refuse
                // together"), so `effective_bits()` on either model is
                // guaranteed `Some` here too -- `.expect` documents that as
                // an invariant rather than papering over it with a `0` that
                // could be misread as a real bit count.
                Some(_) => {
                    const INVARIANT: &str =
                        "binding_bits is Some, so both models' effective_bits() must be Some";
                    let meets_core_svp = structural.core_svp.meets_claim();
                    let meets_matzov = structural.matzov.meets_claim();
                    if meets_core_svp && meets_matzov {
                        SecurityAdmissionState::ScreenedFullModelAgreement
                    } else if meets_core_svp {
                        let matzov_bits = structural.matzov.effective_bits().expect(INVARIANT);
                        SecurityAdmissionState::ScreenedModelGap {
                            matzov_bits,
                            shortfall_bits: claimed_security.saturating_sub(matzov_bits),
                        }
                    } else {
                        SecurityAdmissionState::BelowClaim {
                            core_svp_bits: structural.core_svp.effective_bits().expect(INVARIANT),
                        }
                    }
                }
            }
        };

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

        Ok(Self {
            config,
            claimed_security,
            classical_security: estimate.classical_bits,
            hybrid_security: estimate.hybrid_bits,
            quantum_security: estimate.quantum_bits,
            he_standard_compliant,
            admission_state,
        })
    }

    /// Named/fixed-tuple constructors call this. The tuple is a compile-time
    /// literal, so a screening failure here is a programmer error in this
    /// module, not caller input -- panicking immediately, at binary startup
    /// (every named constructor runs in `tests::*` and at every call site),
    /// is the correct fail-fast behavior. See [`Self::try_new_verified`] for
    /// the fallible logic and [`Self::custom_screened`] for the
    /// caller-facing entry point that returns the `Result` instead.
    fn new_verified(
        n: usize,
        primes: Vec<u64>,
        t: u64,
        eta: usize,
        claimed_security: u32,
        name: &'static str,
    ) -> Self {
        match Self::try_new_verified(n, primes, t, eta, claimed_security, name) {
            Ok(config) => config,
            Err(error) => panic!("SECURITY ERROR: config '{name}' failed screening: {error}"),
        }
    }

    /// Production-capable, fallible counterpart to the fixed-tuple named
    /// constructors above.
    ///
    /// Screens an arbitrary caller-supplied `(n, primes, t, eta)` tuple
    /// through the IDENTICAL exact-product + factorization-aware policy the
    /// named configs are built on, and returns a typed `Err` instead of
    /// panicking. This is what
    /// [`crate::params::FHEConfig::custom_screened`] and
    /// [`crate::params::FHEConfig::for_depth_screened`] route through --
    /// issue #88: a raw [`FHEConfig`] from `FHEConfig::custom`/`for_depth`
    /// alone is, by its TYPE, never mistakeable for a screened tuple (it
    /// carries no `admission_state`, no `hybrid_security`, no
    /// `he_standard_compliant`); only this constructor produces a
    /// `SecureConfig`, and it never does so silently for an unscreened or
    /// structurally-refused tuple.
    pub fn custom_screened(
        n: usize,
        primes: Vec<u64>,
        t: u64,
        eta: usize,
        claimed_security: u32,
    ) -> Nine65Result<Self> {
        Self::try_new_verified(n, primes, t, eta, claimed_security, "custom_screened")
    }

    /// Returns true only when the named claim, HE bound, and audited dimension
    /// floor are all satisfied.
    ///
    /// This is the contract `CLAUDE.md`'s Security Configs table documents:
    /// gated on the conservative Core-SVP model alone (`hybrid_security`),
    /// which is why `secure_256` -- 267 bits under Core-SVP, 240 under
    /// MATZOV, against a 256-bit claim -- passes this check. No config is
    /// renamed over that gap; see [`Self::is_production_safe_under_all_models`]
    /// for the stricter check that DOES refuse it.
    pub fn is_production_safe(&self) -> bool {
        self.hybrid_security >= self.claimed_security
            && self.he_standard_compliant
            && (self.claimed_security < 128 || self.config.n >= 8192)
    }

    /// Stricter than [`Self::is_production_safe`]: additionally requires the
    /// claim to be met under BOTH in-tree cost models, i.e.
    /// `admission_state == ScreenedFullModelAgreement`.
    ///
    /// This is WR-7's resolution of issue #76 ("secure_256 naming vs MATZOV
    /// binding"): rather than renaming `secure_256` (CLAUDE.md already
    /// settled that "no config is renamed"), a caller who needs assurance
    /// under the more aggressive MATZOV model as well as Core-SVP gets a
    /// typed gate that refuses `secure_256` -- 240 bits under MATZOV against
    /// its 256-bit claim -- while `secure_128`, `secure_128_deep`, and
    /// `secure_192` all still pass (each clears its own claim under both
    /// models). `secure_256` remains `is_production_safe()` under the
    /// existing Core-SVP-gated contract; this method is additive, not a
    /// replacement.
    pub fn is_production_safe_under_all_models(&self) -> bool {
        matches!(
            self.admission_state,
            SecurityAdmissionState::ScreenedFullModelAgreement
        ) && self.is_production_safe()
    }

    /// Exact fingerprint of this config's tuple. See [`ParameterFingerprint`].
    pub fn fingerprint(&self) -> ParameterFingerprint {
        ParameterFingerprint::of(&self.config)
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
    /// `new_verified` gates admission on Core-SVP alone. MATZOV is the more
    /// aggressive model and is routinely the smaller of the two, so a config
    /// can carry a name it meets under Core-SVP and misses under MATZOV.
    /// That gap is a labelling fact and is documented per-config rather than
    /// hidden (see [`SecureConfig::is_production_safe_under_all_models`]).
    ///
    /// WR-7 / issue #87 requirement 5: this is sourced from the SAME
    /// factorization-aware structural screen construction runs
    /// (`dual_estimate_with_factorization`), not a separately re-run
    /// width-only call, so a report generated from this method cannot name a
    /// different model than construction actually used. For every tuple
    /// shipped today the two are numerically identical
    /// (`security_estimator::tests::factored_screen_leaves_every_secure_config_unchanged`),
    /// so this changes no published number -- it only removes the
    /// possibility of the two silently diverging in the future.
    ///
    /// Panics if the structural screen REFUSES this tuple's shape. That is
    /// deliberate, not a gap: `ScreenedSecurity`'s fields are plain `u32`s
    /// (a pre-existing public shape this method must not silently repurpose
    /// into sentinel territory -- WR-7 prohibits exactly that, "no
    /// `u64::MAX`/`-1` markers, use proper typed Option/Result"), and a
    /// refused tuple has NO screened bit count to put in them; reporting `0`
    /// would read as "screens at 0 bits", which is a different and false
    /// claim. Every `SecureConfig` that can exist already fails closed on a
    /// structural refusal at construction (`try_new_verified`), so this can
    /// only fire if that invariant is ever relaxed -- an invariant
    /// violation, which should panic loudly rather than print a misleading
    /// number.
    pub fn screened_security_dual(&self) -> ScreenedSecurity {
        let factors: Vec<(u64, u32)> = self.config.primes.iter().map(|&p| (p, 1)).collect();
        let dual = LatticeSecurityEstimator::new(CostModel::CoreSVP)
            .dual_estimate_with_factorization(
                self.config.n,
                &factors,
                SecretDistribution::Ternary,
                self.claimed_security,
            );
        const INVARIANT: &str =
            "SecureConfig invariant violated: a live config's structural screen was REFUSED, \
             but try_new_verified is supposed to fail closed on that for every non-insecure-tier \
             config before a SecureConfig can exist";
        ScreenedSecurity {
            core_svp_bits: dual.core_svp.effective_bits().expect(INVARIANT),
            matzov_bits: dual.matzov.effective_bits().expect(INVARIANT),
            binding_bits: dual.binding_bits.expect(INVARIANT),
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

/// Validate a raw `FHEConfig` against its declared claim, with a 128-bit
/// minimum on production paths.
pub fn assert_production_safe_fhe_config(config: &FHEConfig) {
    if cfg!(any(test, debug_assertions, feature = "allow_insecure")) {
        return;
    }

    // `security_bits` on a raw `FHEConfig` is, at best, a caller-declared
    // claim -- `FHEConfig::custom` no longer derives it from a first-prime
    // heuristic (issue #88), and `FHEConfig::for_depth` stores the caller's
    // request verbatim, unverified. Either way this floor is what actually
    // governs: `security_bits` can only push the requirement UP, never
    // provide the proof that the tuple meets it.
    let required_security = (config.security_bits as u32).max(128);
    let log_q = exact_product_bit_length(&config.primes);
    let estimator = LatticeSecurityEstimator::new(CostModel::CoreSVP);
    let estimate = estimator.estimate(
        config.n,
        log_q,
        SecretDistribution::Ternary,
        required_security,
    );

    // WR-7 / issue #87 requirement 6: apply the same factorization-aware
    // structural policy to raw-config production validation. Fails closed
    // on a REFUSED verdict rather than falling back to `estimate` above.
    let factors: Vec<(u64, u32)> = config.primes.iter().map(|&p| (p, 1)).collect();
    let structural = estimator.dual_estimate_with_factorization(
        config.n,
        &factors,
        SecretDistribution::Ternary,
        required_security,
    );

    assert!(
        config.n >= 8192,
        "PRODUCTION SECURITY VIOLATION: N={} is below the audited floor N=8192",
        config.n
    );
    assert!(
        structural.binding_bits.is_some(),
        "PRODUCTION SECURITY VIOLATION: config '{}' modulus factorization was REFUSED by the \
         structural screen (narrow/prime-power/power-of-two/non-coprime/malformed lane) -- no \
         production security number may be asserted for it.\nCore-SVP: {}\nMATZOV: {}",
        config.name,
        structural.core_svp.analysis,
        structural.matzov.analysis,
    );
    assert!(
        estimate.effective_bits >= required_security,
        "PRODUCTION SECURITY VIOLATION: config '{}' screens at {} bits ({} required).\n{}",
        config.name,
        estimate.effective_bits,
        required_security,
        estimate.analysis,
    );
    assert!(
        HEStandardBounds::is_compliant(config.n, log_q, required_security),
        "PRODUCTION SECURITY VIOLATION: config '{}' exceeds the HE Standard modulus bound",
        config.name
    );
}

/// Return a detailed error rather than panicking.
pub fn verify_production_safety(config: &SecureConfig) -> Result<(), String> {
    // Defense in depth: `SecureConfig::try_new_verified` already fails
    // closed on these two states for anything but the insecure test tier,
    // so a `SecureConfig` reaching here in `StructurallyRefused`/
    // `BelowClaim` state can only be the insecure tier -- reject it by
    // typed state rather than only by the numeric checks below, so this
    // function keeps working even if a future numeric threshold changes.
    match config.admission_state {
        SecurityAdmissionState::StructurallyRefused => {
            return Err(
                "structural screen refused this modulus shape -- no production security \
                 number was ever assigned to it"
                    .to_string(),
            );
        }
        SecurityAdmissionState::InsecureTier => {
            return Err(format!(
                "config '{}' is an explicit insecure/test tier",
                config.config.name
            ));
        }
        SecurityAdmissionState::BelowClaim { .. }
        | SecurityAdmissionState::ScreenedModelGap { .. }
        | SecurityAdmissionState::ScreenedFullModelAgreement => {}
    }
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
    // WR-7: FACTORIZATION-AWARE PRODUCTION ADMISSION (issues #87, #88, #76)
    // =====================================================================

    /// The exact boundary #87 exists for: a lane that is genuinely prime,
    /// NTT-compatible, and coprime with every other lane -- so it sails past
    /// every shape check `custom_screened` runs -- can still be narrower
    /// than the structural screen's modelled floor. `65537` is exactly the
    /// manufactured-`Q = t * D` lane `security_estimator.rs`'s own module
    /// doc calls out, and the width-only model cannot see it at all (the
    /// full product is still wide).
    #[test]
    fn custom_screened_refuses_a_narrow_prime_lane() {
        let result =
            SecureConfig::custom_screened(8192, vec![65537, 998244353, 985661441], 257, 3, 128);
        let error = result.expect_err(
            "a narrow (17-bit) prime lane must be refused by the structural screen, not \
             silently screened by the width-only number",
        );
        assert!(
            matches!(error, Nine65Error::SecurityScreenRefused { .. }),
            "expected SecurityScreenRefused, got: {error:?}"
        );
        assert!(error.to_string().contains("REFUSED"));
    }

    /// Positive control: the same shape of tuple the named constructors use
    /// (four wide, distinct, coprime, NTT-compatible primes) must be
    /// admitted through the public fallible entry point too, and land in
    /// the SAME admission state `secure_128`/`secure_128_deep` do.
    #[test]
    fn custom_screened_admits_a_well_formed_wide_prime_chain() {
        let config = SecureConfig::custom_screened(
            8192,
            vec![998244353, 985661441, 754974721, 469762049],
            65537,
            3,
            128,
        )
        .expect("this is exactly secure_128_deep's own tuple; it must screen");
        assert_eq!(
            config.admission_state,
            SecurityAdmissionState::ScreenedFullModelAgreement
        );
        assert!(config.is_production_safe());
        assert!(config.is_production_safe_under_all_models());
    }

    /// A caller-supplied lane that is not prime at all must be refused as a
    /// shape error before it ever reaches the security screen -- distinct
    /// from a structural refusal, which is about lanes that ARE prime but
    /// have the wrong shape (narrow, power-of-two, ...).
    #[test]
    fn custom_screened_rejects_a_non_prime_lane() {
        let result = SecureConfig::custom_screened(8192, vec![998244352], 3, 2, 40);
        let error = result.expect_err("998244352 is even -- not prime");
        assert!(
            matches!(error, Nine65Error::InvalidParameter { .. }),
            "expected InvalidParameter for a non-prime lane, got: {error:?}"
        );
    }

    /// A tuple genuinely too small for the requested claim must fail on the
    /// numeric bound (`SecurityLevelNotMet`), which is a DIFFERENT typed
    /// outcome than a structural refusal (`SecurityScreenRefused`) -- the
    /// two must stay distinguishable, per #88's separation of "claimed
    /// but unmet" from "unscreenable at all".
    #[test]
    fn custom_screened_rejects_a_tuple_that_screens_below_its_claim() {
        // A single 30-bit prime at N=1024 is comfortably inside the
        // structural screen's modelled regime (wide, prime, NTT-compatible)
        // but nowhere near 256-bit security.
        let result = SecureConfig::custom_screened(1024, vec![998244353], 257, 2, 256);
        let error = result.expect_err("a single 30-bit lane at N=1024 cannot claim 256 bits");
        assert!(
            matches!(error, Nine65Error::SecurityLevelNotMet { .. }),
            "expected SecurityLevelNotMet (a number was produced and it was too low), got: {error:?}"
        );
    }

    /// `custom_screened` must reject a malformed tuple (N not a power of
    /// two) with a typed error, never a panic -- it takes caller-controlled
    /// input, unlike the fixed-literal named constructors.
    #[test]
    fn custom_screened_never_panics_on_malformed_input() {
        let result = SecureConfig::custom_screened(1000, vec![998244353], 257, 2, 40);
        assert!(result.is_err(), "N=1000 is not a power of two");
    }

    /// #76's resolution, asserted rather than only documented: `secure_256`
    /// is the one shipped config with a Core-SVP/MATZOV model gap, and it
    /// must be typed as such -- distinguishable at the type level from the
    /// three configs where both models agree -- without renaming anything.
    #[test]
    fn secure_256_is_typed_as_a_model_gap_not_full_agreement() {
        let s256 = SecureConfig::secure_256();
        match s256.admission_state {
            SecurityAdmissionState::ScreenedModelGap {
                matzov_bits,
                shortfall_bits,
            } => {
                assert_eq!(
                    matzov_bits, 240,
                    "pinned by screened_levels_for_named_configs"
                );
                assert_eq!(shortfall_bits, 16, "256 - 240");
            }
            other => panic!("secure_256 must be ScreenedModelGap, got {other:?}"),
        }
        // No config is renamed (CLAUDE.md's settled position): it remains
        // production-safe under the existing Core-SVP-gated contract...
        assert!(s256.is_production_safe());
        // ...but the stricter all-models gate -- WR-7's actual answer to
        // #76 -- refuses it.
        assert!(!s256.is_production_safe_under_all_models());
    }

    /// Every OTHER named production config clears both models and must be
    /// typed `ScreenedFullModelAgreement`, and pass the strict all-models
    /// gate `secure_256` fails.
    #[test]
    fn every_other_named_config_has_full_model_agreement() {
        for (name, config) in [
            ("secure_128", SecureConfig::secure_128()),
            ("secure_128_deep", SecureConfig::secure_128_deep()),
            ("secure_192", SecureConfig::secure_192()),
        ] {
            assert_eq!(
                config.admission_state,
                SecurityAdmissionState::ScreenedFullModelAgreement,
                "{name}: expected full model agreement"
            );
            assert!(
                config.is_production_safe_under_all_models(),
                "{name}: must pass the strict all-models gate"
            );
        }
    }

    /// The insecure test tier must be typed `InsecureTier` regardless of
    /// whether it happens to meet or miss its own (deliberately low) claim
    /// -- never conflated with a real screened state.
    #[test]
    fn insecure_tier_configs_are_typed_as_such() {
        assert_eq!(
            SecureConfig::test_fast_insecure().admission_state,
            SecurityAdmissionState::InsecureTier
        );
        assert_eq!(
            SecureConfig::test_medium_insecure().admission_state,
            SecurityAdmissionState::InsecureTier
        );
    }

    /// `screened_security_dual` (issue #87 requirement 5) must report
    /// numbers identical to the pinned structural table -- it is now
    /// sourced from the same `dual_estimate_with_factorization` call
    /// construction runs, not a separately re-run width-only estimate.
    #[test]
    fn screened_security_dual_matches_the_pinned_structural_table() {
        let s256 = SecureConfig::secure_256();
        let dual = s256.screened_security_dual();
        assert_eq!(dual.core_svp_bits, 267);
        assert_eq!(dual.matzov_bits, 240);
        assert_eq!(dual.binding_bits, 240);
        assert!(!dual.meets_claim_under_both);
    }

    // ---------------------------------------------------------------------
    // Fingerprints (issue #75: freeze the tuple before an external
    // attestation is claimed)
    // ---------------------------------------------------------------------

    /// Fingerprinting must be a PURE function of `(n, primes, t, eta)`: two
    /// configs built via completely different construction paths -- one
    /// through the fully screened, panic-on-failure named constructor
    /// (`secure_128_deep`, always available), the other through the
    /// `#[cfg(any(test, debug_assertions, feature = "allow_insecure"))]`
    /// gated insecure test tier's raw struct-literal style (built here by
    /// hand, bypassing screening entirely) -- must fingerprint identically
    /// whenever the underlying tuple is identical. This is the
    /// "feature-dependent" property #75/WR-7 asks tested: the fingerprint
    /// must not depend on which cfg-gated path constructed the config.
    #[test]
    fn fingerprint_is_independent_of_construction_path_and_feature_gating() {
        let via_named_constructor = SecureConfig::secure_128_deep();

        // Hand-built raw FHEConfig with the identical tuple, taking neither
        // the named-constructor path nor any screening at all -- exactly
        // the shape of the `_insecure` struct literals scattered through
        // this crate under `cfg(any(test, debug_assertions, feature =
        // "allow_insecure"))`.
        let hand_built = FHEConfig {
            n: 8192,
            primes: vec![998244353, 985661441, 754974721, 469762049],
            q: 998244353,
            t: 65537,
            eta: 3,
            security_bits: 0, // deliberately different from the claim below
            name: "hand_built_for_fingerprint_test",
        };

        assert_eq!(
            via_named_constructor.fingerprint(),
            ParameterFingerprint::of(&hand_built),
            "fingerprint must depend only on (n, primes, t, eta), not on \
             security_bits, name, or which construction path built the config"
        );
    }

    /// Deterministic across every named + insecure-tier config shipped
    /// today, and distinct across every DISTINCT tuple -- but not
    /// necessarily distinct across every NAME. Since the 2026-08-26 re-cut
    /// (`docs/OPEN_WORK_2026-08-26.md` A3) `secure_128` and
    /// `secure_128_deep` carry the byte-identical tuple, and a fingerprint
    /// keyed on the tuple (never the name -- that is the entire point, see
    /// [`ParameterFingerprint::of`]) is SUPPOSED to collide for those two.
    /// This groups configs by their expected tuple-equality class rather
    /// than assuming every name is numerically distinct, so it does not
    /// quietly start asserting something false about the current tree.
    ///
    /// Exercises both the always-available named constructors and the
    /// `_insecure` tier, which only exists under `cfg(any(test,
    /// debug_assertions, feature = "allow_insecure"))`, proving
    /// fingerprinting itself is not gated behind or sensitive to that
    /// feature.
    #[test]
    fn fingerprint_pins_across_all_named_and_insecure_tier_configs() {
        // Each inner slice is a group of names expected to SHARE a
        // fingerprint (because they share a tuple); different groups must
        // fingerprint differently from each other.
        let groups: Vec<Vec<(&str, SecureConfig)>> = vec![
            vec![
                ("secure_128", SecureConfig::secure_128()),
                ("secure_128_deep", SecureConfig::secure_128_deep()),
            ],
            vec![("secure_192", SecureConfig::secure_192())],
            vec![("secure_256", SecureConfig::secure_256())],
            vec![("test_fast_insecure", SecureConfig::test_fast_insecure())],
            vec![("test_medium_insecure", SecureConfig::test_medium_insecure())],
        ];

        let mut group_fingerprints = Vec::new();
        for group in &groups {
            let mut fps_in_group = std::collections::HashSet::new();
            for (name, config) in group {
                let fp = config.fingerprint();
                assert_eq!(
                    ParameterFingerprint::of(&config.config),
                    fp,
                    "{name}: fingerprint must be a pure, repeatable function of the tuple"
                );
                fps_in_group.insert(fp);
            }
            assert_eq!(
                fps_in_group.len(),
                1,
                "every name in this group is documented to share a tuple, so they must \
                 share a fingerprint: {group:?}"
            );
            group_fingerprints.push(*fps_in_group.iter().next().unwrap());
        }

        let mut seen_across_groups = std::collections::HashSet::new();
        for (group, fp) in groups.iter().zip(&group_fingerprints) {
            let names: Vec<&str> = group.iter().map(|(name, _)| *name).collect();
            assert!(
                seen_across_groups.insert(*fp),
                "{names:?}: this group's fingerprint collided with a DIFFERENT group's -- \
                 those tuples are not supposed to be equal"
            );
        }
    }

    /// A single-prime change must change the fingerprint -- it is not
    /// merely a function of lane COUNT or of `n`.
    #[test]
    fn fingerprint_changes_when_a_single_lane_changes() {
        let a = SecureConfig::custom_screened(
            8192,
            vec![998244353, 985661441, 754974721, 469762049],
            65537,
            3,
            128,
        )
        .expect("secure_128_deep's own tuple");
        let b = SecureConfig::custom_screened(
            16384,
            vec![998244353, 985661441, 754974721, 469762049, 167772161],
            65537,
            4,
            192,
        )
        .expect("secure_192's own tuple");

        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    /// #75: this crate archives an attestation against the exact tuple it
    /// covers, and REJECTS a mismatched one rather than accepting it as
    /// advisory -- the whole point of freezing a fingerprint before any
    /// attestation is claimed. No shipped config has a real external
    /// attestation recorded (that is #75's still-open, human-owned part);
    /// this exercises only the typed accept/reject machinery with a
    /// synthetic record, never asserts a real external result.
    #[test]
    fn external_attestation_binds_only_to_its_own_fingerprint() {
        let s128 = SecureConfig::secure_128();
        let s192 = SecureConfig::secure_192();

        let matching = ExternalAttestation {
            fingerprint: s128.fingerprint(),
            estimator_name: "synthetic-test-double, not a real run".to_string(),
            reported_bits: Some(196),
            raw_output_reference: "test-only synthetic record".to_string(),
            run_date: "n/a".to_string(),
        };
        assert!(matching.verify_binds_to(&s128).is_ok());

        let mismatched = ExternalAttestation {
            fingerprint: s192.fingerprint(),
            ..matching
        };
        let error = mismatched
            .verify_binds_to(&s128)
            .expect_err("an attestation for secure_192's tuple must not bind to secure_128");
        assert!(error.contains("does not match"));
    }

    /// A tuple redefinition under an UNCHANGED name (exactly what happened
    /// to `secure_128` on 2026-08-26) must change the fingerprint. An
    /// attestation keyed only to the config NAME would have silently kept
    /// applying across that redefinition; one keyed to the fingerprint
    /// cannot.
    #[test]
    fn fingerprint_would_have_caught_the_secure_128_recut() {
        let old_three_prime_shape = FHEConfig {
            n: 8192,
            primes: vec![998244353, 985661441, 754974721],
            q: 998244353,
            t: 65537,
            eta: 3,
            security_bits: 128,
            name: "secure_128",
        };
        let current = SecureConfig::secure_128();
        assert_ne!(
            ParameterFingerprint::of(&old_three_prime_shape),
            current.fingerprint(),
            "the retired three-prime secure_128 and the current four-prime secure_128 share a \
             name but must not share a fingerprint"
        );
    }

    // ---------------------------------------------------------------------
    // `FHEConfig::custom`/`for_depth` are unscreened by construction
    // ---------------------------------------------------------------------

    /// `custom` no longer derives `security_bits` from the legacy
    /// first-prime heuristic -- it is always `0`, i.e. never a number a
    /// caller could mistake for a claim.
    #[test]
    fn raw_custom_never_asserts_a_security_number() {
        let config = FHEConfig::custom(2048, vec![998244353], 1024, 2).expect("valid shape");
        assert_eq!(config.security_bits, 0);

        // Same first prime as a config that would, under the retired
        // heuristic, have reported a nonzero number purely from that one
        // prime's width -- pinning that this constructor no longer does so
        // for ANY input, not just this one.
        let wider = FHEConfig::custom(8192, vec![998244353, 985661441, 754974721], 65537, 3)
            .expect("valid shape");
        assert_eq!(wider.security_bits, 0);
    }
}
