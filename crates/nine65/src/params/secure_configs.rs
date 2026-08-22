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
// MEASURED EVIDENCE (2026-08-22, `cargo test -p nine65 --lib --release
// diag_measure_noise_growth -- --nocapture`, which encrypts under each config,
// runs one public refresh, and checks the result against the decryption
// oracle):
//
//   secure_128       3 lanes  bootstrap(fresh 7) -> decrypts 8   WRONG (+1)
//                             bootstrap(7)^2     -> decrypts 51445, expected 49
//   secure_128_deep  4 lanes  bootstrap(fresh 7) -> decrypts 7   correct
//                             bootstrap(7)^2     -> decrypts 49  correct
//   secure_192       5 lanes  bootstrap(fresh 7) -> decrypts 7   correct
//                             bootstrap(7)^2     -> decrypts 49  correct
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
// secure_128 is predicted to clear the bar with 49 bits against a 45-bit
// requirement, and the decryption oracle above says it does not. Under the
// worst-case bound it is 42 bits against 45 and is correctly refused, while
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
             fund one ct x ct multiply plus relinearization afterwards. A public \
             refresh on this chain returns a wrong-but-plausible plaintext \
             (measured: encrypt(7) -> refresh -> decrypt yields 8). Use a config \
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
        let estimate = estimator.estimate(
            n,
            log_q,
            SecretDistribution::Ternary,
            claimed_security,
        );
        let he_standard_compliant =
            HEStandardBounds::is_compliant(n, log_q, claimed_security);

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
        // requires N >= 8192 (see hardware_opt's note — the lattice estimator
        // blesses smaller N, but the audited N >= 8192 floor governs
        // production claims). Insecure test tiers are exempt.
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
    /// assessed the former tuple below its 128-bit claim. The RNS chain remains
    /// three NTT-friendly primes so the arithmetic/noise capacity is unchanged;
    /// this change increases the lattice dimension and security margin.
    ///
    /// Screened 2026-08-22: Core-SVP 259 bits, MATZOV 233 bits. The name is not
    /// an overclaim; both models clear 128.
    ///
    /// **No public refresh on this chain.** Three main primes leave 42 bits of
    /// `Delta` headroom after a public refresh against the 45 bits one
    /// subsequent multiply needs, and the refresh output is already wrong at the
    /// decryption oracle (`encrypt(7) -> refresh -> decrypt` yields `8`).
    /// [`ensure_public_refresh_supported`] refuses it, and
    /// `ClockworkBootstrap::bootstrap` returns that refusal. Use
    /// [`SecureConfig::secure_128_deep`] — same 128-bit claim, four primes — when
    /// the workload needs evaluator-side refresh.
    pub fn secure_128() -> Self {
        Self::new_verified(
            8192,
            vec![998244353, 985661441, 754974721],
            65537,
            3,
            128,
            "secure_128",
        )
    }

    /// 128-bit candidate with a four-prime chain for deeper leveled work.
    ///
    /// Screened 2026-08-22: Core-SVP 196 bits, MATZOV 176 bits — both clear the
    /// 128-bit name. The longer chain costs screened margin relative to
    /// `secure_128` (log2(q) 119 vs 90 at the same N) and buys arithmetic
    /// headroom: this is the shortest chain that carries a **public** refresh
    /// (71 bits of post-refresh `Delta` headroom against a 45-bit requirement),
    /// verified against the decryption oracle.
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
    /// (96 bits of post-refresh `Delta` headroom against a 48-bit requirement).
    pub fn secure_192() -> Self {
        Self::new_verified(
            16384,
            vec![
                998244353,
                985661441,
                754974721,
                469762049,
                167772161,
            ],
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
                998244353,
                985661441,
                754974721,
                469762049,
                167772161,
                595591169,
            ],
            65_537,
            5,
            256,
            "secure_256",
        )
    }

    /// Hardware-optimized configuration using composite anchors (Separation Principle showcase)
    pub fn hardware_opt() -> Self {
        // N=8192 satisfies the audited production floor for the 128-bit claim.
        // (The lattice estimator blesses 4096 at hybrid≈129, but the conservative
        // N>=8192 floor governs any >=128-bit production claim.)
        Self::new_verified(
            8192,
            vec![
                998244353, 985661441, 754974721,
            ],
            65537,
            3,
            128,
            "hardware_opt",
        )
    }

    // =========================================================================
    // TEST/BENCHMARK CONFIGURATIONS (NOT FOR PRODUCTION)
    // =========================================================================

    /// Fast test configuration. Never deploy with sensitive data.
    #[cfg(any(test, debug_assertions, feature = "allow_insecure"))]
    pub fn test_fast_insecure() -> Self {
        Self::new_verified(
            1024,
            vec![998_244_353],
            65_537,
            2,
            40,
            "test_fast_insecure",
        )
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

    let required_security = (config.security_bits as u32).max(128);
    let log_q = exact_product_bit_length(&config.primes);
    let estimator = LatticeSecurityEstimator::new(CostModel::CoreSVP);
    let estimate = estimator.estimate(
        config.n,
        log_q,
        SecretDistribution::Ternary,
        required_security,
    );

    assert!(
        config.n >= 8192,
        "PRODUCTION SECURITY VIOLATION: N={} is below the audited floor N=8192",
        config.n
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
    /// Ground truth (`cargo test -p nine65 --lib --release
    /// diag_measure_noise_growth -- --nocapture`, run 2026-08-22):
    /// `secure_128` refreshes `encrypt(7)` into a ciphertext that decrypts to
    /// `8`; `secure_128_deep` and `secure_192` decrypt to `7` and then square
    /// correctly to `49`.
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
                expect_supported: false,
            },
            Case {
                config: SecureConfig::hardware_opt().into_config(),
                expect_supported: false,
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
    /// chain, so lengthening `secure_128`'s chain by one prime admits it and
    /// shortening `secure_128_deep`'s by one refuses it.
    #[test]
    fn public_refresh_predicate_is_not_a_name_match() {
        let mut lengthened = SecureConfig::secure_128().into_config();
        lengthened.primes.push(469_762_049);
        assert!(
            supports_public_refresh(&lengthened),
            "a 4-prime chain must be admitted even while still named secure_128"
        );

        let mut shortened = SecureConfig::secure_128_deep().into_config();
        shortened.primes.pop();
        assert!(
            !supports_public_refresh(&shortened),
            "a 3-prime chain must be refused even while still named secure_128_deep"
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

        // secure_128 (3 lanes): both public entry points must refuse.
        let refused = SecureConfig::secure_128().into_config();
        let boot = ClockworkBootstrap::new(&refused).expect("bootstrap context");
        let ct = empty_ct(refused.n);
        let bsk = empty_bsk(refused.n);
        let ksk = empty_ksk();

        let circular = boot
            .bootstrap(&ct, &bsk, &ksk)
            .expect_err("secure_128 public refresh must be refused");
        assert!(
            circular.to_string().contains(REFUSAL),
            "secure_128 bootstrap() returned the wrong error: {circular}"
        );

        let non_circular = boot
            .bootstrap_with_ksk(&ct, &bsk, &ksk)
            .expect_err("secure_128 non-circular public refresh must be refused");
        assert!(
            non_circular.to_string().contains(REFUSAL),
            "secure_128 bootstrap_with_ksk() returned the wrong error: {non_circular}"
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
            SecureConfig::hardware_opt(),
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
            SecureConfig::hardware_opt(),
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
            SecureConfig::hardware_opt(),
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
            exact_product_bit_length(&[998244353, 985661441, 754974721]),
            90
        );
        assert!(
            exact_product_bit_length(&[
                998244353,
                985661441,
                754974721,
                469762049,
                167772161,
                595591169,
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
            ("hardware_opt", SecureConfig::hardware_opt()),
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

        let hardware_opt = SecureConfig::hardware_opt();
        assert!(verify_production_safety(&hardware_opt).is_ok());

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
}

