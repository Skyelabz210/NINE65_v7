//! Audited production parameter configurations for NINE65.
//!
//! All arithmetic in this module is exact integer arithmetic. The internal
//! security estimator is a deterministic screening gate, not an independent
//! lattice-security certificate. Every release that carries a named security
//! claim must archive an external lattice-estimator result for the exact tuple
//! `(N, Q, t, secret distribution, error distribution)`.
//!
//! | Config | N | RNS chain | Claim |
//! |--------|---|-----------|-------|
//! | `secure_128` | 8192 | 3 NTT primes (~90 bits) | 128 bits |
//! | `secure_128_deep` | 8192 | 4 NTT primes (~120 bits) | 128 bits |
//! | `secure_192` | 16384 | 5 NTT primes (~147 bits) | 192 bits |
//! | `secure_256` | 16384 | 6 NTT primes (~177 bits) | 256 bits |

use super::security_estimator::{
    CostModel, HEStandardBounds, LatticeSecurityEstimator, SecretDistribution,
};
use super::{gcd, is_ntt_compatible, is_prime, FHEConfig};

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
        assert!(
            is_insecure_tier || claimed_security < 128 || n >= 8192,
            "SECURITY ERROR: config '{}' claims {}-bit security but dimension N={} is below the 8192 floor",
            name, claimed_security, n
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

    /// Audited 128-bit production candidate.
    ///
    /// N was raised from 4096 to 8192 after the July 2026 independent audit
    /// assessed the former tuple below its 128-bit claim. The RNS chain remains
    /// three NTT-friendly primes so the arithmetic/noise capacity is unchanged;
    /// this change increases the lattice dimension and security margin.
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

