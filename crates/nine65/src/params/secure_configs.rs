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
//! | `secure_128` | 8192 | 3 NTT primes (~90 bits) | candidate 128-bit profile |
//! | `secure_128_deep` | 8192 | 4 NTT primes (~120 bits) | candidate 128-bit profile |
//! | `secure_192` | 16384 | 5 NTT primes (~147 bits) | candidate 192-bit profile |
//! | `secure_256` | 16384 | 6 NTT primes (~177 bits) | candidate 256-bit profile |

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

#[derive(Clone, Debug)]
pub struct SecureConfig {
    pub config: FHEConfig,
    pub claimed_security: u32,
    pub classical_security: u32,
    pub hybrid_security: u32,
    pub quantum_security: u32,
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
        validate_class_f_chain(n, &primes);
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

        assert!(
            estimate.effective_bits >= claimed_security,
            "SECURITY ERROR: config '{}' claims {} bits but screens at {} bits.\n{}",
            name,
            claimed_security,
            estimate.effective_bits,
            estimate.analysis,
        );
        if claimed_security >= 128 {
            assert!(
                he_standard_compliant,
                "SECURITY ERROR: config '{}' exceeds the HE Standard bound",
                name
            );
        }

        let config = FHEConfig {
            n,
            primes,
            q,
            t,
            eta,
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

    pub fn is_production_safe(&self) -> bool {
        self.claimed_security >= 128
            && self.config.n >= 8192
            && self.hybrid_security >= self.claimed_security
            && self.he_standard_compliant
    }

    pub fn into_config(self) -> FHEConfig {
        self.config
    }

    pub fn secure_128() -> Self {
        Self::new_verified(
            8192,
            vec![998_244_353, 985_661_441, 754_974_721],
            65_537,
            3,
            128,
            "secure_128",
        )
    }

    pub fn secure_128_deep() -> Self {
        Self::new_verified(
            8192,
            vec![998_244_353, 985_661_441, 754_974_721, 469_762_049],
            65_537,
            3,
            128,
            "secure_128_deep",
        )
    }

    pub fn secure_192() -> Self {
        Self::new_verified(
            16_384,
            vec![
                998_244_353,
                985_661_441,
                754_974_721,
                469_762_049,
                167_772_161,
            ],
            65_537,
            4,
            192,
            "secure_192",
        )
    }

    pub fn secure_256() -> Self {
        Self::new_verified(
            16_384,
            vec![
                998_244_353,
                985_661_441,
                754_974_721,
                469_762_049,
                167_772_161,
                595_591_169,
            ],
            65_537,
            5,
            256,
            "secure_256",
        )
    }

    pub fn hardware_opt() -> Self {
        Self::new_verified(
            8192,
            vec![998_244_353, 985_661_441, 754_974_721],
            65_537,
            3,
            128,
            "hardware_opt",
        )
    }

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

pub fn assert_production_safe_fhe_config(config: &FHEConfig) {
    if cfg!(any(test, debug_assertions, feature = "allow_insecure")) {
        return;
    }

    validate_class_f_chain(config.n, &config.primes);
    assert!(config.t >= 2, "plaintext modulus must be at least two");
    assert!(
        config.primes.iter().all(|&prime| config.t < prime),
        "plaintext modulus must be smaller than every RNS prime"
    );

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

pub fn verify_production_safety(config: &SecureConfig) -> Result<(), String> {
    if config.claimed_security < 128 {
        return Err(format!(
            "claim={} bits is below the production minimum of 128 bits",
            config.claimed_security
        ));
    }
    if config.config.n < 8192 {
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

    fn production_configs() -> [SecureConfig; 5] {
        [
            SecureConfig::secure_128(),
            SecureConfig::secure_128_deep(),
            SecureConfig::secure_192(),
            SecureConfig::secure_256(),
            SecureConfig::hardware_opt(),
        ]
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
        for config in production_configs() {
            assert!(config.is_production_safe(), "{}", config.config.name);
            assert!(config.hybrid_security >= config.claimed_security);
            assert!(config.he_standard_compliant);
        }
    }

    #[test]
    fn every_production_lane_is_prime_distinct_coprime_and_ntt_compatible() {
        for config in production_configs() {
            for (index, &prime) in config.config.primes.iter().enumerate() {
                assert!(is_prime(prime), "{prime} is composite");
                assert!(
                    is_ntt_compatible(prime, config.config.n),
                    "{prime} is not NTT-compatible for N={} ({})",
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
    fn class_f_validator_rejects_composite_lane() {
        let result = std::panic::catch_unwind(|| validate_class_f_chain(2, &[65]));
        assert!(result.is_err());
    }

    #[test]
    fn class_f_validator_rejects_duplicate_lane() {
        let result = std::panic::catch_unwind(|| {
            validate_class_f_chain(1024, &[998_244_353, 998_244_353]);
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_configs_construct_but_are_not_production_safe() {
        let fast = SecureConfig::test_fast_insecure();
        let medium = SecureConfig::test_medium_insecure();
        assert!(!fast.is_production_safe());
        assert!(!medium.is_production_safe());
        assert!(verify_production_safety(&fast).is_err());
        assert!(verify_production_safety(&medium).is_err());
    }

    #[test]
    fn production_safety_returns_diagnostics() {
        assert!(verify_production_safety(&SecureConfig::secure_128()).is_ok());
        assert!(verify_production_safety(&SecureConfig::secure_192()).is_ok());
        assert!(verify_production_safety(&SecureConfig::secure_256()).is_ok());
        assert!(verify_production_safety(&SecureConfig::hardware_opt()).is_ok());
    }

    #[test]
    fn exact_product_bit_length_matches_known_chains() {
        assert_eq!(
            exact_product_bit_length(&[998_244_353, 985_661_441, 754_974_721]),
            90
        );
        assert!(
            exact_product_bit_length(&[
                998_244_353,
                985_661_441,
                754_974_721,
                469_762_049,
                167_772_161,
                595_591_169,
            ]) > 128
        );
    }
}
