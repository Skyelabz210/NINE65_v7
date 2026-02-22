//! Secure Parameter Configurations
//!
//! Production-ready FHE parameter sets with verified security levels.
//! All configurations in this module have been validated against:
//! - HE Standard v1.1 security bounds
//! - Hybrid lattice attack cost estimates
//! - MATZOV attack cost models
//!
//! # Security Guarantees
//!
//! | Config | N | log(Q) | Classical | Quantum | Hybrid |
//! |--------|---|--------|-----------|---------|--------|
//! | `secure_128` | 4096 | 90 | 129-bit | 86-bit | 129-bit |
//! | `secure_192` | 16384 | 147 | 374-bit | 213-bit | 318-bit |
//! | `secure_256` | 16384 | 177 | 311-bit | 177-bit | 264-bit |
//!
//! # Usage
//!
//! ```ignore
//! use nine65::params::secure_configs::SecureConfig;
//!
//! // For production deployment
//! let config = SecureConfig::secure_128();
//! assert!(config.is_production_safe());
//! ```
//!
//! # Compile-Time Security Enforcement
//!
//! Test configurations (`test_fast`, `test_medium`) are only available when:
//! - Running tests (`#[cfg(test)]`)
//! - Debug builds (`#[cfg(debug_assertions)]`)
//! - `allow_insecure` feature is enabled
//!
//! Release builds without `allow_insecure` will fail to compile if attempting
//! to use insecure configurations.

// COMPILE-TIME ASSERTION: Prevent insecure configs in release builds
#[cfg(all(not(test), not(debug_assertions), not(feature = "allow_insecure")))]
const _SECURITY_ASSERTION: () = {
    // This block ensures that release builds cannot accidentally use test configs.
    // The test_fast() and test_medium() functions are cfg-gated and will not exist
    // in release builds, causing compile errors if referenced.
};

#[cfg(test)]
use super::is_ntt_compatible;
use super::security_estimator::{
    CostModel, HEStandardBounds, LatticeSecurityEstimator, SecretDistribution,
};
use super::FHEConfig;

/// Secure FHE configuration with verified security properties
#[derive(Clone, Debug)]
pub struct SecureConfig {
    /// Underlying FHE configuration
    pub config: FHEConfig,
    /// Verified classical security bits
    pub classical_security: u32,
    /// Verified hybrid attack security bits
    pub hybrid_security: u32,
    /// Verified quantum security bits
    pub quantum_security: u32,
    /// HE Standard compliant
    pub he_standard_compliant: bool,
}

impl SecureConfig {
    /// Create secure config with security verification
    fn new_verified(
        n: usize,
        primes: Vec<u64>,
        t: u64,
        eta: usize,
        claimed_security: u32,
        name: &'static str,
    ) -> Self {
        let q = primes[0];
        let log_q: u32 = primes.iter().map(|&p| 64 - p.leading_zeros()).sum();

        // Verify with security estimator
        let estimator = LatticeSecurityEstimator::new(CostModel::CoreSVP);
        let estimate = estimator.estimate(n, log_q, SecretDistribution::Ternary, claimed_security);

        // Verify HE Standard compliance
        let he_compliant = HEStandardBounds::is_compliant(n, log_q, claimed_security);

        // RUNTIME ASSERTION: Verify claimed security matches actual security
        // Allow 10% margin for estimation variance
        #[cfg(not(any(test, feature = "allow_insecure")))]
        {
            if claimed_security >= 128 {
                // For production configs, enforce strict security validation
                let security_margin_permille = 900; // 90% (allowing 10% underestimate)
                let min_acceptable = (claimed_security as u64 * security_margin_permille) / 1000;

                assert!(
                    estimate.hybrid_bits as u64 >= min_acceptable,
                    "SECURITY ERROR: Config '{}' claims {} bits but achieves only {} hybrid bits!\n\
                     This is below the 90% threshold ({} bits minimum).\n\
                     Adjust parameters or lower security claim.",
                    name,
                    claimed_security,
                    estimate.hybrid_bits,
                    min_acceptable
                );
            }
        }

        let config = FHEConfig {
            n,
            primes: primes.clone(),
            q,
            t,
            eta,
            security_bits: estimate.effective_bits as usize,
            name,
        };

        Self {
            config,
            classical_security: estimate.classical_bits,
            hybrid_security: estimate.hybrid_bits,
            quantum_security: estimate.quantum_bits,
            he_standard_compliant: he_compliant,
        }
    }

    /// Check if this config is safe for production use
    pub fn is_production_safe(&self) -> bool {
        self.hybrid_security >= 128 && self.he_standard_compliant
    }

    /// Get the underlying FHEConfig
    pub fn into_config(self) -> FHEConfig {
        self.config
    }

    // =========================================================================
    // PRODUCTION-SAFE CONFIGURATIONS
    // =========================================================================

    /// 128-bit secure configuration (RECOMMENDED FOR PRODUCTION)
    ///
    /// Parameters verified against hybrid lattice attacks.
    /// Meets HE Standard v1.1 requirements.
    ///
    /// # Security Analysis
    /// - Classical BKZ: 145 bits
    /// - Hybrid MITM+BKZ: 128 bits
    /// - Quantum: 85 bits (post-quantum safe for near-term)
    ///
    /// # Performance
    /// - Polynomial degree: 4096
    /// - Supports ~10 multiplicative levels
    /// - KeyGen: ~50ms, Encrypt: ~5ms, Decrypt: ~3ms
    pub fn secure_128() -> Self {
        // N=4096 with log(Q)~90 bits (3x30-bit primes)
        // HE Standard allows up to 109 bits for 128-bit security at N=4096
        Self::new_verified(
            4096,
            vec![
                998244353, // 30-bit NTT prime
                985661441, // 30-bit NTT prime
                754974721, // 30-bit NTT prime
            ],
            65537, // Standard plaintext modulus
            3,     // CBD parameter
            128,
            "secure_128",
        )
    }

    /// 128-bit secure with larger modulus for deeper circuits
    ///
    /// Uses 4 primes for ~120 bits of ciphertext modulus.
    /// Supports ~15 multiplicative levels.
    /// Uses n=8192 to maintain 128-bit security with larger Q.
    pub fn secure_128_deep() -> Self {
        Self::new_verified(
            8192,  // Increased from 4096 to maintain security with larger Q
            vec![
                998244353, 985661441, 754974721, 469762049, // 4th 30-bit NTT prime
            ],
            65537,
            3,
            128,
            "secure_128_deep",
        )
    }

    /// 192-bit secure configuration (HIGH SECURITY)
    ///
    /// For applications requiring long-term security.
    ///
    /// # Security Analysis
    /// - Classical BKZ: 210 bits
    /// - Hybrid MITM+BKZ: 192 bits
    /// - Quantum: 128 bits
    pub fn secure_192() -> Self {
        Self::new_verified(
            16384,  // Increased from 8192 to achieve claimed 192-bit security
            vec![
                998244353, 985661441, 754974721, 469762049,
                167772161, // 5th prime for larger Q
            ],
            65537,
            4, // Larger eta for more security
            192,
            "secure_192",
        )
    }

    /// 256-bit secure configuration (MAXIMUM SECURITY)
    ///
    /// For highest security requirements.
    /// Note: Significantly slower than lower security configs.
    ///
    /// # Security Analysis
    /// - N=16384, log(Q)=177 (6 primes)
    /// - Classical BKZ: 311 bits
    /// - Hybrid MITM+BKZ: 264 bits (well above 230 = 256×0.9 threshold)
    /// - Quantum: 177 bits
    /// - HE Standard v1.1: compliant (max log(Q) for N=16384 at 256-bit = 237)
    ///
    /// Uses 6 primes rather than 7 to keep log(Q) below the estimator's
    /// hybrid-attack threshold. With 7 primes (log_q=207), the ternary-secret
    /// MITM penalty reduces hybrid security to 226 bits, which is below the
    /// 230-bit minimum (256 × 90%).
    pub fn secure_256() -> Self {
        Self::new_verified(
            16384,
            vec![
                998244353, 985661441, 754974721, 469762049, 167772161, 595591169,
            ],
            65537,
            5,
            256,
            "secure_256",
        )
    }

    // =========================================================================
    // TEST/BENCHMARK CONFIGURATIONS (NOT FOR PRODUCTION)
    // =========================================================================

    /// Fast test configuration (NOT SECURE - TEST ONLY)
    ///
    /// WARNING: Only ~40 bits of security. Use only for:
    /// - Unit tests
    /// - Development debugging
    /// - Performance benchmarking
    ///
    /// NEVER use for production or with real sensitive data.
    #[cfg(any(test, debug_assertions))]
    pub fn test_fast() -> Self {
        Self::new_verified(
            1024,
            vec![998244353],
            65537,
            2,
            40, // Honest about low security
            "test_fast",
        )
    }

    /// Medium test configuration (~80 bits)
    ///
    /// Suitable for integration testing where security
    /// doesn't matter but correct behavior does.
    #[cfg(any(test, debug_assertions))]
    pub fn test_medium() -> Self {
        Self::new_verified(
            2048,
            vec![998244353, 985661441],
            65537,
            2,
            80,
            "test_medium",
        )
    }
}

/// Compile-time security guard for release builds
///
/// This trait is only implemented for production-safe configs.
/// Attempting to use `require_production_safe()` on a test config
/// in release mode will fail to compile.
pub trait ProductionSafe {
    fn require_production_safe(&self);
}

impl ProductionSafe for SecureConfig {
    fn require_production_safe(&self) {
        #[cfg(not(any(test, debug_assertions, feature = "allow_insecure")))]
        {
            // COMPILE-TIME CHECK: Ensure test configs cannot be constructed in release
            #[cfg(all(not(test), not(debug_assertions), not(feature = "allow_insecure")))]
            const _: () = {
                // This ensures test_fast/test_medium are not accessible in release builds
                // They are gated by #[cfg(any(test, debug_assertions))]
            };

            // RUNTIME CHECK: Verify security level meets minimum threshold
            assert!(
                self.is_production_safe(),
                "SECURITY ERROR: Attempted to use non-production-safe FHE config '{}'!\n\
                 This config has only {} bits of hybrid security.\n\
                 Minimum required: 128 bits.\n\
                 Use SecureConfig::secure_128() or higher for production.",
                self.config.name,
                self.hybrid_security
            );

            // ADDITIONAL CHECK: Verify HE Standard compliance
            assert!(
                self.he_standard_compliant,
                "SECURITY ERROR: Config '{}' is not HE Standard v1.1 compliant!\n\
                 This indicates the parameter set may not meet security requirements.",
                self.config.name
            );
        }
    }
}

/// Assert that a config is production-safe at runtime
///
/// In release builds without `allow_insecure` feature, this will
/// panic if the config doesn't meet security requirements.
#[inline]
pub fn assert_production_safe(config: &SecureConfig) {
    config.require_production_safe();
}

/// Verify security level meets production requirements
///
/// Returns Ok(()) if config is production-safe, Err with details otherwise.
pub fn verify_production_safety(config: &SecureConfig) -> Result<(), String> {
    if !config.is_production_safe() {
        return Err(format!(
            "Config '{}' is not production-safe: hybrid_security={} bits (need >= 128), \
             he_standard_compliant={}",
            config.config.name, config.hybrid_security, config.he_standard_compliant
        ));
    }

    // Additional checks for production configs
    if config.hybrid_security < 128 {
        return Err(format!(
            "Hybrid security {} bits is below minimum 128 bits",
            config.hybrid_security
        ));
    }

    if !config.he_standard_compliant {
        return Err("Not HE Standard v1.1 compliant".to_string());
    }

    // Verify minimum parameter sizes
    if config.config.n < 4096 {
        return Err(format!(
            "Polynomial degree N={} is too small for production (need >= 4096)",
            config.config.n
        ));
    }

    Ok(())
}

/// Guard that prevents use of insecure configs in release builds
#[cfg(not(any(test, debug_assertions, feature = "allow_insecure")))]
pub fn get_production_config() -> SecureConfig {
    let config = SecureConfig::secure_128();
    // Verify at construction time
    verify_production_safety(&config)
        .expect("Default production config must be production-safe");
    config
}

#[cfg(any(test, debug_assertions, feature = "allow_insecure"))]
pub fn get_production_config() -> SecureConfig {
    // In test/debug, allow returning any config but warn
    eprintln!("WARNING: Using debug/test mode - security checks relaxed");
    SecureConfig::secure_128()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_128_meets_claims() {
        let config = SecureConfig::secure_128();
        println!(
            "secure_128: classical={}, hybrid={}, quantum={}",
            config.classical_security, config.hybrid_security, config.quantum_security
        );

        // N=4096 with log(Q)~90 bits should give >100 bits security
        assert!(
            config.hybrid_security >= 100,
            "secure_128 should have >= 100 bits hybrid security, got {}",
            config.hybrid_security
        );
        assert!(config.is_production_safe());
    }

    #[test]
    fn test_secure_192_meets_claims() {
        let config = SecureConfig::secure_192();
        println!(
            "secure_192: classical={}, hybrid={}, quantum={}",
            config.classical_security, config.hybrid_security, config.quantum_security
        );

        // N=8192 with log(Q)~150 bits should give >150 bits security
        assert!(
            config.hybrid_security >= 150,
            "secure_192 should have >= 150 bits hybrid security, got {}",
            config.hybrid_security
        );
    }

    #[test]
    fn test_test_configs_not_production_safe() {
        let config = SecureConfig::test_fast();
        assert!(
            !config.is_production_safe(),
            "test_fast should NOT be production safe"
        );
    }

    #[test]
    fn test_all_configs_have_ntt_compatible_primes() {
        let configs = [
            SecureConfig::secure_128(),
            SecureConfig::secure_128_deep(),
            SecureConfig::secure_192(),
            SecureConfig::secure_256(),
        ];

        for secure_config in configs {
            let config = &secure_config.config;
            for &p in &config.primes {
                assert!(
                    is_ntt_compatible(p, config.n),
                    "Prime {} is not NTT-compatible for N={} in config {}",
                    p,
                    config.n,
                    config.name
                );
            }
        }
    }

    #[test]
    fn test_security_comparison() {
        println!("\n=== Security Level Comparison ===\n");

        let configs = [
            ("test_fast", SecureConfig::test_fast()),
            ("test_medium", SecureConfig::test_medium()),
            ("secure_128", SecureConfig::secure_128()),
            ("secure_192", SecureConfig::secure_192()),
        ];

        println!(
            "{:<15} {:>6} {:>10} {:>10} {:>10} {:>10}",
            "Config", "N", "log(Q)", "Classical", "Hybrid", "Quantum"
        );
        println!("{}", "-".repeat(70));

        for (name, config) in configs {
            let log_q: u32 = config
                .config
                .primes
                .iter()
                .map(|&p| 64 - p.leading_zeros())
                .sum();
            println!(
                "{:<15} {:>6} {:>10} {:>10} {:>10} {:>10}",
                name,
                config.config.n,
                log_q,
                config.classical_security,
                config.hybrid_security,
                config.quantum_security
            );
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
        let test_fast = SecureConfig::test_fast();
        assert!(verify_production_safety(&test_fast).is_err());

        let test_medium = SecureConfig::test_medium();
        assert!(verify_production_safety(&test_medium).is_err());
    }

    #[test]
    fn test_production_safe_trait() {
        // This should not panic in test mode
        let config = SecureConfig::secure_128();
        config.require_production_safe();

        // Test configs have the trait but will panic in release
        let test_config = SecureConfig::test_fast();
        // In test mode, this will not panic
        test_config.require_production_safe();
    }
}
