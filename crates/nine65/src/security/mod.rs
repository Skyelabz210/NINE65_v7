//! Security Module
//!
//! Provides security-related functionality:
//! - LWE-based security estimates for QMNF FHE parameters
//! - Secret data marker traits for constant-time enforcement
//! - Constant-time verification tests
//!
//! Based on HomomorphicEncryption.org Security Standard v1.1 tables.
//!
//! For precise estimates, run the external LWE Estimator:
//! `sage -python scripts/lwe_estimate.py`

pub mod secret_data;

pub use secret_data::{SecretData, SecretKeyPath, SecretPoly, SecretScalar};

#[cfg(test)]
pub mod ct_verification;

#[cfg(feature = "clockwork")]
pub mod gro_gate;
#[cfg(feature = "clockwork")]
pub use gro_gate::TimingGate;

#[cfg(feature = "clockwork")]
pub mod key_manager;
#[cfg(feature = "clockwork")]
pub use key_manager::KeyManager;

#[cfg(feature = "clockwork")]
pub mod integrity;
#[cfg(feature = "clockwork")]
pub use integrity::{compute_limb_checksum, verify_limb_checksum};

use crate::params::FHEConfig;

/// LWE parameters for security estimation
#[derive(Debug, Clone)]
pub struct LWEParams {
    /// Ring dimension
    pub n: usize,
    /// Log base-2 of modulus
    pub log_q: u32,
    /// Error distribution parameter σ × 1000 (3200 = σ=3.2)
    pub sigma_millibits: u32,
    /// Error distribution type
    pub error_type: ErrorDistribution,
}

/// Type of error distribution
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorDistribution {
    /// Discrete Gaussian with standard deviation σ
    DiscreteGaussian,
    /// Centered Binomial Distribution with parameter η
    CBD,
    /// Ternary uniform distribution
    Ternary,
}

/// Security estimate result
#[derive(Debug, Clone)]
pub struct SecurityEstimate {
    /// Classical security level in bits
    pub classical_bits: u32,
    /// Quantum security level in bits (rough estimate)
    pub quantum_bits: u32,
    /// Best known attack
    pub best_attack: String,
    /// Confidence level of estimate
    pub confidence: ConfidenceLevel,
    /// N/log(q) ratio × 1000 (key security indicator, permille)
    pub ratio_permille: u32,
}

/// Confidence level of security estimate
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfidenceLevel {
    /// Quick heuristic estimate
    Rough,
    /// Based on HE Standard tables
    Standard,
    /// Full lattice-estimator run
    Precise,
}

impl LWEParams {
    /// Extract LWE parameters from FHE config
    pub fn from_config(config: &FHEConfig) -> Self {
        let log_q = 64 - config.q.leading_zeros();

        // CBD(η) has σ ≈ √(η/2), stored as millibits (× 1000)
        // σ_millibits = √(η/2) × 1000 = √(η × 500_000)
        let sigma_millibits =
            crate::arithmetic::integer_math::integer_sqrt(config.eta as u64 * 500_000) as u32;

        Self {
            n: config.n,
            log_q,
            sigma_millibits,
            error_type: ErrorDistribution::CBD,
        }
    }

    /// Create with custom parameters (sigma_millibits = σ × 1000)
    pub fn new(n: usize, log_q: u32, sigma_millibits: u32) -> Self {
        Self {
            n,
            log_q,
            sigma_millibits,
            error_type: ErrorDistribution::DiscreteGaussian,
        }
    }

    /// Get N/log(q) ratio × 1000 (key security indicator, permille)
    pub fn ratio_permille(&self) -> u32 {
        ((self.n as u64 * 1000) / self.log_q as u64) as u32
    }

    /// Estimate security using HE Standard v1.1 Table 3
    ///
    /// This provides conservative estimates based on the published
    /// Homomorphic Encryption Security Standard.
    ///
    /// # Reference
    /// Martin Albrecht et al., "Homomorphic Encryption Standard v1.1"
    /// HomomorphicEncryption.org, 2018
    pub fn he_standard_estimate(&self) -> SecurityEstimate {
        let ratio_pm = self.ratio_permille();

        // HE Standard Table 3 thresholds (conservative)
        // These are N/log(q) ratios × 1000 for different security levels
        let (classical_bits, best_attack) = if ratio_pm > 50_000 {
            (256, "BKZ/sieving theoretical limit")
        } else if ratio_pm > 38_000 {
            (192, "BKZ with progressive sieving")
        } else if ratio_pm > 28_000 {
            (128, "BKZ with lattice sieving")
        } else if ratio_pm > 18_000 {
            (96, "BKZ with enumeration")
        } else if ratio_pm > 12_000 {
            (80, "Hybrid lattice attack")
        } else {
            (64, "Direct lattice attack")
        };

        // Quantum security roughly 2/3 of classical for lattice problems
        // (Grover doesn't help much for lattice)
        let quantum_bits = (classical_bits * 2) / 3;

        SecurityEstimate {
            classical_bits,
            quantum_bits,
            best_attack: best_attack.to_string(),
            confidence: ConfidenceLevel::Standard,
            ratio_permille: ratio_pm,
        }
    }

    /// Quick heuristic estimate
    ///
    /// Faster but less accurate than HE Standard lookup.
    pub fn quick_estimate(&self) -> SecurityEstimate {
        // Rule of thumb: security ≈ 2.6 × n / log(q)
        // Integer: raw_estimate_x1000 = 2600 × n / log(q)
        let raw_estimate_x1000 = (self.n as u64 * 2_600) / self.log_q as u64;

        // Round to standard levels (thresholds × 1000)
        let classical_bits = if raw_estimate_x1000 >= 240_000 {
            256
        } else if raw_estimate_x1000 >= 180_000 {
            192
        } else if raw_estimate_x1000 >= 120_000 {
            128
        } else if raw_estimate_x1000 >= 90_000 {
            96
        } else if raw_estimate_x1000 >= 75_000 {
            80
        } else {
            64
        };

        let quantum_bits = (classical_bits * 2) / 3;

        SecurityEstimate {
            classical_bits,
            quantum_bits,
            best_attack: "Heuristic estimate".to_string(),
            confidence: ConfidenceLevel::Rough,
            ratio_permille: self.ratio_permille(),
        }
    }

    /// Check if parameters meet HE Standard for target security
    pub fn meets_he_standard(&self, target_bits: u32) -> bool {
        // HE Standard Table 3 minimum N/log(q) ratios (× 1000 = permille)
        let required_ratio_permille: u32 = match target_bits {
            256 => 50_000,
            192 => 38_000,
            128 => 28_000,
            96 => 18_000,
            80 => 12_000,
            _ => return false,
        };

        self.ratio_permille() >= required_ratio_permille
    }

    /// Get maximum log(q) for given N at target security
    pub fn max_log_q_for_security(n: usize, target_bits: u32) -> u32 {
        let required_ratio_permille: u32 = match target_bits {
            256 => 50_000,
            192 => 38_000,
            128 => 28_000,
            96 => 18_000,
            80 => 12_000,
            _ => 10_000,
        };

        ((n as u64 * 1000) / required_ratio_permille as u64) as u32
    }

    /// Generate security documentation
    pub fn security_rationale(&self, config_name: &str) -> String {
        let estimate = self.he_standard_estimate();
        let ratio_pm = self.ratio_permille();

        format!(
            r#"Security Rationale for '{}'
================================

Parameters:
  Ring dimension N: {}
  Modulus bits log(q): {}
  Error parameter σ: {}.{:03}
  Error distribution: {:?}

Security Analysis:
  N/log(q) ratio: {}.{:03}

  HE Standard Estimate:
    Classical security: {} bits
    Quantum security: ~{} bits
    Best known attack: {}
    Confidence: {:?}

Verification:
  □ Run `sage -python scripts/lwe_estimate.py` for precise estimate
  □ Compare against HE Standard Table 3
  □ Verify σ ≥ 3.2 for security proofs

References:
  [1] HomomorphicEncryption.org Security Standard v1.1 (2018)
  [2] Albrecht et al., "On the concrete hardness of Learning with Errors"
"#,
            config_name,
            self.n,
            self.log_q,
            self.sigma_millibits / 1000,
            self.sigma_millibits % 1000,
            self.error_type,
            ratio_pm / 1000,
            ratio_pm % 1000,
            estimate.classical_bits,
            estimate.quantum_bits,
            estimate.best_attack,
            estimate.confidence,
        )
    }
}

impl SecurityEstimate {
    /// Check if meets minimum security level
    pub fn meets_minimum(&self, min_classical: u32, min_quantum: u32) -> bool {
        self.classical_bits >= min_classical && self.quantum_bits >= min_quantum
    }

    /// Human-readable security level name
    pub fn level_name(&self) -> &'static str {
        match self.classical_bits {
            256.. => "Ultra-High (256-bit)",
            192..=255 => "Very High (192-bit)",
            128..=191 => "High (128-bit)",
            96..=127 => "Medium (96-bit)",
            80..=95 => "Standard (80-bit)",
            _ => "Low",
        }
    }
}

impl std::fmt::Display for SecurityEstimate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {} bits classical, ~{} bits quantum (ratio: {}.{})",
            self.level_name(),
            self.classical_bits,
            self.quantum_bits,
            self.ratio_permille / 1000,
            self.ratio_permille % 1000
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::SecureConfig;

    #[test]
    fn test_lwe_params_from_config() {
        let config = SecureConfig::secure_128().into_config();
        let params = LWEParams::from_config(&config);

        assert_eq!(params.n, config.n); // must mirror the config, not a pinned N
        assert_eq!(params.n, 8192); // SecureConfig::secure_128() uses N=8192
        assert!(params.log_q > 0);
        assert!(params.sigma_millibits > 0);

        println!(
            "Secure 128 config: N={}, log(q)={}, σ={}.{:03}",
            params.n,
            params.log_q,
            params.sigma_millibits / 1000,
            params.sigma_millibits % 1000
        );
    }

    #[test]
    fn test_he_standard_estimate() {
        let config = SecureConfig::secure_128().into_config();
        let params = LWEParams::from_config(&config);
        let estimate = params.he_standard_estimate();

        println!("HE Standard 128 estimate: {}", estimate);
        println!("{}", params.security_rationale("secure_128"));

        assert!(
            estimate.classical_bits >= 128,
            "Secure 128 config should provide 128-bit security"
        );
        assert!(
            params.meets_he_standard(128),
            "Should meet HE Standard for 128-bit"
        );
    }

    #[test]
    fn test_security_levels() {
        let test_cases = [
            (1024, 30, 80),   // Light config
            (2048, 30, 128),  // HE Standard 128
            (2048, 54, 128),  // HE Standard max q
            (4096, 60, 128),  // Standard BFV
            (8192, 218, 128), // Deep circuits
        ];

        for (n, log_q, expected_min) in test_cases {
            let params = LWEParams::new(n, log_q, 3200); // sigma=3.2 -> 3200 millibits
            let estimate = params.he_standard_estimate();

            println!(
                "N={}, log(q)={}: {} bits (ratio {}.{:03})",
                n,
                log_q,
                estimate.classical_bits,
                estimate.ratio_permille / 1000,
                estimate.ratio_permille % 1000
            );

            assert!(
                estimate.classical_bits >= expected_min,
                "N={}, log(q)={} should have >= {} bits security",
                n,
                log_q,
                expected_min
            );
        }
    }

    #[test]
    fn test_max_log_q() {
        let n = 2048;
        let max_128 = LWEParams::max_log_q_for_security(n, 128);
        let max_192 = LWEParams::max_log_q_for_security(n, 192);

        println!(
            "N={}: max log(q) for 128-bit = {}, for 192-bit = {}",
            n, max_128, max_192
        );

        assert!(max_128 > max_192, "Higher security requires smaller q");
        assert!(max_128 >= 54, "Should allow at least 54-bit q for 128-bit");
    }

    #[test]
    fn test_all_configs_security() {
        let configs = [
            ("secure_128", SecureConfig::secure_128().into_config()),
            ("secure_192", SecureConfig::secure_192().into_config()),
            ("standard_128", FHEConfig::standard_128_insecure()), // Keep this one for now, it's not deprecated
            ("high_192", FHEConfig::high_192_insecure()), // Keep this one for now, it's not deprecated
        ];

        for (name, config) in configs {
            let params = LWEParams::from_config(&config);
            let estimate = params.he_standard_estimate();

            println!(
                "{}: {} (N={}, log(q)={})",
                name, estimate, config.n, params.log_q
            );

            // All configs should have at least 80-bit security
            assert!(
                estimate.classical_bits >= 80,
                "{} has insufficient security",
                name
            );
        }
    }
}
