//! Parameter Validation Module
//!
//! Ensures FHE parameters are safe from the Hidden Orbital Problem
//! and comply with HE Standard security requirements.
//!
//! CRITICAL: These checks MUST pass before any FHE operations.

use crate::arithmetic::k_elimination::KElimination;

/// Result of parameter validation
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Overall pass/fail
    pub valid: bool,
    /// Orbital boundary check
    pub orbital_safe: bool,
    /// HE Standard compliance
    pub he_standard_compliant: bool,
    /// Security level (estimated bits)
    pub estimated_security_bits: u32,
    /// Maximum supported N
    pub max_safe_n: usize,
    /// Detailed messages
    pub messages: Vec<String>,
}

/// Parameter validator
pub struct ParameterValidator {
    /// K-Elimination configuration
    ke_capacity_bits: u32,
    /// K-Elimination total capacity
    ke_total_capacity: u128,
}

impl ParameterValidator {
    /// Create validator with current K-Elimination configuration
    pub fn new() -> Self {
        let ke = KElimination::for_fhe(0);
        let total_capacity = ke.alpha_cap.saturating_mul(ke.beta_cap);
        let capacity_bits = 128 - total_capacity.leading_zeros();

        Self {
            ke_capacity_bits: capacity_bits,
            ke_total_capacity: total_capacity,
        }
    }

    /// Validate FHE parameters
    pub fn validate(&self, n: usize, q: u64, t: u64) -> ValidationResult {
        let mut messages = Vec::new();

        // 1. Orbital Boundary Check
        let max_tensor_value = self.max_tensor_intermediate(q, n);
        let tensor_bits = 128 - max_tensor_value.leading_zeros();
        let orbital_safe = max_tensor_value < self.ke_total_capacity;

        if orbital_safe {
            let margin = if max_tensor_value == 0 {
                u128::MAX
            } else {
                self.ke_total_capacity / max_tensor_value
            };
            messages.push(format!(
                "✓ Orbital: {} bits required, {} bits available (margin: {}×)",
                tensor_bits, self.ke_capacity_bits, margin
            ));
        } else {
            messages.push(format!(
                "✗ ORBITAL VIOLATION: {} bits required, only {} bits available!",
                tensor_bits, self.ke_capacity_bits
            ));
            messages.push("  → Reduce q or N, or increase K-Elimination moduli".to_string());
        }

        // 2. HE Standard Compliance
        let log_q = 64 - q.leading_zeros();
        let max_log_q = self.he_standard_max_log_q(n);
        let he_standard_compliant = log_q <= max_log_q;

        if he_standard_compliant {
            messages.push(format!(
                "✓ HE Standard: log(q)={} ≤ max {} for N={}",
                log_q, max_log_q, n
            ));
        } else {
            messages.push(format!(
                "⚠ HE Standard: log(q)={} > max {} for N={} (128-bit security not guaranteed)",
                log_q, max_log_q, n
            ));
        }

        // 3. Security Estimate
        let estimated_security_bits = self.estimate_security_bits(n, log_q);
        messages.push(format!(
            "  Security estimate: {} bits (rough, use LWE estimator for precise)",
            estimated_security_bits
        ));

        // 4. Noise Budget Check
        let delta = q / t;
        let noise_bits = 64 - delta.leading_zeros();
        if noise_bits < 10 {
            messages.push(format!(
                "⚠ Noise budget: Δ={} (~{} bits) - very tight for deep circuits",
                delta, noise_bits
            ));
        } else {
            messages.push(format!(
                "✓ Noise budget: Δ={} (~{} bits)",
                delta, noise_bits
            ));
        }

        // 5. Calculate max safe N
        let max_safe_n = self.max_safe_n_for_q(q);

        let valid = orbital_safe; // Orbital safety is critical

        ValidationResult {
            valid,
            orbital_safe,
            he_standard_compliant,
            estimated_security_bits,
            max_safe_n,
            messages,
        }
    }

    /// Calculate maximum tensor product intermediate value
    fn max_tensor_intermediate(&self, q: u64, n: usize) -> u128 {
        // After tensor product of two N-coefficient polynomials:
        // Each coefficient can be up to N * q^2 in the worst case
        let q128 = q as u128;
        let n128 = n as u128;
        n128.saturating_mul(q128).saturating_mul(q128)
    }

    /// HE Standard maximum log(q) for given N (128-bit classical security)
    fn he_standard_max_log_q(&self, n: usize) -> u32 {
        match n {
            1024 => 27,
            2048 => 54,
            4096 => 109,
            8192 => 218,
            16384 => 438,
            32768 => 881,
            _ => {
                // Rough interpolation
                let log_n = 64 - (n as u64).leading_zeros();
                (log_n - 10) * 27
            }
        }
    }

    /// Estimate security bits (rough - use LWE estimator for precise)
    fn estimate_security_bits(&self, n: usize, log_q: u32) -> u32 {
        let ratio_permille = ((n as u64) * 1000) / (log_q as u64);

        if ratio_permille > 30_000 {
            192
        } else if ratio_permille > 20_000 {
            128
        } else if ratio_permille > 15_000 {
            96
        } else if ratio_permille > 10_000 {
            64
        } else {
            32
        }
    }

    /// Maximum safe N for given q
    fn max_safe_n_for_q(&self, q: u64) -> usize {
        // Solve: n * q^2 < ke_total_capacity
        // n < ke_total_capacity / q^2
        let q128 = q as u128;
        let q_sq = q128.saturating_mul(q128);
        let max_n = if q_sq == 0 {
            0
        } else {
            self.ke_total_capacity / q_sq
        };

        // Round down to power of 2
        let log_max = 128 - max_n.leading_zeros();
        if log_max > 1 {
            1usize << (log_max - 1)
        } else {
            1
        }
    }
}

impl Default for ParameterValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function for quick validation
pub fn validate_params(n: usize, q: u64, t: u64) -> ValidationResult {
    ParameterValidator::new().validate(n, q, t)
}

/// Assert parameters are valid (panics if not)
pub fn assert_params_valid(n: usize, q: u64, t: u64) {
    let result = validate_params(n, q, t);

    if !result.valid {
        panic!(
            "INVALID FHE PARAMETERS!\n\
             N={}, q={}, t={}\n\
             {}\n\
             This would cause the Hidden Orbital Problem.",
            n,
            q,
            t,
            result.messages.join("\n")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_params_valid() {
        let result = validate_params(1024, 998244353, 500000);
        assert!(result.orbital_safe, "Standard params should be safe");
        println!("{:#?}", result);
    }

    #[test]
    fn test_large_n_valid() {
        let result = validate_params(4096, 998244353, 500000);
        assert!(result.orbital_safe, "N=4096 should be safe");
    }

    #[test]
    fn test_large_q_fails() {
        // This should fail - 62-bit q is too large
        let result = validate_params(1024, 4611686018427387903, 500000);
        assert!(!result.orbital_safe, "Large q should fail orbital check");
    }

    #[test]
    fn test_max_safe_n() {
        let validator = ParameterValidator::new();
        let max_n = validator.max_safe_n_for_q(998244353);
        println!("Max safe N for q=998244353: {}", max_n);
        assert!(max_n >= 4096, "Should support at least N=4096");
    }

    #[test]
    fn test_he_standard_compliance() {
        // N=1024 with q=30-bit exceeds HE Standard
        let result = validate_params(1024, 998244353, 500000);
        assert!(
            !result.he_standard_compliant,
            "N=1024 q=30bit should exceed HE Standard"
        );

        // N=2048 with q=30-bit is compliant
        let result = validate_params(2048, 998244353, 500000);
        assert!(
            result.he_standard_compliant,
            "N=2048 q=30bit should be compliant"
        );
    }

    #[test]
    #[should_panic(expected = "INVALID FHE PARAMETERS")]
    fn test_assert_invalid_panics() {
        // This should panic
        assert_params_valid(1024, u64::MAX, 500000);
    }
}
