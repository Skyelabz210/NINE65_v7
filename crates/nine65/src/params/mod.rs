//! FHE Configuration - Parameter Sets for Various Security Levels
//!
//! # Security Warning
//!
//! **IMPORTANT**: Many legacy parameter sets have lower security than originally
//! claimed due to hybrid lattice attacks. Use the `secure_configs` module for
//! production deployment.
//!
//! ## Security Levels (Verified)
//!
//! | Config | N | Claimed | Actual | Status |
//! |--------|---|---------|--------|--------|
//! | `light` | 1024 | 80-bit | **36-bit** | TEST ONLY |
//! | `he_standard_128` | 2048 | 128-bit | **56-bit** | TEST ONLY |
//! | `standard_128` | 4096 | 128-bit | 96-bit | MARGINAL |
//! | `high_192` | 8192 | 192-bit | 176-bit | SECURE |
//! | `SecureConfig::secure_128()` | 4096 | 128-bit | **128-bit** | PRODUCTION |
//! | `SecureConfig::secure_192()` | 8192 | 192-bit | **192-bit** | PRODUCTION |
//!
//! ## For Production Use
//!
//! ```ignore
//! use nine65::params::secure_configs::SecureConfig;
//!
//! // This is verified to meet 128-bit security against hybrid attacks
//! let config = SecureConfig::secure_128();
//! ```
//!
//! ## Legacy Configs (Testing Only)
//!
//! The `light_insecure()`, `he_standard_128_insecure()`, etc. functions are retained for
//! backward compatibility and testing but should NOT be used in production.

pub mod primes;
pub mod production;
pub mod secure_configs;
pub mod security_estimator;
pub mod validation;

#[cfg(feature = "exact_rational")]
pub mod exact_params;
#[cfg(feature = "exact_rational")]
pub use exact_params::ExactDelta;

pub use primes::*;
pub use secure_configs::{
    assert_production_safe, assert_production_safe_fhe_config, ProductionSafe, SecureConfig,
};
pub use security_estimator::{
    CostModel, HEStandardBounds, LatticeSecurityEstimator, SecretDistribution, SecurityEstimate,
};
pub use validation::{assert_params_valid, validate_params, ParameterValidator, ValidationResult};

/// FHE Configuration Parameters
#[derive(Clone, Debug)]
pub struct FHEConfig {
    /// Polynomial degree (power of 2)
    pub n: usize,
    /// Ciphertext modulus primes
    pub primes: Vec<u64>,
    /// Primary ciphertext modulus (product or first prime)
    pub q: u64,
    /// Plaintext modulus
    pub t: u64,
    /// Noise parameter (CBD eta)
    pub eta: usize,
    /// Security level in bits
    pub security_bits: usize,
    /// Name of this parameter set
    pub name: &'static str,
}

impl FHEConfig {
    /// Light configuration for testing (~36-bit actual security)
    ///
    /// # Security Warning
    ///
    /// **DO NOT USE IN PRODUCTION**
    ///
    /// This config has only ~36 bits of security against hybrid lattice attacks.
    /// Use `SecureConfig::secure_128()` for production.
    ///
    /// # Security Warning
    /// This configuration provides only ~36-bit security and is NOT safe for production.
    /// Use ONLY for unit tests, benchmarks, or development debugging.
    ///
    /// # Feature Gate
    /// This function is only available when the `allow_insecure` feature is enabled,
    /// or in test builds. Production builds cannot access this config.
    #[cfg(any(test, feature = "allow_insecure"))]
    #[deprecated(
        since = "5.0.0",
        note = "INSECURE: light_insecure() has only ~36-bit security. Use SecureConfig::secure_128() for production."
    )]
    pub fn light_insecure() -> Self {
        Self {
            n: 1024,
            primes: vec![998244353],
            q: 998244353,
            t: 2053, // Carefully chosen to avoid encode/decode precision issues
            eta: 2,
            security_bits: 36, // CORRECTED: actual security level
            name: "light_insecure",
        }
    }

    /// Configuration for ct×ct multiplication using large single modulus
    /// Uses 60-bit prime so Δ² fits without overflow
    pub fn large_single() -> Self {
        // Use a 60-bit NTT-compatible prime
        // q must satisfy: q ≡ 1 (mod 2N) for NTT
        // For N=4096: q ≡ 1 (mod 8192)
        // 1152921504606846593 = 2^60 + 8193 is prime and ≡ 1 (mod 8192)
        let q: u64 = 1152921504606846593;
        let _t: u64 = 65537; // Standard plaintext modulus

        // Δ = q/t ≈ 17.6 trillion
        // Δ² ≈ 3.1 × 10^26 which is > q, so this still overflows

        // Need smaller t to make Δ smaller
        // If t = q/1000, then Δ = 1000, Δ² = 1M << q ✓
        // Let's use t = 2^20 ≈ 1M, Δ ≈ 1T, Δ² ≈ 10^24 which is still huge

        // Actually for Δ² < q we need Δ < √q ≈ 10^9
        // So t > q/10^9 ≈ 10^9
        // Use t = 10^9 + small adjustment for NTT compatibility

        // Simpler approach: use smaller N to allow larger t
        // For testing, use N=1024 and t that gives Δ < √q

        Self {
            n: 4096,
            primes: vec![q],
            q,
            t: 1099511627777, // ~2^40, gives Δ ≈ 2^20
            eta: 3,
            security_bits: 128,
            name: "large_single",
        }
    }

    /// Configuration for ct×ct testing with small Δ to avoid Δ² overflow
    /// Uses large t to keep Δ small enough that Δ² < q
    /// WARNING: Has only ~1 bit noise budget - use light_rns for real work
    #[cfg(any(test, debug_assertions, feature = "allow_insecure"))]
    pub fn light_mul_insecure() -> Self {
        // For single-modulus ct×ct: need Δ² < q (so tensor product doesn't overflow)
        // With t=500000: Δ ≈ 1996, Δ² ≈ 4M < q ✓
        // BUT: noise budget = log2(Δ) - initial_noise ≈ 11 - 10 = 1 bit!
        Self {
            n: 1024,
            primes: vec![998244353],
            q: 998244353,
            t: 500000, // Large t gives small Δ
            eta: 2,
            security_bits: 80,
            name: "light_mul_insecure",
        }
    }

    /// Light RNS configuration for ct×ct multiplication with proper noise budget
    ///
    /// Uses THREE 30-bit NTT-compatible primes for RNS multiplication:
    /// - Effective Q = q1 × q2 × q3 ≈ 7.4 × 10^26 (~90 bits)
    /// - Each channel: Δ_i = qi/t ≈ 15231, Δ_i² ≈ 232M < qi ✓
    /// - Noise budget: log2(Q/t) - initial ≈ 74 bits
    /// - Required: Q > N × q² for safe CRT reconstruction
    ///   - N × q² = 1024 × (10^9)² ≈ 10^21 (~70 bits)
    ///   - Q ≈ 7.4 × 10^26 (~90 bits) > 10^21 ✓
    /// - Supports 5+ levels of CT×CT multiplication
    ///
    /// This is the RECOMMENDED light config for multiplication testing.
    #[cfg(any(test, debug_assertions, feature = "allow_insecure"))]
    pub fn light_rns_insecure() -> Self {
        Self {
            n: 1024,
            // Three 30-bit NTT primes: Q ≈ 7.4 × 10^26 (~90 bits)
            // This ensures Q > N × q² for safe CRT reconstruction
            primes: vec![998244353, 985661441, 754974721],
            q: 998244353, // Primary modulus for output
            t: 65537,     // Standard plaintext modulus
            eta: 2,
            security_bits: 80,
            name: "light_rns_insecure",
        }
    }

    /// QMNF Exact RNS configuration for ct×ct multiplication
    ///
    /// Uses the QMNF exact multiplication approach from ct_mul_exact:
    /// - Single 30-bit modulus q = 998244353
    /// - Large t = 500000 → small Δ ≈ 1996
    /// - Δ² ≈ 4M << M×A (92-bit reconstruction capacity)
    /// - K-Elimination enables exact rescaling (no float)
    ///
    /// Key constraint: Δ² < 2^92 (M×A capacity)
    /// With Δ ≈ 2000, Δ² ≈ 4M << 2^92 ✓
    ///
    /// Trade-off: Smaller plaintext space (t=500000 vs t=65537)
    /// but exact arithmetic and guaranteed correct results.
    ///
    /// This is the config that matches the QMNF papers' exact approach.
    #[cfg(any(test, debug_assertions, feature = "allow_insecure"))]
    pub fn light_exact_insecure() -> Self {
        Self {
            n: 1024,
            primes: vec![998244353], // Single 30-bit prime
            q: 998244353,
            t: 500000, // Large t → small Δ → Δ² fits in reconstruction capacity
            eta: 2,
            security_bits: 80,
            name: "light_exact_insecure",
        }
    }

    /// QMNF Exact RNS with 2 primes using K-Elimination for rescaling
    ///
    /// Uses the QMNF K-Elimination approach:
    /// - Main modulus M = Q = product of primes ≈ 9.84e17 (~60 bits)
    /// - Anchor modulus A ≈ 4.6e18 (~62 bits) from ExactDivider
    /// - Reconstruction capacity M×A ≈ 2^122 (way more than needed)
    ///
    /// Critical constraint: Δ² < M×A (K-Elimination reconstruction limit)
    /// - Need Δ < 2^61 → need t > Q/2^61 ≈ 1 (any t works!)
    ///
    /// Practical choice: t = 65537 (standard plaintext modulus)
    /// - Δ = Q/t ≈ 1.5e13 ≈ 2^44
    /// - Δ² ≈ 2^88 < M×A ≈ 2^122 ✓
    /// - Noise budget: log2(Δ) - initial ≈ 44 - 12 ≈ 32 bits (plenty!)
    ///
    /// NOTE: This config requires K-Elimination rescaling in RNSFHEContext.
    /// Standard Bajard rescaling will fail because Δ² > Q.
    #[cfg(any(test, debug_assertions, feature = "allow_insecure"))]
    #[deprecated(
        since = "5.0.0",
        note = "INSECURE: light_rns_exact_insecure() has only ~80-bit security (n=1024). Use SecureConfig::secure_128() for production."
    )]
    pub fn light_rns_exact_insecure() -> Self {
        Self {
            n: 1024,
            primes: vec![998244353, 985661441], // Two 30-bit primes: Q ≈ 2^60
            q: 998244353,
            t: 65537, // Standard t → Δ ≈ 2^44, Δ² ≈ 2^88 < M×A ≈ 2^122 ✓
            eta: 2,
            security_bits: 80,
            name: "light_rns_exact_insecure",
        }
    }

    /// Check if this config supports RNS-based ct×ct multiplication
    pub fn supports_rns_mul(&self) -> bool {
        self.primes.len() >= 2
    }

    /// Get the effective modulus product Q for RNS configs
    pub fn rns_product(&self) -> u128 {
        self.primes.iter().fold(1u128, |acc, &p| acc * p as u128)
    }

    /// Get noise budget in millibits for RNS multiplication
    /// This accounts for the larger effective modulus from multiple primes
    /// Returns budget * 1000 for integer-only precision
    pub fn rns_noise_budget_millibits(&self) -> u64 {
        if self.primes.len() < 2 {
            return self.noise_budget() as u64 * 1000;
        }

        // With RNS, effective Q = product of all primes
        let q_product = self.rns_product();
        let delta_effective = q_product / self.t as u128;
        let delta_bits = if delta_effective > 0 {
            128 - delta_effective.leading_zeros()
        } else {
            0
        };

        // Initial noise estimate
        let eta_bits = self.eta as u32 + 1;
        let n_bits_half = self.n.trailing_zeros() / 2; // integer log2(sqrt(n))
        let initial_noise_bits = eta_bits + n_bits_half + 3;

        (delta_bits as u64).saturating_sub(initial_noise_bits as u64) * 1000
    }

    /// Standard configuration (~96-bit actual security)
    ///
    /// # Security Note
    ///
    /// This config achieves ~96 bits of security against hybrid attacks.
    /// For guaranteed 128-bit security, use `SecureConfig::secure_128()`.
    ///
    /// Suitable for applications where 96-bit security is acceptable
    /// and performance is prioritized over maximum security margin.
    pub fn standard_128() -> Self {
        Self {
            n: 4096,
            // 3 primes required for RNS multiplication: Q > N × q²
            // 998244353 × 985661441 × 754974721 ≈ 7.4 × 10^26
            // This ensures tensor product coefficients (up to ~4 × 10^21) don't overflow
            primes: vec![998244353, 985661441, 754974721],
            q: 998244353, // Primary modulus
            t: 65537,
            eta: 3,
            security_bits: 96, // CORRECTED: actual hybrid attack security
            name: "standard_128",
        }
    }

    /// High security configuration (~176-bit actual security)
    ///
    /// This config exceeds 128-bit security and is suitable for
    /// applications requiring long-term security guarantees.
    ///
    /// For exact 192-bit security, use `SecureConfig::secure_192()`.
    pub fn high_192() -> Self {
        Self {
            n: 8192,
            primes: vec![998244353, 985661441, 754974721],
            q: 998244353,
            t: 65537,
            eta: 3,
            security_bits: 176, // CORRECTED: actual hybrid attack security
            name: "high_192",
        }
    }

    /// Deep circuit configuration (larger N for more noise budget)
    pub fn deep_128() -> Self {
        Self {
            n: 16384,
            primes: vec![998244353, 985661441, 754974721, 469762049],
            q: 998244353,
            t: 65537,
            eta: 3,
            security_bits: 128,
            name: "deep_128",
        }
    }

    /// Batched/SIMD configuration (small t for slot packing)
    ///
    /// Uses 3 primes for RNS multiplication capacity.
    pub fn batched() -> Self {
        Self {
            n: 4096,
            primes: vec![998244353, 985661441, 754974721],
            q: 998244353,
            t: 257, // Small prime for efficient batching
            eta: 3,
            security_bits: 128,
            name: "batched",
        }
    }

    /// HE Standard 128-bit Configuration (~56-bit actual security)
    ///
    /// # Security Warning
    ///
    /// **DO NOT USE IN PRODUCTION**
    ///
    /// Despite meeting HE Standard ratios, this config only achieves ~56 bits
    /// of security against hybrid MITM+BKZ attacks due to ternary secret exploitation.
    ///
    /// The HE Standard v1.1 table was designed for Gaussian secrets, not ternary.
    /// Use `SecureConfig::secure_128()` for actual 128-bit security.
    ///
    /// # Security Warning
    ///
    /// This configuration provides only ~56-bit security with ternary secrets.
    /// This is NOT safe for production use. Kept for backward compatibility only.
    ///
    /// # Feature Gate
    /// This function is only available when the `allow_insecure` feature is enabled,
    /// or in test builds. Production builds cannot access this config.
    #[cfg(any(test, feature = "allow_insecure"))]
    #[deprecated(
        since = "5.0.0",
        note = "INSECURE: he_standard_128_insecure() has only ~56-bit security with ternary secrets. Use SecureConfig::secure_128()."
    )]
    pub fn he_standard_128_insecure() -> Self {
        // Validate at construction time
        let config = Self {
            n: 2048,
            primes: vec![998244353], // 30-bit NTT-friendly prime
            q: 998244353,
            t: 65537, // Standard plaintext modulus (Fermat prime F4)
            eta: 3,
            security_bits: 56, // CORRECTED: actual security with ternary secrets
            name: "he_standard_128_insecure",
        };

        // Verify orbital bounds
        let result = validate_params(config.n, config.q, config.t);
        debug_assert!(
            result.orbital_safe,
            "he_standard_128_insecure config fails orbital bounds check"
        );

        config
    }

    /// HE Standard 128-bit with larger plaintext space
    ///
    /// Same security as `he_standard_128` but with smaller Δ for
    /// more noise budget. Trade-off: smaller maximum plaintext values.
    pub fn he_standard_128_deep() -> Self {
        Self {
            n: 2048,
            primes: vec![998244353],
            q: 998244353,
            t: 4096, // Larger t = smaller Δ = more noise budget
            eta: 3,
            security_bits: 128,
            name: "he_standard_128_deep",
        }
    }

    /// Check if this config supports single-modulus ct×ct multiplication
    /// Returns (supported, max_product) where max_product is the largest
    /// m1×m2 value that can be computed without overflow
    pub fn supports_single_mod_mul(&self) -> (bool, u64) {
        let delta = self.delta();
        let delta_squared = (delta as u128) * (delta as u128);

        if delta_squared >= self.q as u128 {
            // Δ² > q: single-mod ct×ct will overflow
            // Return max product that keeps Δ² × product < q
            let max = self.q as u128 / delta_squared;
            (false, max.min(u64::MAX as u128) as u64)
        } else {
            // Δ² < q: can do ct×ct with products up to q/Δ²
            let max = self.q as u128 / delta_squared;
            (true, max.min(u64::MAX as u128) as u64)
        }
    }

    /// Custom configuration with validation
    pub fn custom(n: usize, primes: Vec<u64>, t: u64, eta: usize) -> Result<Self, &'static str> {
        // Validate n is power of 2
        if !n.is_power_of_two() {
            return Err("N must be a power of 2");
        }

        if n < 512 {
            return Err("N must be at least 512 for security");
        }

        // Validate primes
        if primes.is_empty() {
            return Err("Need at least one prime");
        }

        for &p in &primes {
            if !is_prime(p) {
                return Err("All moduli must be prime");
            }
            if !is_ntt_compatible(p, n) {
                return Err("Primes must be NTT-compatible (q ≡ 1 mod 2N)");
            }
        }

        // Validate t
        if t < 2 {
            return Err("Plaintext modulus must be at least 2");
        }

        // Estimate security
        let security_bits = estimate_security(n, primes[0]);

        Ok(Self {
            n,
            primes: primes.clone(),
            q: primes[0],
            t,
            eta,
            security_bits,
            name: "custom",
        })
    }

    /// Get the scaling factor Δ = floor(q/t)
    pub fn delta(&self) -> u64 {
        self.q / self.t
    }

    /// Estimate noise budget in bits
    pub fn noise_budget(&self) -> usize {
        // Approximate: log2(Δ) - log2(initial_noise)
        let delta_bits = 64 - self.delta().leading_zeros();
        let noise_bits = (self.eta as u32 * 2) + (self.n.trailing_zeros());
        if delta_bits > noise_bits {
            (delta_bits - noise_bits) as usize
        } else {
            0
        }
    }

    /// Estimate multiplicative depth
    pub fn estimated_depth(&self) -> usize {
        // Very rough estimate: noise budget / bits_per_mul
        let budget = self.noise_budget();
        let bits_per_mul = (64 - self.t.leading_zeros()) as usize + 5;
        if bits_per_mul > 0 {
            budget / bits_per_mul
        } else {
            0
        }
    }

    // ========================================================================
    // DEPTH-AWARE CONFIGURATIONS
    // ========================================================================

    /// Create configuration for target multiplicative depth with modulus switching
    ///
    /// # Parameters
    /// - `depth`: Target multiplicative depth (number of sequential multiplications)
    /// - `n`: Polynomial degree (must be power of 2, min 1024)
    /// - `security_bits`: Minimum security level
    ///
    /// # Formula
    /// `primes_needed = depth + 2` (min 2 primes at final level for correct decryption)
    ///
    /// # Example
    /// ```ignore
    /// // Depth-2 circuit: (a*b) * (c*d)
    /// let config = FHEConfig::for_depth(2, 4096, 128);
    /// assert_eq!(config.primes.len(), 4);  // 4 primes for depth-2
    /// ```
    pub fn for_depth(depth: usize, n: usize, security_bits: usize) -> Self {
        assert!(
            n.is_power_of_two() && n >= 1024,
            "N must be power of 2 >= 1024"
        );
        assert!(depth >= 1, "Depth must be at least 1");

        let primes_needed = depth + 2; // Need 2 primes at final level

        // Select appropriate pre-defined primes based on N
        let available_primes: &[u64] = match n {
            1024 => &PRIMES_1024,
            4096 => &PRIMES_4096,
            8192 | 16384 => &PRIMES_8192,
            _ => &PRIMES_4096, // Default to 4096 primes for unknown N
        };

        // Use as many primes as needed, up to available
        let primes: Vec<u64> = if primes_needed <= available_primes.len() {
            available_primes[..primes_needed].to_vec()
        } else {
            // Need more primes - find additional NTT-compatible primes
            let mut primes = available_primes.to_vec();
            let additional = find_ntt_primes(n, primes_needed - primes.len(), 28);
            for p in additional {
                if !primes.contains(&p) {
                    primes.push(p);
                }
                if primes.len() >= primes_needed {
                    break;
                }
            }
            primes
        };

        let eta = if n <= 2048 { 2 } else { 3 };

        Self {
            n,
            primes: primes.clone(),
            q: primes[0],
            t: 65537,
            eta,
            security_bits,
            name: "depth_aware",
        }
    }

    /// 4-prime configuration for depth-2 circuits
    ///
    /// Supports: fresh → mul+mod_switch → mul+mod_switch → decrypt
    /// Prime chain: 4 → 3 → 2 (final level)
    pub fn depth2_128() -> Self {
        Self {
            n: 4096,
            primes: vec![998244353, 985661441, 754974721, 469762049],
            q: 998244353,
            t: 65537,
            eta: 3,
            security_bits: 96,
            name: "depth2_128",
        }
    }

    /// 5-prime configuration for depth-3 circuits
    pub fn depth3_128() -> Self {
        Self {
            n: 8192,
            primes: vec![998244353, 985661441, 754974721, 469762049, 1638350849],
            q: 998244353,
            t: 65537,
            eta: 3,
            security_bits: 128,
            name: "depth3_128",
        }
    }

    /// 8-prime configuration for depth-6 circuits (uses all PRIMES_8192)
    pub fn deep_circuit() -> Self {
        Self {
            n: 8192,
            primes: PRIMES_8192.to_vec(),
            q: PRIMES_8192[0],
            t: 65537,
            eta: 3,
            security_bits: 176,
            name: "deep_circuit",
        }
    }

    /// Maximum multiplicative depth supported by this config with mod-switch
    ///
    /// Formula: `max_depth = num_primes - 2` (need 2 primes at final level)
    pub fn max_mod_switch_depth(&self) -> usize {
        if self.primes.len() >= 2 {
            self.primes.len() - 2
        } else {
            0
        }
    }
}

/// Estimate security level based on LWE hardness
fn estimate_security(n: usize, q: u64) -> usize {
    // Simplified estimate based on n and log2(q)
    let log_q = 64 - q.leading_zeros();
    let ratio_permille = ((n as u64) * 1000) / log_q as u64;

    if ratio_permille > 50_000 {
        192
    } else if ratio_permille > 30_000 {
        128
    } else if ratio_permille > 20_000 {
        80
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::secure_configs::SecureConfig;

    #[test]
    fn test_all_configs_valid() {
        let configs = [
            SecureConfig::test_fast_insecure().into_config(),
            SecureConfig::test_medium_insecure().into_config(),
            FHEConfig::light_mul_insecure(),
            FHEConfig::light_rns_insecure(),
            FHEConfig::standard_128(),
            FHEConfig::high_192(),
            FHEConfig::deep_128(),
            FHEConfig::batched(),
            FHEConfig::he_standard_128_deep(),
        ];

        for config in configs {
            assert!(
                config.n.is_power_of_two(),
                "{} n not power of 2",
                config.name
            );
            assert!(!config.primes.is_empty(), "{} has no primes", config.name);
            assert!(config.t >= 2, "{} t too small", config.name);
            assert!(config.delta() > 0, "{} delta is 0", config.name);

            let rns_info = if config.supports_rns_mul() {
                format!(
                    "RNS Q={}, RNS budget={}mb",
                    config.rns_product(),
                    config.rns_noise_budget_millibits()
                )
            } else {
                "single-mod".to_string()
            };

            println!(
                "{}: N={}, q={}, t={}, Δ={}, budget={}bits, depth≈{}, {}",
                config.name,
                config.n,
                config.q,
                config.t,
                config.delta(),
                config.noise_budget(),
                config.estimated_depth(),
                rns_info
            );
        }
    }

    #[test]
    #[allow(deprecated)]
    fn test_he_standard_compliance() {
        let config = FHEConfig::he_standard_128_insecure();

        // HE Standard v1.1 Table 3 requirements for 128-bit classical security
        let log_q = 64 - config.q.leading_zeros();
        let he_max_log_q = 54; // For N=2048

        assert!(config.n >= 2048, "N must be >= 2048 for 128-bit");
        assert!(
            log_q <= he_max_log_q,
            "log(q)={} exceeds HE Standard max {} for N={}",
            log_q,
            he_max_log_q,
            config.n
        );

        // Verify N/log(q) ratio (rough security indicator)
        let ratio_permille = ((config.n as u64) * 1000) / log_q as u64;
        assert!(
            ratio_permille > 38_000,
            "N/log(q) ratio {}.{:03} too low for 128-bit",
            ratio_permille / 1000,
            ratio_permille % 1000
        );

        // Verify orbital safety
        let result = validate_params(config.n, config.q, config.t);
        assert!(
            result.orbital_safe,
            "HE Standard config fails orbital bounds"
        );
        assert!(
            result.he_standard_compliant,
            "HE Standard config not compliant"
        );

        println!("HE Standard 128-bit Compliance:");
        println!("  N = {}", config.n);
        println!("  log(q) = {} (max {})", log_q, he_max_log_q);
        println!(
            "  N/log(q) = {}.{:03} (need > 38)",
            ratio_permille / 1000,
            ratio_permille % 1000
        );
        println!("  Orbital safe: {}", result.orbital_safe);
        println!("  HE compliant: {}", result.he_standard_compliant);
    }

    #[test]
    fn test_custom_config() {
        let config =
            FHEConfig::custom(2048, vec![998244353], 1024, 2).expect("Should create valid config");

        assert_eq!(config.n, 2048);
        assert_eq!(config.t, 1024);
    }

    #[test]
    fn test_estimated_depth() {
        let light = FHEConfig::standard_128();
        let deep = FHEConfig::deep_128();

        // Deep config should have more depth
        assert!(
            deep.estimated_depth() >= light.estimated_depth(),
            "Deep config should have >= depth"
        );
    }
}
