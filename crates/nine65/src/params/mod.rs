//! FHE configuration and parameter sets.
//!
//! Legacy parameter sets are retained for compatibility and testing. Named
//! production candidates live in `secure_configs` and require independent
//! estimator artifacts for external security claims. The full RNS modulus is
//! canonically represented by its ordered prime-factor vector; scalar products
//! are checked and exact multi-limb accounting is used when the product exceeds
//! `u128`.

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
pub use secure_configs::{assert_production_safe, ProductionSafe, SecureConfig};
pub use security_estimator::{
    CostModel, HEStandardBounds, LatticeSecurityEstimator, SecretDistribution, SecurityEstimate,
};
pub use validation::{assert_params_valid, validate_params, ParameterValidator, ValidationResult};

/// Multiply an ordered factor vector into exact little-endian 64-bit limbs.
///
/// The vector grows as required, so no saturation, wrapping, fixed product cap,
/// Garner reconstruction, or mixed-radix conversion is involved.
fn exact_product_limbs(factors: &[u64]) -> Vec<u64> {
    let mut limbs = vec![1u64];

    for &factor in factors {
        let mut carry = 0u128;
        for limb in &mut limbs {
            let product = (*limb as u128) * factor as u128 + carry;
            *limb = product as u64;
            carry = product >> 64;
        }
        if carry != 0 {
            limbs.push(carry as u64);
        }
    }

    while limbs.len() > 1 && limbs.last() == Some(&0) {
        limbs.pop();
    }
    limbs
}

fn limbs_bit_length(limbs: &[u64]) -> u32 {
    for index in (0..limbs.len()).rev() {
        let limb = limbs[index];
        if limb != 0 {
            return index as u32 * 64 + (64 - limb.leading_zeros());
        }
    }
    0
}

/// Exact division of a little-endian multi-limb integer by one nonzero `u64`.
fn divide_limbs_by_u64(limbs: &[u64], divisor: u64) -> Vec<u64> {
    assert!(divisor != 0, "multi-limb divisor must be nonzero");
    let mut quotient = vec![0u64; limbs.len()];
    let mut remainder = 0u128;

    for index in (0..limbs.len()).rev() {
        let numerator = (remainder << 64) | limbs[index] as u128;
        quotient[index] = (numerator / divisor as u128) as u64;
        remainder = numerator % divisor as u128;
    }

    while quotient.len() > 1 && quotient.last() == Some(&0) {
        quotient.pop();
    }
    quotient
}

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
    #[cfg(any(test, feature = "allow_insecure"))]
    #[deprecated(
        since = "5.0.0",
        note = "INSECURE: light() has only ~36-bit security. Use an audited SecureConfig candidate."
    )]
    #[cfg(any(test, debug_assertions, feature = "allow_insecure"))]
    pub fn light_insecure() -> Self {
        Self {
            n: 1024,
            primes: vec![998244353],
            q: 998244353,
            t: 2053,
            eta: 2,
            security_bits: 36,
            name: "light_insecure",
        }
    }

    /// Configuration for ct×ct multiplication using a large single modulus.
    #[cfg(any(test, debug_assertions, feature = "allow_insecure"))]
    pub fn large_single_insecure() -> Self {
        let q: u64 = 1152921504606846593;
        Self {
            n: 4096,
            primes: vec![q],
            q,
            t: 1099511627777,
            eta: 3,
            security_bits: 128,
            name: "large_single_insecure",
        }
    }

    /// Configuration for ct×ct testing with small delta.
    #[cfg(any(test, debug_assertions, feature = "allow_insecure"))]
    pub fn light_mul_insecure() -> Self {
        Self {
            n: 1024,
            primes: vec![998244353],
            q: 998244353,
            t: 500000,
            eta: 2,
            security_bits: 80,
            name: "light_mul_insecure",
        }
    }

    /// Light RNS configuration for multiplication testing.
    #[cfg(any(test, debug_assertions, feature = "allow_insecure"))]
    pub fn light_rns_insecure() -> Self {
        Self {
            n: 1024,
            primes: vec![998244353, 985661441, 754974721],
            q: 998244353,
            t: 65537,
            eta: 2,
            security_bits: 80,
            name: "light_rns_insecure",
        }
    }

    /// Exact single-lane test configuration.
    #[cfg(any(test, debug_assertions, feature = "allow_insecure"))]
    pub fn light_exact_insecure() -> Self {
        Self {
            n: 1024,
            primes: vec![998244353],
            q: 998244353,
            t: 500000,
            eta: 2,
            security_bits: 80,
            name: "light_exact_insecure",
        }
    }

    /// Exact two-lane RNS test configuration using K-Elimination rescaling.
    #[deprecated(
        since = "5.0.0",
        note = "INSECURE: light_rns_exact has only test-level security."
    )]
    #[cfg(any(test, debug_assertions, feature = "allow_insecure"))]
    pub fn light_rns_exact_insecure() -> Self {
        Self {
            n: 1024,
            primes: vec![998244353, 985661441],
            q: 998244353,
            t: 65537,
            eta: 2,
            security_bits: 80,
            name: "light_rns_exact_insecure",
        }
    }

    /// Check if this config supports RNS-based ct×ct multiplication.
    pub fn supports_rns_mul(&self) -> bool {
        self.primes.len() >= 2
    }

    /// Return the exact modulus product when it fits in `u128`.
    ///
    /// `None` is a first-class overflow result. The ordered prime vector and
    /// [`Self::rns_product_limbs`] remain the canonical representations for large
    /// products.
    pub fn try_rns_product(&self) -> Option<u128> {
        self.primes
            .iter()
            .try_fold(1u128, |acc, &prime| acc.checked_mul(prime as u128))
    }

    /// Return the exact modulus product as little-endian 64-bit limbs.
    pub fn rns_product_limbs(&self) -> Vec<u64> {
        exact_product_limbs(&self.primes)
    }

    /// Return the exact bit length of the full RNS modulus product.
    pub fn rns_product_bit_length(&self) -> u32 {
        limbs_bit_length(&self.rns_product_limbs())
    }

    /// Return the exact scalar modulus product or fail closed on overflow.
    ///
    /// New code should prefer [`Self::try_rns_product`] unless a fitting scalar
    /// product is a proven precondition.
    pub fn rns_product(&self) -> u128 {
        self.try_rns_product().expect(
            "RNS modulus product exceeds u128; use rns_product_limbs or rns_product_bit_length",
        )
    }

    /// Get the exact integer noise budget in millibits for RNS multiplication.
    pub fn rns_noise_budget_millibits(&self) -> u64 {
        if self.primes.len() < 2 {
            return self.noise_budget() as u64 * 1000;
        }

        assert!(self.t >= 2, "plaintext modulus must be at least two");
        assert!(
            self.primes.iter().all(|&prime| self.t < prime),
            "plaintext modulus must be smaller than every RNS prime"
        );

        let product = self.rns_product_limbs();
        let effective_delta = divide_limbs_by_u64(&product, self.t);
        let delta_bits = limbs_bit_length(&effective_delta);

        let eta_bits = self.eta as u32 + 1;
        let n_bits_half = self.n.trailing_zeros() / 2;
        let initial_noise_bits = eta_bits + n_bits_half + 3;

        (delta_bits as u64).saturating_sub(initial_noise_bits as u64) * 1000
    }

    /// Standard configuration (~96-bit actual security).
    #[cfg(any(test, debug_assertions, feature = "allow_insecure"))]
    pub fn standard_128_insecure() -> Self {
        Self {
            n: 4096,
            primes: vec![998244353, 985661441, 754974721],
            q: 998244353,
            t: 65537,
            eta: 3,
            security_bits: 96,
            name: "standard_128_insecure",
        }
    }

    /// High legacy security configuration (~176-bit internal estimate).
    #[cfg(any(test, debug_assertions, feature = "allow_insecure"))]
    pub fn high_192_insecure() -> Self {
        Self {
            n: 8192,
            primes: vec![998244353, 985661441, 754974721],
            q: 998244353,
            t: 65537,
            eta: 3,
            security_bits: 176,
            name: "high_192_insecure",
        }
    }

    /// Deep legacy circuit configuration.
    #[cfg(any(test, debug_assertions, feature = "allow_insecure"))]
    pub fn deep_128_insecure() -> Self {
        Self {
            n: 16384,
            primes: vec![998244353, 985661441, 754974721, 469762049],
            q: 998244353,
            t: 65537,
            eta: 3,
            security_bits: 128,
            name: "deep_128_insecure",
        }
    }

    /// Batched/SIMD legacy configuration.
    #[cfg(any(test, debug_assertions, feature = "allow_insecure"))]
    pub fn batched_insecure() -> Self {
        Self {
            n: 4096,
            primes: vec![998244353, 985661441, 754974721],
            q: 998244353,
            t: 257,
            eta: 3,
            security_bits: 128,
            name: "batched_insecure",
        }
    }

    /// HE Standard 128-bit legacy configuration (~56-bit internal estimate).
    #[cfg(any(test, feature = "allow_insecure"))]
    #[deprecated(
        since = "5.0.0",
        note = "INSECURE: he_standard_128 has only test-level security with ternary secrets."
    )]
    #[cfg(any(test, debug_assertions, feature = "allow_insecure"))]
    pub fn he_standard_128_insecure() -> Self {
        let config = Self {
            n: 2048,
            primes: vec![998244353],
            q: 998244353,
            t: 65537,
            eta: 3,
            security_bits: 56,
            name: "he_standard_128_insecure",
        };

        let result = validate_params(config.n, config.q, config.t);
        debug_assert!(
            result.orbital_safe,
            "he_standard_128 config fails orbital bounds check"
        );
        config
    }

    /// HE Standard legacy configuration with a larger plaintext space.
    #[cfg(any(test, debug_assertions, feature = "allow_insecure"))]
    pub fn he_standard_128_deep_insecure() -> Self {
        Self {
            n: 2048,
            primes: vec![998244353],
            q: 998244353,
            t: 4096,
            eta: 3,
            security_bits: 128,
            name: "he_standard_128_deep_insecure",
        }
    }

    /// Check if this config supports single-modulus ct×ct multiplication.
    pub fn supports_single_mod_mul(&self) -> (bool, u64) {
        let delta = self.delta();
        let delta_squared = (delta as u128) * (delta as u128);

        if delta_squared >= self.q as u128 {
            let max = self.q as u128 / delta_squared;
            (false, max.min(u64::MAX as u128) as u64)
        } else {
            let max = self.q as u128 / delta_squared;
            (true, max.min(u64::MAX as u128) as u64)
        }
    }

    /// Custom configuration with fail-closed validation.
    pub fn custom(n: usize, primes: Vec<u64>, t: u64, eta: usize) -> Result<Self, &'static str> {
        if !n.is_power_of_two() {
            return Err("N must be a power of 2");
        }
        if n < 512 {
            return Err("N must be at least 512 for security");
        }
        if primes.is_empty() {
            return Err("Need at least one prime");
        }

        for &prime in &primes {
            if !is_prime(prime) {
                return Err("All moduli must be prime");
            }
            if !is_ntt_compatible(prime, n) {
                return Err("Primes must be NTT-compatible (q ≡ 1 mod 2N)");
            }
        }

        if t < 2 {
            return Err("Plaintext modulus must be at least 2");
        }
        if primes.iter().any(|&prime| t >= prime) {
            return Err("Plaintext modulus must be smaller than every RNS prime");
        }

        let security_bits = estimate_security(n, primes[0]);
        Ok(Self {
            n,
            q: primes[0],
            primes,
            t,
            eta,
            security_bits,
            name: "custom",
        })
    }

    /// Get the scaling factor delta = floor(q/t).
    pub fn delta(&self) -> u64 {
        self.q / self.t
    }

    /// Estimate noise budget in bits.
    pub fn noise_budget(&self) -> usize {
        let delta_bits = 64 - self.delta().leading_zeros();
        let noise_bits = (self.eta as u32 * 2) + self.n.trailing_zeros();
        if delta_bits > noise_bits {
            (delta_bits - noise_bits) as usize
        } else {
            0
        }
    }

    /// Estimate multiplicative depth.
    pub fn estimated_depth(&self) -> usize {
        let budget = self.noise_budget();
        let bits_per_mul = (64 - self.t.leading_zeros()) as usize + 5;
        if bits_per_mul > 0 {
            budget / bits_per_mul
        } else {
            0
        }
    }

    /// Create a configuration for a target multiplicative depth.
    pub fn for_depth(depth: usize, n: usize, security_bits: usize) -> Self {
        assert!(
            n.is_power_of_two() && n >= 1024,
            "N must be power of 2 >= 1024"
        );
        assert!(depth >= 1, "Depth must be at least 1");

        let primes_needed = depth + 2;
        let available_primes: &[u64] = match n {
            1024 => &PRIMES_1024,
            4096 => &PRIMES_4096,
            8192 | 16384 => &PRIMES_8192,
            _ => &PRIMES_4096,
        };

        let primes: Vec<u64> = if primes_needed <= available_primes.len() {
            available_primes[..primes_needed].to_vec()
        } else {
            let mut primes = available_primes.to_vec();
            let additional = find_ntt_primes(n, primes_needed - primes.len(), 28);
            for prime in additional {
                if !primes.contains(&prime) {
                    primes.push(prime);
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
            q: primes[0],
            primes,
            t: 65537,
            eta,
            security_bits,
            name: "depth_aware",
        }
    }

    /// Four-prime configuration for depth-two tests.
    #[cfg(any(test, debug_assertions, feature = "allow_insecure"))]
    pub fn depth2_128_insecure() -> Self {
        Self {
            n: 4096,
            primes: vec![998244353, 985661441, 754974721, 469762049],
            q: 998244353,
            t: 65537,
            eta: 3,
            security_bits: 96,
            name: "depth2_128_insecure",
        }
    }

    /// Five-prime configuration for depth-three tests.
    #[cfg(any(test, debug_assertions, feature = "allow_insecure"))]
    pub fn depth3_128_insecure() -> Self {
        Self {
            n: 8192,
            primes: vec![998244353, 985661441, 754974721, 469762049, 1638350849],
            q: 998244353,
            t: 65537,
            eta: 3,
            security_bits: 128,
            name: "depth3_128_insecure",
        }
    }

    /// Eight-prime configuration for depth-six tests.
    #[cfg(any(test, debug_assertions, feature = "allow_insecure"))]
    pub fn deep_circuit_insecure() -> Self {
        Self {
            n: 8192,
            primes: PRIMES_8192.to_vec(),
            q: PRIMES_8192[0],
            t: 65537,
            eta: 3,
            security_bits: 176,
            name: "deep_circuit_insecure",
        }
    }

    /// Maximum multiplicative depth supported by modulus switching.
    pub fn max_mod_switch_depth(&self) -> usize {
        if self.primes.len() >= 2 {
            self.primes.len() - 2
        } else {
            0
        }
    }
}

/// Estimate security level based on N/log2(q).
fn estimate_security(n: usize, q: u64) -> usize {
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

    fn raw_config(primes: Vec<u64>) -> FHEConfig {
        FHEConfig {
            n: 2048,
            q: primes[0],
            primes,
            t: 2,
            eta: 2,
            security_bits: 0,
            name: "product_boundary_test",
        }
    }

    #[test]
    fn test_all_configs_valid() {
        let configs = [
            SecureConfig::test_fast_insecure().into_config(),
            SecureConfig::test_medium_insecure().into_config(),
            FHEConfig::light_mul_insecure(),
            FHEConfig::light_rns_insecure(),
            FHEConfig::standard_128_insecure(),
            FHEConfig::high_192_insecure(),
            FHEConfig::deep_128_insecure(),
            FHEConfig::batched_insecure(),
            FHEConfig::he_standard_128_deep_insecure(),
        ];

        for config in configs {
            assert!(config.n.is_power_of_two(), "{} n not power of 2", config.name);
            assert!(!config.primes.is_empty(), "{} has no primes", config.name);
            assert!(config.t >= 2, "{} t too small", config.name);
            assert!(
                config.primes.iter().all(|&prime| config.t < prime),
                "{} t must be below every prime",
                config.name
            );
            assert!(config.delta() > 0, "{} delta is 0", config.name);

            let rns_info = if config.supports_rns_mul() {
                format!(
                    "RNS bits={}, RNS budget={}mb",
                    config.rns_product_bit_length(),
                    config.rns_noise_budget_millibits()
                )
            } else {
                "single-mod".to_string()
            };

            println!(
                "{}: N={}, q={}, t={}, delta={}, budget={}bits, depth={}, {}",
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
        let log_q = 64 - config.q.leading_zeros();
        let he_max_log_q = 54;

        assert!(config.n >= 2048, "N must be >= 2048 for 128-bit");
        assert!(
            log_q <= he_max_log_q,
            "log(q)={} exceeds HE Standard max {} for N={}",
            log_q,
            he_max_log_q,
            config.n
        );

        let ratio_permille = ((config.n as u64) * 1000) / log_q as u64;
        assert!(ratio_permille > 38_000);

        let result = validate_params(config.n, config.q, config.t);
        assert!(result.orbital_safe);
        assert!(result.he_standard_compliant);
    }

    #[test]
    fn test_custom_config() {
        let config =
            FHEConfig::custom(2048, vec![998244353], 1024, 2).expect("valid config");
        assert_eq!(config.n, 2048);
        assert_eq!(config.t, 1024);
    }

    #[test]
    fn custom_rejects_invalid_plaintext_lane_relationships() {
        assert!(FHEConfig::custom(2048, vec![998244353], 1, 2).is_err());
        assert!(FHEConfig::custom(2048, vec![998244353], 998244353, 2).is_err());
        assert!(FHEConfig::custom(2048, vec![998244353], 998244354, 2).is_err());
    }

    #[test]
    fn checked_rns_product_covers_u128_boundaries() {
        let below = raw_config(vec![u64::MAX, u64::MAX]);
        assert!(below.try_rns_product().is_some());
        assert_eq!(below.rns_product_bit_length(), 128);

        // 2^128 - 1 = (2^64 - 1) * 274177 * 67280421310721.
        let equal = raw_config(vec![u64::MAX, 274177, 67280421310721]);
        assert_eq!(equal.try_rns_product(), Some(u128::MAX));
        assert_eq!(equal.rns_product_bit_length(), 128);

        let above = raw_config(vec![u64::MAX, 274177, 67280421310721, 2]);
        assert_eq!(above.try_rns_product(), None);
        assert_eq!(above.rns_product_bit_length(), 129);
        assert_eq!(above.rns_product_limbs().len(), 3);
    }

    #[test]
    #[should_panic(expected = "exceeds u128")]
    fn scalar_rns_product_fails_closed_above_u128() {
        raw_config(vec![u64::MAX, 274177, 67280421310721, 2]).rns_product();
    }

    #[test]
    fn exact_noise_budget_accepts_large_products_without_scalar_projection() {
        let config = FHEConfig {
            n: 16384,
            primes: vec![998244353, 985661441, 754974721, 469762049, 167772161, 595591169],
            q: 998244353,
            t: 65537,
            eta: 5,
            security_bits: 256,
            name: "large_product_budget_test",
        };
        assert!(config.try_rns_product().is_none());
        assert!(config.rns_product_bit_length() > 128);
        assert!(config.rns_noise_budget_millibits() > 0);
    }

    #[test]
    fn test_estimated_depth() {
        let light = FHEConfig::standard_128_insecure();
        let deep = FHEConfig::deep_128_insecure();
        assert!(deep.estimated_depth() >= light.estimated_depth());
    }
}
