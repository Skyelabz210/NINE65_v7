//! Production Parameters - 128-bit Post-Quantum Security
//!
//! Based on HomomorphicEncryption.org standards and lattice-estimator validation.
//! These are NOT toy parameters.

/// Verified NTT-friendly primes for high-security configurations
///
/// These primes have been validated (2026-01-25):
/// - Primality verified with sympy.isprime (Miller-Rabin + Lucas)
/// - NTT compatibility: q ≡ 1 (mod 16384) for N up to 8192
/// - Coprimality verified between all primes
pub const VERIFIED_PRIMES_51BIT: [u64; 5] = [
    1125899906990081, // Verified prime, q ≡ 1 (mod 16384), 51 bits
    1125899907219457, // Verified prime, q ≡ 1 (mod 16384), 51 bits
    1125899907776513, // Verified prime, q ≡ 1 (mod 16384), 51 bits
    1125899908005889, // Verified prime, q ≡ 1 (mod 16384), 51 bits
    1125899908022273, // Verified prime, q ≡ 1 (mod 16384), 51 bits
];

/// 30-bit NTT primes (for lighter operations, still secure with enough of them)
///
/// All values verified prime with deterministic Miller-Rabin (2026-02-06).
/// All satisfy q ≡ 1 (mod 65536) for NTT compatibility with N up to 32768.
pub const PRODUCTION_PRIMES_30BIT: [u64; 15] = [
    998244353, // 2^23 * 7 * 17 + 1  - the classic
    985661441, // 2^22 * 5 * 47 + 1
    975175681, // verified prime
    962592769, // verified prime
    950009857, // verified prime
    943718401, // verified prime
    935329793, // verified prime
    924844033, // verified prime
    918552577, // verified prime
    908328961, // verified prime, q ≡ 1 mod 65536 (N=32768 compatible)
    897581057, // verified prime
    902627329, // verified prime, q ≡ 1 mod 65536 (N=32768 compatible)
    909770753, // verified prime
    909377537, // verified prime
    909180929, // verified prime
];

/// Production configuration for 128-bit classical security
/// N=8192, ~15 primes, logQ ≈ 438 bits
#[derive(Clone, Debug)]
pub struct ProductionConfig128 {
    pub n: usize,
    pub log_n: usize,
    pub primes: Vec<u64>,
    pub special_primes: Vec<u64>, // For key switching
    pub t: u64,                   // Plaintext modulus
    pub sigma_millibits: u32,     // Error std dev × 1000 (3200 = σ=3.2, integer CBD)
    pub eta: usize,               // CBD parameter
    pub max_depth: usize,         // Multiplicative depth
}

impl ProductionConfig128 {
    /// Standard 128-bit configuration
    /// Based on HE Standard: N=8192 requires logQ ≤ 218 for 128-bit security
    pub fn standard() -> Self {
        Self {
            n: 8192,
            log_n: 13,
            // 7 primes × ~30 bits = ~210 bits, within 218-bit budget
            primes: PRODUCTION_PRIMES_30BIT[0..7].to_vec(),
            special_primes: PRODUCTION_PRIMES_30BIT[7..10].to_vec(),
            t: 65537, // 2^16 + 1, prime
            sigma_millibits: 3200,
            eta: 3,
            max_depth: 6, // Each mul consumes ~1 level
        }
    }

    /// Deep circuit configuration (15+ levels)
    /// N=16384 allows logQ ≤ 438 for 128-bit security
    pub fn deep() -> Self {
        Self {
            n: 16384,
            log_n: 14,
            // 14 primes × ~30 bits = ~420 bits, within 438-bit budget
            primes: PRODUCTION_PRIMES_30BIT[0..14].to_vec(),
            special_primes: vec![PRODUCTION_PRIMES_30BIT[14]],
            t: 65537,
            sigma_millibits: 3200,
            eta: 4,
            max_depth: 13,
        }
    }

    /// High security (192-bit) configuration
    /// N=32768 allows logQ ≤ 881 for 192-bit security
    pub fn high_security() -> Self {
        Self {
            n: 32768,
            log_n: 15,
            // All 15 primes for maximum depth
            primes: PRODUCTION_PRIMES_30BIT.to_vec(),
            special_primes: vec![754974721, 469762049, 167772161, 104857601],
            t: 65537,
            sigma_millibits: 3200,
            eta: 5,
            max_depth: 14,
        }
    }

    /// Get total log(Q) in bits
    pub fn log_q(&self) -> usize {
        self.primes
            .iter()
            .map(|p| 64 - p.leading_zeros() as usize)
            .sum()
    }

    /// Get product of all primes (as big integer representation)
    pub fn q_product_bits(&self) -> usize {
        self.log_q()
    }

    /// Estimate security level using HE Standard table
    /// Reference: https://homomorphicencryption.org/standard/
    ///
    /// | N     | log(q) max | Security |
    /// |-------|------------|----------|
    /// | 1024  | 27         | 128-bit  |
    /// | 2048  | 54         | 128-bit  |
    /// | 4096  | 109        | 128-bit  |
    /// | 8192  | 218        | 128-bit  |
    /// | 16384 | 438        | 128-bit  |
    /// | 32768 | 881        | 128-bit  |
    pub fn estimated_security(&self) -> usize {
        let log_q = self.log_q();
        let n = self.n;

        // HE Standard table for 128-bit security
        let max_log_q_128 = match n {
            1024 => 27,
            2048 => 54,
            4096 => 109,
            8192 => 218,
            16384 => 438,
            32768 => 881,
            65536 => 1770,
            _ => {
                // Interpolate: roughly logQ_max ≈ n / 37.5 for 128-bit
                (n * 1000) / 37_500
            }
        };

        // For 192-bit, the ratio is roughly 1.5x stricter
        let max_log_q_192 = max_log_q_128 * 2 / 3;

        if log_q <= max_log_q_192 {
            192
        } else if log_q <= max_log_q_128 {
            128
        } else if log_q <= max_log_q_128 * 3 / 2 {
            80
        } else {
            0 // Insecure
        }
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), &'static str> {
        if !self.n.is_power_of_two() {
            return Err("N must be power of 2");
        }
        if self.n < 4096 {
            return Err("N must be at least 4096 for production security");
        }
        if self.primes.len() < 5 {
            return Err("Need at least 5 primes for meaningful depth");
        }

        // Check NTT compatibility
        for &p in &self.primes {
            if (p - 1) % (2 * self.n as u64) != 0 {
                return Err("Prime not NTT-compatible with N");
            }
        }

        let security = self.estimated_security();
        if security < 128 {
            return Err("Configuration does not meet 128-bit security");
        }

        Ok(())
    }
}

/// RNS Modulus Chain for level-based rescaling
#[derive(Clone, Debug)]
pub struct ModulusChain {
    /// Primes in the chain, ordered from q_L (largest level) to q_0
    pub primes: Vec<u64>,
    /// Current level (starts at L, decreases with each rescale)
    pub level: usize,
    /// Precomputed products for each level
    pub level_products: Vec<u128>,
}

impl ModulusChain {
    pub fn new(primes: Vec<u64>) -> Self {
        let level = primes.len() - 1;

        // Precompute partial products.
        // Use checked_mul to detect overflow; store 0 as sentinel for levels
        // whose cumulative product exceeds u128.
        let mut level_products = Vec::with_capacity(primes.len());
        let mut product = 1u128;
        let mut overflowed = false;
        for &p in &primes {
            if !overflowed {
                match product.checked_mul(p as u128) {
                    Some(v) => product = v,
                    None => {
                        overflowed = true;
                        product = 0;
                    }
                }
            }
            level_products.push(product);
        }

        Self {
            primes,
            level,
            level_products,
        }
    }

    /// Get current modulus (product of primes at current level)
    pub fn current_modulus(&self) -> u128 {
        if self.level < self.level_products.len() {
            self.level_products[self.level]
        } else {
            0
        }
    }

    /// Get prime at specific level
    pub fn prime_at(&self, level: usize) -> Option<u64> {
        self.primes.get(level).copied()
    }

    /// Drop to next level (after multiplication)
    pub fn drop_level(&mut self) -> bool {
        if self.level > 0 {
            self.level -= 1;
            true
        } else {
            false
        }
    }

    /// Remaining multiplicative depth
    pub fn remaining_depth(&self) -> usize {
        self.level
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_production_config_128() {
        let config = ProductionConfig128::standard();

        println!("Production 128-bit config:");
        println!("  N = {}", config.n);
        println!("  log(Q) ≈ {} bits", config.log_q());
        println!("  Primes: {}", config.primes.len());
        println!("  Max depth: {}", config.max_depth);
        println!("  Estimated security: {}-bit", config.estimated_security());

        assert!(config.validate().is_ok());
        assert!(config.estimated_security() >= 128);
    }

    #[test]
    fn test_production_config_deep() {
        let config = ProductionConfig128::deep();

        println!("Production deep config:");
        println!("  N = {}", config.n);
        println!("  log(Q) ≈ {} bits", config.log_q());
        println!("  Primes: {}", config.primes.len());
        println!("  Max depth: {}", config.max_depth);
        println!("  Estimated security: {}-bit", config.estimated_security());

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_modulus_chain() {
        let primes = vec![998244353, 985661441, 754974721];
        let mut chain = ModulusChain::new(primes);

        assert_eq!(chain.level, 2);
        assert_eq!(chain.remaining_depth(), 2);

        chain.drop_level();
        assert_eq!(chain.level, 1);
        assert_eq!(chain.remaining_depth(), 1);
    }

    #[test]
    fn test_primes_are_ntt_compatible() {
        let n = 8192usize;

        for &p in &PRODUCTION_PRIMES_30BIT {
            assert_eq!(
                (p - 1) % (2 * n as u64),
                0,
                "Prime {} not NTT-compatible for N={}",
                p,
                n
            );
        }
    }

    #[test]
    fn test_primes_are_coprime() {
        for (i, &a) in PRODUCTION_PRIMES_30BIT.iter().enumerate() {
            for &b in PRODUCTION_PRIMES_30BIT.iter().skip(i + 1) {
                assert_ne!(a, b, "Duplicate primes");
            }
        }
    }

    #[test]
    fn test_production_30bit_primes_are_prime() {
        use crate::params::primes::is_prime;
        for (i, &p) in PRODUCTION_PRIMES_30BIT.iter().enumerate() {
            assert!(
                is_prime(p),
                "PRODUCTION_PRIMES_30BIT[{}] = {} is NOT prime",
                i,
                p
            );
        }
    }

    #[test]
    fn test_verified_51bit_primes_are_prime() {
        use crate::params::primes::is_prime;
        for (i, &p) in VERIFIED_PRIMES_51BIT.iter().enumerate() {
            assert!(
                is_prime(p),
                "VERIFIED_PRIMES_51BIT[{}] = {} is NOT prime",
                i,
                p
            );
        }
    }

    #[test]
    fn test_verified_51bit_ntt_compatible() {
        for &p in &VERIFIED_PRIMES_51BIT {
            assert_eq!(
                (p - 1) % 16384,
                0,
                "51-bit prime {} not NTT-compatible (q ≢ 1 mod 16384)",
                p
            );
        }
    }

    /// All PRODUCTION_PRIMES_30BIT must satisfy q ≡ 1 (mod 65536) for N=32768.
    /// The high_security() config uses N=32768, so this is a hard requirement.
    #[test]
    fn test_production_30bit_ntt_compatible_n32768() {
        for (i, &p) in PRODUCTION_PRIMES_30BIT.iter().enumerate() {
            assert_eq!(
                (p - 1) % 65536,
                0,
                "PRODUCTION_PRIMES_30BIT[{}] = {} not NTT-compatible for N=32768 (q ≢ 1 mod 65536)",
                i,
                p
            );
        }
    }
}
