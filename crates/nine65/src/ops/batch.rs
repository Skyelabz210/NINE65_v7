//! Batching Encoder for Packing Multiple Values
//!
//! Provides efficient batch encoding of multiple values into a single ciphertext.
//! This enables processing up to N values in parallel with homomorphic operations.
//!
//! ## Encoding Modes
//!
//! ### Coefficient Batching (Default - Works with all parameters)
//! - Packs values into polynomial coefficients using `round(q·m/t)` per value
//! - Supports up to N values per ciphertext
//! - Homomorphic add/sub work coefficient-wise
//! - Homomorphic mul results in polynomial product (not element-wise!)
//!
//! ### SIMD Slot Batching (Requires `t ≡ 1 (mod 2N)` - Future enhancement)
//! - Uses CRT isomorphism for true SIMD operations
//! - Homomorphic mul works element-wise on slots
//! - Not yet implemented (planned for v0.3)
//!
//! # Example
//!
//! ```ignore
//! let encoder = BatchEncoder::new(&config)?;
//!
//! // Pack up to N values into one ciphertext
//! let values = vec![10, 20, 30, 40];
//! let poly = encoder.encode(&values)?;
//!
//! // After homomorphic add, decode back
//! let decoded = encoder.decode(&result_poly, values.len());
//! // For add: decoded = [10+a, 20+b, 30+c, 40+d] where [a,b,c,d] was added
//! ```

use crate::errors::{Nine65Error, Nine65Result};
use crate::params::FHEConfig;
use crate::ring::RingPolynomial;

/// Batch Encoder for packing multiple values
///
/// Encodes multiple values into polynomial coefficients for batch homomorphic operations.
/// Each coefficient stores `round(q · value[i] / t)`.
///
/// ## Capacity
/// - Supports up to N values per ciphertext (where N is polynomial degree)
/// - For N=1024, can pack 1024 values into one ciphertext
///
/// ## Homomorphic Properties
/// - **Add/Sub**: Work coefficient-wise (SIMD-like for add/sub)
/// - **Mul**: Results in polynomial product (convolution, NOT element-wise)
///
/// For true SIMD multiplication, use slot-based batching when `t ≡ 1 (mod 2N)`
/// (planned for future release).
#[derive(Clone, Debug)]
pub struct BatchEncoder {
    /// Polynomial degree N
    n: usize,
    /// Plaintext modulus t
    t: u64,
    /// Ciphertext modulus q
    q: u64,
}

impl BatchEncoder {
    /// Create a new batch encoder
    ///
    /// Works with any FHE configuration. For coefficient batching,
    /// no special requirements on `t` are needed.
    pub fn new(config: &FHEConfig) -> Nine65Result<Self> {
        Ok(Self {
            n: config.n,
            t: config.t,
            q: config.q,
        })
    }

    /// Check if config supports SIMD slot batching
    ///
    /// SIMD slot batching requires `t ≡ 1 (mod 2N)` for the polynomial ring
    /// to split into independent slots. Coefficient batching works regardless.
    pub fn supports_simd_slots(config: &FHEConfig) -> bool {
        let m = 2 * config.n;
        (config.t - 1).is_multiple_of(m as u64)
    }

    /// Get maximum number of values that can be packed
    pub fn capacity(&self) -> usize {
        self.n
    }

    /// Get polynomial degree
    pub fn degree(&self) -> usize {
        self.n
    }

    /// Encode values into polynomial coefficients
    ///
    /// Each value is rounded onto the q/t plaintext lattice and placed in a
    /// coefficient.
    ///
    /// # Arguments
    /// * `values` - Values to encode (each must be < t)
    ///
    /// # Errors
    /// Returns error if values.len() > n or any value >= t
    pub fn encode(&self, values: &[u64]) -> Nine65Result<RingPolynomial> {
        if values.len() > self.n {
            return Err(Nine65Error::TooManySlotValues {
                got: values.len(),
                max: self.n,
            });
        }

        let mut coeffs = vec![0u64; self.n];

        for (i, &v) in values.iter().enumerate() {
            if v >= self.t {
                return Err(Nine65Error::MessageOutOfBounds {
                    message: v,
                    modulus: self.t,
                });
            }
            coeffs[i] = super::encrypt::encode_bfv_coefficient(v, self.q, self.t);
        }

        Ok(RingPolynomial::from_coeffs(coeffs, self.q))
    }

    /// Decode polynomial coefficients to values
    ///
    /// Extracts the first `count` values from polynomial coefficients.
    /// Each coefficient is unscaled: `v[i] = round(coeff[i] · t / q)`
    ///
    /// # Arguments
    /// * `poly` - Polynomial to decode
    /// * `count` - Number of values to extract
    pub fn decode(&self, poly: &RingPolynomial, count: usize) -> Vec<u64> {
        let count = count.min(self.n);

        poly.coeffs[..count]
            .iter()
            .map(|&c| super::encrypt::decode_bfv_coefficient(c, self.q, self.t))
            .collect()
    }

    /// Decode all coefficients
    pub fn decode_all(&self, poly: &RingPolynomial) -> Vec<u64> {
        self.decode(poly, self.n)
    }

    /// Encode with automatic zero-padding to full degree
    ///
    /// Same as `encode`, but explicitly documents that trailing coefficients
    /// are zero-padded.
    pub fn encode_padded(&self, values: &[u64]) -> Nine65Result<RingPolynomial> {
        self.encode(values)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a test config
    fn test_config() -> FHEConfig {
        FHEConfig {
            name: "batch_test",
            n: 1024,
            q: 132120577, // Prime ≡ 1 (mod 2048) for NTT
            t: 65537,     // Fermat prime
            eta: 3,
            primes: vec![132120577],
            security_bits: 128,
        }
    }

    #[test]
    fn test_batch_encoder_creation() {
        let config = test_config();
        let encoder = BatchEncoder::new(&config).unwrap();

        println!("BatchEncoder created successfully:");
        println!("  N = {}", encoder.n);
        println!("  capacity = {}", encoder.capacity());
        println!("  t = {}", encoder.t);

        assert_eq!(encoder.capacity(), config.n);
    }

    #[test]
    fn test_simd_support_check() {
        let config = test_config();
        let supports_simd = BatchEncoder::supports_simd_slots(&config);

        // t=65537, N=1024, 2N=2048
        // 65536 = 32 * 2048, so 65537 equiv 1 (mod 2048) [OK]
        println!("SIMD slot support: {}", supports_simd);
        assert!(
            supports_simd,
            "Config should support SIMD slots: t={}, 2N={}",
            config.t,
            2 * config.n
        );
    }

    #[test]
    fn test_encode_decode_single() {
        let config = test_config();
        let encoder = BatchEncoder::new(&config).unwrap();

        // Encode single value
        let values = vec![42u64];
        let poly = encoder.encode(&values).unwrap();

        // Decode should recover the value
        let decoded = encoder.decode(&poly, 1);
        assert_eq!(
            decoded[0], 42,
            "First value should be 42, got {}",
            decoded[0]
        );
    }

    #[test]
    fn test_encode_decode_vector() {
        let config = test_config();
        let encoder = BatchEncoder::new(&config).unwrap();

        // Encode multiple values
        let values: Vec<u64> = (0..10).map(|i| i * 100).collect();
        let poly = encoder.encode(&values).unwrap();

        // Decode and verify
        let decoded = encoder.decode(&poly, values.len());
        assert_eq!(
            decoded, values,
            "Decoded values should match encoded values"
        );
    }

    #[test]
    fn test_encode_decode_full_capacity() {
        let config = test_config();
        let encoder = BatchEncoder::new(&config).unwrap();

        let mut values: Vec<u64> = (0..encoder.capacity())
            .map(|i| (i as u64 * 97 + 13) % config.t)
            .collect();
        values[0] = config.t - 1;

        let poly = encoder.encode(&values).unwrap();
        let decoded = encoder.decode(&poly, values.len());

        assert_eq!(
            decoded, values,
            "Every batch coefficient must round-trip exactly"
        );
    }

    #[test]
    fn test_encode_too_many_values() {
        let config = test_config();
        let encoder = BatchEncoder::new(&config).unwrap();

        // Try to encode more values than capacity
        let too_many: Vec<u64> = (0..encoder.capacity() + 10).map(|i| i as u64).collect();

        let result = encoder.encode(&too_many);
        assert!(result.is_err(), "Should fail with too many values");

        if let Err(e) = result {
            assert!(e.is_batching_error(), "Should be batching error");
        }
    }

    #[test]
    fn test_encode_value_out_of_range() {
        let config = test_config();
        let encoder = BatchEncoder::new(&config).unwrap();

        // Try to encode value >= t
        let invalid = vec![encoder.t + 1];

        let result = encoder.encode(&invalid);
        assert!(result.is_err(), "Should fail with value >= t");
    }

    #[test]
    fn test_decode_all() {
        let config = test_config();
        let encoder = BatchEncoder::new(&config).unwrap();

        let values = vec![1u64, 2, 3, 4, 5];
        let poly = encoder.encode(&values).unwrap();

        let all = encoder.decode_all(&poly);
        assert_eq!(all.len(), encoder.capacity());
        assert_eq!(&all[..5], &values[..]);

        // Remaining should be zeros
        for &v in &all[5..] {
            assert_eq!(v, 0, "Padded values should be 0");
        }
    }

    #[test]
    fn test_light_config() {
        // Test with deterministic local config
        let config = test_config();
        let encoder = BatchEncoder::new(&config).unwrap();

        let values = vec![10u64, 20, 30];
        let poly = encoder.encode(&values).unwrap();
        let decoded = encoder.decode(&poly, values.len());

        assert_eq!(decoded, values);
        println!("Light config batch encoding works!");
    }

    #[test]
    fn test_zero_values() {
        let config = test_config();
        let encoder = BatchEncoder::new(&config).unwrap();

        // All zeros
        let values = vec![0u64; 100];
        let poly = encoder.encode(&values).unwrap();
        let decoded = encoder.decode(&poly, values.len());

        assert_eq!(decoded, values, "Zero values should roundtrip");
    }

    #[test]
    fn test_boundary_values() {
        let config = test_config();
        let encoder = BatchEncoder::new(&config).unwrap();

        let values = vec![0, 1, 100, 1000, config.t - 1];
        let poly = encoder.encode(&values).unwrap();
        let decoded = encoder.decode(&poly, values.len());

        assert_eq!(decoded, values, "Boundary values should roundtrip");
    }
}
