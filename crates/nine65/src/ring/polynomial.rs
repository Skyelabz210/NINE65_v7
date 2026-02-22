//! Ring Polynomial - Operations in Z_q[X]/(X^N + 1)
//!
//! BFV FHE operates on polynomials in the quotient ring R_q = Z_q[X]/(X^N + 1).
//! This module provides the polynomial abstraction over the NTT engine.

#[cfg(feature = "ntt_fft")]
use crate::arithmetic::NTTEngineFFT as NTTEngine;

#[cfg(not(feature = "ntt_fft"))]
use crate::arithmetic::NTTEngine;
use crate::entropy::{FheRng, ShadowHarvester};
use crate::errors::{Nine65Error, Nine65Result};
use zeroize::Zeroize;

const MAX_RING_POLY_DEGREE: usize = 32768;

/// Domain tag for polynomial representation.
///
/// Prevents accidental mixed-domain arithmetic. NTT-domain polynomials must
/// be inverse-transformed before coefficient-domain operations, and vice versa.
///
/// # Invariant
/// `RingPolynomial` is **always** in `Coefficient` domain. NTT-domain data
/// lives as bare `Vec<u64>` inside the NTT engine and RNS limbs. This enum
/// exists for use in higher-level wrappers and RNS domain tracking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolyDomain {
    /// Standard coefficient representation in Z_q[X]/(X^N + 1)
    Coefficient,
    /// Number Theoretic Transform (evaluation) domain
    Ntt,
}

/// Polynomial in R_q = Z_q[X]/(X^N + 1)
///
/// # Domain Invariant
/// `RingPolynomial` is **always** in the coefficient domain. The NTT
/// transform is applied and removed internally by the NTT engine within
/// `mul()` and `mul_ct()`. If you need to track NTT-domain data, use
/// the `PolyDomain` enum with bare `Vec<u64>` representations.
///
/// Implements `Zeroize` for secure memory clearing of sensitive data.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", derive(bincode::Encode, bincode::Decode))]
pub struct RingPolynomial {
    /// Coefficients in standard (coefficient) form — never NTT domain.
    pub coeffs: Vec<u64>,
    /// The modulus
    pub q: u64,
}

impl Zeroize for RingPolynomial {
    fn zeroize(&mut self) {
        self.coeffs.zeroize();
    }
}

impl RingPolynomial {
    /// Create a zero polynomial
    pub fn zero(n: usize, q: u64) -> Self {
        Self {
            coeffs: vec![0; n],
            q,
        }
    }

    /// Create from coefficients
    pub fn from_coeffs(coeffs: Vec<u64>, q: u64) -> Self {
        let reduced: Vec<u64> = coeffs.iter().map(|&c| c % q).collect();
        Self { coeffs: reduced, q }
    }

    /// Create from signed coefficients
    pub fn from_signed(coeffs: &[i64], q: u64) -> Self {
        let unsigned: Vec<u64> = coeffs
            .iter()
            .map(|&c| ShadowHarvester::signed_to_unsigned(c, q))
            .collect();
        Self {
            coeffs: unsigned,
            q,
        }
    }

    /// Get polynomial degree (N)
    pub fn degree(&self) -> usize {
        self.coeffs.len()
    }

    /// Validate polynomial structure and bounds
    ///
    /// # Security
    /// Use after deserialization to prevent:
    /// - DoS via excessive allocation (bounded by MAX_RING_POLY_DEGREE)
    /// - Inconsistent modulus/degree
    /// - Out-of-range coefficients
    pub fn validate(&self, expected_n: usize, expected_q: u64) -> Nine65Result<()> {
        if self.coeffs.len() > MAX_RING_POLY_DEGREE {
            return Err(Nine65Error::InvalidParameter {
                message: format!(
                    "RingPolynomial: degree {} exceeds maximum {}",
                    self.coeffs.len(),
                    MAX_RING_POLY_DEGREE
                ),
            });
        }

        if self.coeffs.len() != expected_n {
            return Err(Nine65Error::InvalidPolynomialDegree {
                got: self.coeffs.len(),
                expected: expected_n,
            });
        }

        if self.q != expected_q {
            return Err(Nine65Error::ConfigError {
                message: format!(
                    "RingPolynomial: modulus {} != expected {}",
                    self.q, expected_q
                ),
            });
        }

        for (i, &coeff) in self.coeffs.iter().enumerate() {
            if coeff >= self.q {
                return Err(Nine65Error::ConfigError {
                    message: format!(
                        "RingPolynomial: coeff[{}] = {} >= q = {} (out of bounds)",
                        i, coeff, self.q
                    ),
                });
            }
        }

        Ok(())
    }

    /// Add two polynomials
    ///
    /// # Panics (debug only)
    /// Panics if moduli or degrees don't match — catches mixed-parameter errors.
    pub fn add(&self, other: &Self, ntt: &NTTEngine) -> Self {
        debug_assert_eq!(self.q, other.q, "RingPolynomial::add: modulus mismatch ({} vs {})", self.q, other.q);
        debug_assert_eq!(self.coeffs.len(), other.coeffs.len(), "RingPolynomial::add: degree mismatch ({} vs {})", self.coeffs.len(), other.coeffs.len());
        let coeffs = ntt.add(&self.coeffs, &other.coeffs);
        Self { coeffs, q: self.q }
    }

    /// Subtract two polynomials
    ///
    /// # Panics (debug only)
    /// Panics if moduli or degrees don't match.
    pub fn sub(&self, other: &Self, ntt: &NTTEngine) -> Self {
        debug_assert_eq!(self.q, other.q, "RingPolynomial::sub: modulus mismatch ({} vs {})", self.q, other.q);
        debug_assert_eq!(self.coeffs.len(), other.coeffs.len(), "RingPolynomial::sub: degree mismatch ({} vs {})", self.coeffs.len(), other.coeffs.len());
        let coeffs = ntt.sub(&self.coeffs, &other.coeffs);
        Self { coeffs, q: self.q }
    }

    /// Negate polynomial
    pub fn neg(&self, ntt: &NTTEngine) -> Self {
        let coeffs = ntt.neg(&self.coeffs);
        Self { coeffs, q: self.q }
    }

    /// Multiply two polynomials using NTT
    ///
    /// # Panics (debug only)
    /// Panics if moduli or degrees don't match.
    pub fn mul(&self, other: &Self, ntt: &NTTEngine) -> Self {
        debug_assert_eq!(self.q, other.q, "RingPolynomial::mul: modulus mismatch ({} vs {})", self.q, other.q);
        debug_assert_eq!(self.coeffs.len(), other.coeffs.len(), "RingPolynomial::mul: degree mismatch ({} vs {})", self.coeffs.len(), other.coeffs.len());
        let coeffs = ntt.multiply(&self.coeffs, &other.coeffs);
        Self { coeffs, q: self.q }
    }

    /// Constant-time polynomial multiplication using NTT
    ///
    /// Uses constant-time Barrett reduction to prevent timing side-channels.
    /// Use this variant when one or both operands depend on secret data.
    ///
    /// # Panics (debug only)
    /// Panics if moduli or degrees don't match.
    pub fn mul_ct(&self, other: &Self, ntt: &NTTEngine) -> Self {
        debug_assert_eq!(self.q, other.q, "RingPolynomial::mul_ct: modulus mismatch ({} vs {})", self.q, other.q);
        debug_assert_eq!(self.coeffs.len(), other.coeffs.len(), "RingPolynomial::mul_ct: degree mismatch ({} vs {})", self.coeffs.len(), other.coeffs.len());
        let coeffs = ntt.multiply_ct(&self.coeffs, &other.coeffs);
        Self { coeffs, q: self.q }
    }

    /// Scalar multiplication
    pub fn scalar_mul(&self, scalar: u64, ntt: &NTTEngine) -> Self {
        let coeffs = ntt.scalar_mul(&self.coeffs, scalar);
        Self { coeffs, q: self.q }
    }

    /// Exact scalar division (only works if all coeffs divisible by scalar)
    /// This is K-Elimination exact division
    pub fn exact_scalar_div(&self, scalar: u64) -> Option<Self> {
        let mut result = vec![0u64; self.coeffs.len()];
        for (i, &c) in self.coeffs.iter().enumerate() {
            if c % scalar != 0 {
                return None;
            }
            result[i] = c / scalar;
        }
        Some(Self {
            coeffs: result,
            q: self.q,
        })
    }

    /// Rounded scalar division: round(coeff / scalar)
    pub fn rounded_scalar_div(&self, scalar: u64) -> Self {
        let half = scalar / 2;
        let coeffs: Vec<u64> = self.coeffs.iter().map(|&c| (c + half) / scalar).collect();
        Self { coeffs, q: self.q }
    }

    /// Generate random polynomial with CBD noise
    pub fn random_cbd(n: usize, q: u64, eta: usize, harvester: &mut ShadowHarvester) -> Self {
        let signed = harvester.cbd_vector(n, eta);
        Self::from_signed(&signed, q)
    }

    /// Generate random ternary polynomial
    pub fn random_ternary(n: usize, q: u64, harvester: &mut ShadowHarvester) -> Self {
        let signed = harvester.ternary_vector(n);
        Self::from_signed(&signed, q)
    }

    /// Generate uniform random polynomial
    pub fn random_uniform(n: usize, q: u64, harvester: &mut ShadowHarvester) -> Self {
        let coeffs: Vec<u64> = (0..n).map(|_| harvester.uniform(q)).collect();
        Self { coeffs, q }
    }

    // =========================================================================
    // GENERIC RNG METHODS (for secure/flexible entropy sources)
    // =========================================================================

    /// Generate random polynomial with CBD noise using any FheRng
    ///
    /// For production encryption, use with `SecureRng`.
    /// For testing, use with `ShadowHarvester`.
    pub fn random_cbd_rng<R: FheRng>(n: usize, q: u64, eta: usize, rng: &mut R) -> Self {
        let signed = rng.cbd_vector(n, eta);
        Self::from_signed(&signed, q)
    }

    /// Generate random ternary polynomial using any FheRng
    ///
    /// For production encryption, use with `SecureRng`.
    /// For testing, use with `ShadowHarvester`.
    pub fn random_ternary_rng<R: FheRng>(n: usize, q: u64, rng: &mut R) -> Self {
        let signed = rng.ternary_vector(n);
        Self::from_signed(&signed, q)
    }

    /// Generate uniform random polynomial using any FheRng
    ///
    /// For production encryption, use with `SecureRng`.
    /// For testing, use with `ShadowHarvester`.
    pub fn random_uniform_rng<R: FheRng>(n: usize, q: u64, rng: &mut R) -> Self {
        let coeffs: Vec<u64> = (0..n).map(|_| rng.uniform(q)).collect();
        Self { coeffs, q }
    }

    /// Infinity norm: max absolute coefficient
    pub fn infinity_norm(&self) -> u64 {
        self.coeffs
            .iter()
            .map(|&c| {
                let half_q = self.q / 2;
                if c > half_q {
                    self.q - c
                } else {
                    c
                }
            })
            .max()
            .unwrap_or(0)
    }

    /// Get coefficient as signed value
    pub fn get_signed(&self, i: usize) -> i64 {
        let c = self.coeffs[i];
        let half_q = self.q / 2;
        if c > half_q {
            -((self.q - c) as i64)
        } else {
            c as i64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PRIME: u64 = 998244353;

    #[test]
    fn test_ring_add_commutative() {
        let ntt = NTTEngine::new(TEST_PRIME, 8);

        let a = RingPolynomial::from_coeffs(vec![1, 2, 3, 4, 5, 6, 7, 8], TEST_PRIME);
        let b = RingPolynomial::from_coeffs(vec![8, 7, 6, 5, 4, 3, 2, 1], TEST_PRIME);

        let ab = a.add(&b, &ntt);
        let ba = b.add(&a, &ntt);

        assert_eq!(ab.coeffs, ba.coeffs);
    }

    #[test]
    fn test_ring_mul_associative() {
        let ntt = NTTEngine::new(TEST_PRIME, 8);

        let a = RingPolynomial::from_coeffs(vec![1, 2, 0, 0, 0, 0, 0, 0], TEST_PRIME);
        let b = RingPolynomial::from_coeffs(vec![3, 4, 0, 0, 0, 0, 0, 0], TEST_PRIME);
        let c = RingPolynomial::from_coeffs(vec![5, 6, 0, 0, 0, 0, 0, 0], TEST_PRIME);

        let ab = a.mul(&b, &ntt);
        let ab_c = ab.mul(&c, &ntt);

        let bc = b.mul(&c, &ntt);
        let a_bc = a.mul(&bc, &ntt);

        assert_eq!(ab_c.coeffs, a_bc.coeffs);
    }

    #[test]
    fn test_ring_negacyclic() {
        let ntt = NTTEngine::new(TEST_PRIME, 4);

        // x^4 = -1 in X^4 + 1
        // Test: x^3 * x^2 = x^5 = x * x^4 = -x
        let x3 = RingPolynomial::from_coeffs(vec![0, 0, 0, 1], TEST_PRIME); // x^3
        let x2 = RingPolynomial::from_coeffs(vec![0, 0, 1, 0], TEST_PRIME); // x^2

        let result = x3.mul(&x2, &ntt);

        // x^5 = x * (-1) = -x, so coeff[1] = q-1
        assert_eq!(result.coeffs[0], 0);
        assert_eq!(result.coeffs[1], TEST_PRIME - 1); // -1 mod q
        assert_eq!(result.coeffs[2], 0);
        assert_eq!(result.coeffs[3], 0);
    }

    #[test]
    fn test_negation() {
        let ntt = NTTEngine::new(TEST_PRIME, 4);

        let a = RingPolynomial::from_coeffs(vec![1, 2, 3, 4], TEST_PRIME);
        let neg_a = a.neg(&ntt);
        let sum = a.add(&neg_a, &ntt);

        // a + (-a) should be zero
        assert_eq!(sum.coeffs, vec![0, 0, 0, 0]);
    }

    #[test]
    fn test_scalar_mul() {
        let ntt = NTTEngine::new(TEST_PRIME, 4);

        let a = RingPolynomial::from_coeffs(vec![1, 2, 3, 4], TEST_PRIME);
        let scaled = a.scalar_mul(10, &ntt);

        assert_eq!(scaled.coeffs, vec![10, 20, 30, 40]);
    }

    #[test]
    fn test_exact_scalar_div() {
        let a = RingPolynomial::from_coeffs(vec![10, 20, 30, 40], TEST_PRIME);

        let result = a.exact_scalar_div(10);
        assert!(result.is_some());
        assert_eq!(result.unwrap().coeffs, vec![1, 2, 3, 4]);

        // Non-divisible should return None
        let b = RingPolynomial::from_coeffs(vec![11, 20, 30, 40], TEST_PRIME);
        assert!(b.exact_scalar_div(10).is_none());
    }

    #[test]
    fn test_signed_coeffs() {
        let poly = RingPolynomial::from_signed(&[-1, 0, 1, -2], TEST_PRIME);

        assert_eq!(poly.get_signed(0), -1);
        assert_eq!(poly.get_signed(1), 0);
        assert_eq!(poly.get_signed(2), 1);
        assert_eq!(poly.get_signed(3), -2);
    }

    #[test]
    fn test_infinity_norm() {
        let poly = RingPolynomial::from_signed(&[-5, 3, -2, 4], TEST_PRIME);

        assert_eq!(poly.infinity_norm(), 5);
    }

    #[test]
    fn test_ternary_polynomial() {
        let mut harvester = ShadowHarvester::with_seed(42);
        let poly = RingPolynomial::random_ternary(1024, TEST_PRIME, &mut harvester);

        // All coefficients should be -1, 0, or 1
        for i in 0..1024 {
            let signed = poly.get_signed(i);
            assert!((-1..=1).contains(&signed), "Invalid ternary: {}", signed);
        }
    }
}
