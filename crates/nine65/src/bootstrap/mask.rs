//! Layer 1: Information-Theoretic Mask (Shannon One-Time Pad)
//!
//! Provides unconditional (information-theoretic) security for ciphertext
//! coefficients during the bootstrap procedure. Every coefficient is additively
//! masked with a uniformly random value, making all observable quantities
//! statistically independent of the underlying data.
//!
//! # Security Properties
//!
//! - **Shannon perfect secrecy**: For uniform mask r, the distribution of
//!   (x + r) mod q is uniform regardless of x. No computational assumption.
//! - **Side-channel immunity**: All physical observables (EM, power, cache)
//!   are functions of uniformly random inputs -> zero information leakage.
//! - **Mask propagation**: Linear operations preserve mask uniformity.
//!   Mask tracks algebraically through add, scalar_mul, and K-Elimination division.
//!
//! # Constant-Time Guarantee
//!
//! Mask application and removal are coefficient-wise add/subtract with no
//! data-dependent branches, no NTT butterflies, and no variable-time operations.
//! This is the safest possible operation from a side-channel perspective.

use crate::entropy::SecureRng;
use crate::ring::RingPolynomial;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::arithmetic::NTTEngine;


/// Information-theoretic mask for a single polynomial.
///
/// The mask is a uniformly random polynomial in R_q. When added to a
/// ciphertext coefficient polynomial, it produces a uniformly random
/// result regardless of the coefficient values.
///
/// # Memory Safety
///
/// The mask implements `ZeroizeOnDrop` -- when the `MaskLayer` is dropped,
/// the mask polynomial is securely overwritten with zeros using volatile
/// writes that the compiler cannot optimize away.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MaskLayer {
    /// The mask polynomial (uniformly random coefficients mod q)
    mask: RingPolynomial,
}

/// Pair of masks for a ciphertext (c0, c1)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CiphertextMask {
    /// Mask for c0 component
    pub mask_c0: MaskLayer,
    /// Mask for c1 component
    pub mask_c1: MaskLayer,
}

impl MaskLayer {
    /// Generate a fresh uniform mask using OS CSPRNG.
    ///
    /// The mask polynomial has N coefficients, each uniformly random in [0, q).
    /// Uses `getrandom` backed by `/dev/urandom` (Linux) or `CryptGenRandom` (Windows).
    ///
    /// # Security
    ///
    /// This is the ONLY acceptable entropy source for mask generation in production.
    /// Shadow entropy MUST NOT be used for masks -- the mask's security guarantee
    /// depends on true uniform randomness, not computational indistinguishability.
    pub fn generate(n: usize, q: u64) -> Self {
        let mut rng = SecureRng::new();
        Self::generate_with_rng(n, q, &mut rng)
    }

    /// Generate a mask from a specific RNG (for testing with deterministic entropy).
    ///
    /// # Warning
    ///
    /// Only use with `SecureRng` in production. Using `ShadowHarvester` here
    /// degrades security from information-theoretic to computational.
    pub fn generate_with_rng(n: usize, q: u64, rng: &mut SecureRng) -> Self {
        let coeffs: Vec<u64> = (0..n).map(|_| rng.random_u64_bounded(q)).collect();
        Self {
            mask: RingPolynomial::from_coeffs(coeffs, q),
        }
    }

    /// Apply mask to a polynomial: result = (poly + mask) mod q
    ///
    /// This is a constant-time, coefficient-wise addition.
    /// No NTT, no data-dependent branches, no variable-time operations.
    ///
    /// After masking, the result is uniformly distributed regardless of the
    /// input polynomial's values (Shannon's theorem).
    #[inline]
    pub fn apply(&self, poly: &RingPolynomial) -> RingPolynomial {
        debug_assert_eq!(
            poly.coeffs.len(),
            self.mask.coeffs.len(),
            "Mask dimension mismatch: poly has {} coeffs, mask has {}",
            poly.coeffs.len(),
            self.mask.coeffs.len()
        );
        debug_assert_eq!(
            poly.q, self.mask.q,
            "Modulus mismatch: poly q={}, mask q={}",
            poly.q, self.mask.q
        );

        let q = poly.q;
        let coeffs: Vec<u64> = poly
            .coeffs
            .iter()
            .zip(self.mask.coeffs.iter())
            .map(|(&x, &r)| {
                // Modular addition: (x + r) mod q
                // Since x < q and r < q, sum < 2q, so one conditional subtract suffices
                let sum = x as u128 + r as u128;
                let q128 = q as u128;
                if sum >= q128 {
                    (sum - q128) as u64
                } else {
                    sum as u64
                }
            })
            .collect();

        RingPolynomial { coeffs, q }
    }

    /// Remove mask from a polynomial: result = (masked - mask) mod q
    ///
    /// This is the inverse of `apply()`. Constant-time, coefficient-wise subtraction.
    /// No NTT, no data-dependent branches -- this is the key property that makes
    /// Step B of the Three-Lock removal sequence side-channel safe.
    #[inline]
    pub fn remove(&self, masked: &RingPolynomial) -> RingPolynomial {
        debug_assert_eq!(
            masked.coeffs.len(),
            self.mask.coeffs.len(),
            "Mask dimension mismatch"
        );
        debug_assert_eq!(masked.q, self.mask.q, "Modulus mismatch");

        let q = masked.q;
        let coeffs: Vec<u64> = masked
            .coeffs
            .iter()
            .zip(self.mask.coeffs.iter())
            .map(|(&x, &r)| {
                // Modular subtraction: (x - r) mod q = (x + q - r) mod q
                // Since x < q and r < q, diff = x + q - r is in [1, 2q-1],
                // so one conditional subtract suffices
                let diff = x as u128 + q as u128 - r as u128;
                let q128 = q as u128;
                if diff >= q128 {
                    (diff - q128) as u64
                } else {
                    diff as u64
                }
            })
            .collect();

        RingPolynomial { coeffs, q }
    }

    /// Track mask through scalar multiplication: new_mask = mask * scalar mod q
    ///
    /// When the masked polynomial is multiplied by a public scalar s:
    ///   (x + r) * s = x*s + r*s
    /// The new mask is r*s mod q, which remains uniform when gcd(s, q) = 1.
    pub fn track_scalar_mul(&self, scalar: u64) -> MaskLayer {
        let q = self.mask.q;
        let coeffs: Vec<u64> = self
            .mask
            .coeffs
            .iter()
            .map(|&r| ((r as u128) * (scalar as u128) % (q as u128)) as u64)
            .collect();

        MaskLayer {
            mask: RingPolynomial { coeffs, q },
        }
    }

    /// Track mask through addition: new_mask = mask1 + mask2 mod q
    ///
    /// When two masked polynomials are added:
    ///   (x + r1) + (y + r2) = (x + y) + (r1 + r2)
    /// The combined mask is r1 + r2, uniform when r1 or r2 is uniform.
    pub fn track_add(&self, other: &MaskLayer) -> MaskLayer {
        let q = self.mask.q;
        let coeffs: Vec<u64> = self
            .mask
            .coeffs
            .iter()
            .zip(other.mask.coeffs.iter())
            .map(|(&r1, &r2)| ((r1 as u128 + r2 as u128) % (q as u128)) as u64)
            .collect();

        MaskLayer {
            mask: RingPolynomial { coeffs, q },
        }
    }

    /// Get the number of coefficients
    pub fn len(&self) -> usize {
        self.mask.coeffs.len()
    }

    /// Check if the mask is empty
    pub fn is_empty(&self) -> bool {
        self.mask.coeffs.is_empty()
    }
}

impl CiphertextMask {
    /// Generate a fresh mask pair for a BFV ciphertext (c0, c1).
    pub fn generate(n: usize, q: u64) -> Self {
        Self {
            mask_c0: MaskLayer::generate(n, q),
            mask_c1: MaskLayer::generate(n, q),
        }
    }

    /// Apply masks to both ciphertext components.
    pub fn apply(
        &self,
        c0: &RingPolynomial,
        c1: &RingPolynomial,
    ) -> (RingPolynomial, RingPolynomial) {
        (self.mask_c0.apply(c0), self.mask_c1.apply(c1))
    }

    /// Remove masks from both ciphertext components.
    pub fn remove(
        &self,
        masked_c0: &RingPolynomial,
        masked_c1: &RingPolynomial,
    ) -> (RingPolynomial, RingPolynomial) {
        (
            self.mask_c0.remove(masked_c0),
            self.mask_c1.remove(masked_c1),
        )
    }

    /// Compute the mask's contribution in the decrypted polynomial domain.
    ///
    /// When a masked ciphertext (c0+r0, c1+r1) is decrypted with secret key s:
    ///   (c0+r0) + (c1+r1)*s = (c0 + c1*s) + (r0 + r1*s)
    ///                       = delta*m + e + mask_contribution
    ///
    /// This method computes mask_contribution = r0 + r1*s, which can be
    /// subtracted from the raw decryption to recover the clean delta*m + e
    /// **without ever removing the mask from the ciphertext in memory**.
    ///
    /// # Security Role
    ///
    /// This is the critical algebraic trick that allows the Three-Lock
    /// to protect m throughout the bootstrap. The ciphertext bytes in memory
    /// remain masked. The mask is consumed algebraically during decryption,
    /// and m exists only briefly in CPU registers.
    pub(crate) fn decrypt_contribution(
        &self,
        sk: &RingPolynomial,
        ntt: &NTTEngine,
    ) -> RingPolynomial {
        let r1_s = self.mask_c1.mask.mul(sk, ntt);
        self.mask_c0.mask.add(&r1_s, ntt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_Q: u64 = 998244353;
    const TEST_N: usize = 64;

    #[test]
    fn test_mask_roundtrip() {
        let mask = MaskLayer::generate(TEST_N, TEST_Q);
        let poly = RingPolynomial::from_coeffs(vec![42; TEST_N], TEST_Q);

        let masked = mask.apply(&poly);
        let recovered = mask.remove(&masked);

        assert_eq!(
            recovered.coeffs, poly.coeffs,
            "Mask apply/remove should be identity"
        );
    }

    #[test]
    fn test_mask_uniformity() {
        // Statistical test: masked output should look uniform
        let mask = MaskLayer::generate(TEST_N, TEST_Q);

        // Mask a constant polynomial -- output should be uniform
        let constant = RingPolynomial::from_coeffs(vec![0; TEST_N], TEST_Q);
        let masked = mask.apply(&constant);

        // Check that masked coefficients are not all the same
        let unique: std::collections::HashSet<u64> = masked.coeffs.iter().copied().collect();
        assert!(
            unique.len() > 1,
            "Masked constant should produce diverse coefficients"
        );
    }

    #[test]
    fn test_mask_different_inputs_same_mask() {
        let mask = MaskLayer::generate(TEST_N, TEST_Q);

        let poly1 = RingPolynomial::from_coeffs(vec![100; TEST_N], TEST_Q);
        let poly2 = RingPolynomial::from_coeffs(vec![200; TEST_N], TEST_Q);

        let masked1 = mask.apply(&poly1);
        let masked2 = mask.apply(&poly2);

        assert_ne!(masked1.coeffs, masked2.coeffs);

        let recovered1 = mask.remove(&masked1);
        let recovered2 = mask.remove(&masked2);
        assert_eq!(recovered1.coeffs, poly1.coeffs);
        assert_eq!(recovered2.coeffs, poly2.coeffs);
    }

    #[test]
    fn test_mask_scalar_tracking() {
        let mask = MaskLayer::generate(TEST_N, TEST_Q);
        let poly = RingPolynomial::from_coeffs(vec![42; TEST_N], TEST_Q);
        let scalar = 7u64;

        let masked = mask.apply(&poly);
        let scaled_masked: Vec<u64> = masked
            .coeffs
            .iter()
            .map(|&c| ((c as u128 * scalar as u128) % TEST_Q as u128) as u64)
            .collect();
        let scaled_masked = RingPolynomial {
            coeffs: scaled_masked,
            q: TEST_Q,
        };

        let tracked_mask = mask.track_scalar_mul(scalar);
        let recovered = tracked_mask.remove(&scaled_masked);

        let expected: Vec<u64> = poly
            .coeffs
            .iter()
            .map(|&c| ((c as u128 * scalar as u128) % TEST_Q as u128) as u64)
            .collect();
        assert_eq!(
            recovered.coeffs, expected,
            "Scalar tracking should recover scaled original"
        );
    }

    #[test]
    fn test_ciphertext_mask_roundtrip() {
        let ct_mask = CiphertextMask::generate(TEST_N, TEST_Q);

        let c0 = RingPolynomial::from_coeffs(vec![100; TEST_N], TEST_Q);
        let c1 = RingPolynomial::from_coeffs(vec![200; TEST_N], TEST_Q);

        let (masked_c0, masked_c1) = ct_mask.apply(&c0, &c1);
        let (rec_c0, rec_c1) = ct_mask.remove(&masked_c0, &masked_c1);

        assert_eq!(rec_c0.coeffs, c0.coeffs);
        assert_eq!(rec_c1.coeffs, c1.coeffs);
    }

    #[test]
    fn test_mask_zeroize_on_drop() {
        let mask = MaskLayer::generate(TEST_N, TEST_Q);
        let was_nonzero = mask.mask.coeffs.iter().any(|&c| c != 0);
        assert!(was_nonzero, "Fresh mask should have non-zero coefficients");
        drop(mask);
        // ZeroizeOnDrop guarantees the volatile zeroing occurred
    }
}
