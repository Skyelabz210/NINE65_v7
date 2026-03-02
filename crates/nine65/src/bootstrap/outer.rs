//! Layer 2: RLWE Outer Encryption
//!
//! Wraps masked ciphertext coefficients in a fresh RLWE encryption under
//! a locally-generated outer secret key (`sk_outer`). This layer provides
//! computational security under the Ring-LWE assumption.
//!
//! # Security Properties
//!
//! - **RLWE hardness**: Memory snapshots observe only RLWE ciphertexts
//! - **Key independence**: `sk_outer` is independent of the working key
//! - **NTT on masked data**: During outer decryption (Step A), NTT butterflies
//!   process masked values -- power trace correlates with random mask, not structure
//! - **Per-bootstrap rotation**: Fresh `sk_outer` per bootstrap eliminates
//!   cross-bootstrap noise correlation
//!
//! # Design
//!
//! The outer layer encrypts individual polynomials (not full BFV ciphertexts).
//! Each coefficient polynomial of the BFV ciphertext is independently wrapped:
//!
//! ```text
//!   outer_ct_i = RLWE.Enc(sk_outer, masked_poly_i)
//!              = (a_i * sk_outer + e_i + masked_poly_i, a_i)
//! ```
//!
//! This keeps the outer layer lightweight -- we're encrypting polynomials,
//! not performing homomorphic operations inside the outer layer.

use crate::arithmetic::NTTEngine;

use crate::entropy::SecureRng;
use crate::ring::RingPolynomial;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Outer RLWE secret key -- generated fresh per bootstrap (or per session).
///
/// Uses `ZeroizeOnDrop` to ensure the key is securely cleared from memory
/// after the bootstrap procedure completes.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct OuterSecretKey {
    /// The secret polynomial (ternary distribution)
    s: RingPolynomial,
}

/// Outer RLWE ciphertext wrapping a single polynomial.
///
/// Structure: (b, a) where b = a * s + e + m (mod q)
/// Decrypt: m approx b - a * s = e + m -> m when |e| < q/2
#[derive(Clone, Debug)]
pub struct OuterCiphertext {
    /// b = a * s_outer + e + message
    pub b: RingPolynomial,
    /// a = random polynomial
    pub a: RingPolynomial,
}

/// The outer RLWE encryption/decryption layer.
///
/// Manages the outer key lifecycle and provides encrypt/decrypt for
/// individual polynomials. The key is generated fresh per bootstrap
/// in Tier 1 deployments, or per session in Tier 2.
pub struct OuterLayer {
    /// Outer secret key (zeroized on drop)
    sk: OuterSecretKey,
    /// Ring dimension
    n: usize,
    /// Ciphertext modulus
    q: u64,
    /// Error distribution parameter (CBD)
    eta: usize,
}

impl OuterLayer {
    /// Create a new outer layer with a fresh random key.
    ///
    /// Generates `sk_outer` using OS CSPRNG. This is the per-bootstrap
    /// key rotation path for Tier 1 deployments.
    pub fn new(n: usize, q: u64, eta: usize) -> Self {
        let sk = Self::generate_key(n, q);
        Self { sk, n, q, eta }
    }

    /// Generate a fresh outer secret key using OS CSPRNG.
    ///
    /// The key is ternary (coefficients in {-1, 0, 1}) matching
    /// the standard RLWE key distribution.
    fn generate_key(n: usize, q: u64) -> OuterSecretKey {
        let mut rng = SecureRng::new();
        let coeffs: Vec<u64> = (0..n)
            .map(|_| {
                let r = rng.random_u64_bounded(3);
                match r {
                    0 => 0,
                    1 => 1,
                    2 => q - 1, // -1 mod q
                    _ => unreachable!(),
                }
            })
            .collect();
        OuterSecretKey {
            s: RingPolynomial { coeffs, q },
        }
    }

    /// Encrypt a polynomial under the outer key.
    ///
    /// Produces RLWE ciphertext: (b, a) where b = a*s + e + m
    ///
    /// The input polynomial is typically already masked (Layer 1),
    /// so this encrypts a uniformly random-looking value.
    pub fn encrypt(&self, poly: &RingPolynomial, ntt: &NTTEngine) -> OuterCiphertext {
        let mut rng = SecureRng::new();

        // a <- uniform random polynomial
        let a = RingPolynomial::random_uniform_rng(self.n, self.q, &mut rng);

        // e <- CBD error distribution
        let e = RingPolynomial::random_cbd_rng(self.n, self.q, self.eta, &mut rng);

        // b = a * s + e + m
        let as_prod = a.mul_ct(&self.sk.s, ntt);
        let as_plus_e = as_prod.add(&e, ntt);
        let b = as_plus_e.add(poly, ntt);

        OuterCiphertext { b, a }
    }

    /// Decrypt an outer ciphertext to recover the polynomial.
    ///
    /// Computes: m approx b - a*s = (a*s + e + m) - a*s = e + m
    ///
    /// For small error |e|, this recovers m exactly (as polynomial mod q).
    /// The error e does NOT need to be removed -- it becomes part of the
    /// bootstrap's output noise, which is bounded by the noise analysis
    /// in OuterDecryptionNoise.lean.
    ///
    /// # Side-Channel Note
    ///
    /// This operation uses NTT multiplication (a*s), which involves butterfly
    /// operations. However, because the input polynomial is masked (Layer 1),
    /// the NTT processes uniformly random data. The power trace during this
    /// decryption correlates with the mask, not with the actual ciphertext
    /// structure. This is the key insight of the Three-Lock design.
    pub fn decrypt(&self, ct: &OuterCiphertext, ntt: &NTTEngine) -> RingPolynomial {
        // m + e = b - a * s
        let as_prod = ct.a.mul_ct(&self.sk.s, ntt);
        ct.b.sub(&as_prod, ntt)
    }

    /// Rotate the outer key (generate a fresh one).
    ///
    /// Call this between bootstraps for Tier 1 (maximum security) or
    /// between sessions for Tier 2 (balanced security/performance).
    ///
    /// The old key is securely zeroized via `ZeroizeOnDrop`.
    pub fn rotate_key(&mut self) {
        self.sk = Self::generate_key(self.n, self.q);
    }

    /// Get the ring dimension
    pub fn ring_dimension(&self) -> usize {
        self.n
    }

    /// Get the modulus
    pub fn modulus(&self) -> u64 {
        self.q
    }
}

/// Pair of outer ciphertexts wrapping a BFV ciphertext's two components.
#[derive(Clone, Debug)]
pub struct OuterCiphertextPair {
    /// Outer encryption of (masked) c0
    pub outer_c0: OuterCiphertext,
    /// Outer encryption of (masked) c1
    pub outer_c1: OuterCiphertext,
}

impl OuterCiphertextPair {
    /// Encrypt both components of a BFV ciphertext.
    pub fn encrypt(
        layer: &OuterLayer,
        c0: &RingPolynomial,
        c1: &RingPolynomial,
        ntt: &NTTEngine,
    ) -> Self {
        Self {
            outer_c0: layer.encrypt(c0, ntt),
            outer_c1: layer.encrypt(c1, ntt),
        }
    }

    /// Decrypt both components.
    pub fn decrypt(&self, layer: &OuterLayer, ntt: &NTTEngine) -> (RingPolynomial, RingPolynomial) {
        (
            layer.decrypt(&self.outer_c0, ntt),
            layer.decrypt(&self.outer_c1, ntt),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_Q: u64 = 998244353;
    const TEST_N: usize = 64;
    const TEST_ETA: usize = 3;

    fn test_ntt() -> NTTEngine {
        NTTEngine::new(TEST_Q, TEST_N)
    }

    #[test]
    fn test_outer_encrypt_decrypt_roundtrip() {
        let ntt = test_ntt();
        let layer = OuterLayer::new(TEST_N, TEST_Q, TEST_ETA);

        let poly = RingPolynomial::from_coeffs(vec![42; TEST_N], TEST_Q);

        let ct = layer.encrypt(&poly, &ntt);
        let recovered = layer.decrypt(&ct, &ntt);

        // The recovered polynomial should be close to the original
        // (difference is the small error e from RLWE encryption)
        for i in 0..TEST_N {
            let diff = if recovered.coeffs[i] >= poly.coeffs[i] {
                recovered.coeffs[i] - poly.coeffs[i]
            } else {
                poly.coeffs[i] - recovered.coeffs[i]
            };
            let signed_diff = std::cmp::min(diff, TEST_Q - diff);
            assert!(
                signed_diff < 1000,
                "Outer decrypt error too large at coeff {}: diff={}",
                i,
                signed_diff
            );
        }
    }

    #[test]
    fn test_outer_different_encryptions() {
        let ntt = test_ntt();
        let layer = OuterLayer::new(TEST_N, TEST_Q, TEST_ETA);

        let poly = RingPolynomial::from_coeffs(vec![42; TEST_N], TEST_Q);

        let ct1 = layer.encrypt(&poly, &ntt);
        let ct2 = layer.encrypt(&poly, &ntt);

        // Two encryptions of the same plaintext should produce different ciphertexts
        assert_ne!(
            ct1.b.coeffs, ct2.b.coeffs,
            "Outer encryption should be randomized"
        );
    }

    #[test]
    fn test_outer_key_rotation() {
        let ntt = test_ntt();
        let mut layer = OuterLayer::new(TEST_N, TEST_Q, TEST_ETA);

        let poly = RingPolynomial::from_coeffs(vec![42; TEST_N], TEST_Q);

        // Encrypt with first key
        let ct1 = layer.encrypt(&poly, &ntt);
        let dec1 = layer.decrypt(&ct1, &ntt);

        // Rotate key
        layer.rotate_key();

        // Old ciphertext should NOT decrypt correctly with new key
        let dec_wrong = layer.decrypt(&ct1, &ntt);

        let errors: usize = (0..TEST_N)
            .filter(|&i| {
                let diff = if dec_wrong.coeffs[i] >= poly.coeffs[i] {
                    dec_wrong.coeffs[i] - poly.coeffs[i]
                } else {
                    poly.coeffs[i] - dec_wrong.coeffs[i]
                };
                let signed_diff = std::cmp::min(diff, TEST_Q - diff);
                signed_diff > 1000
            })
            .count();

        assert!(
            errors > TEST_N / 2,
            "Wrong key should produce mostly garbage (got {} errors out of {})",
            errors,
            TEST_N
        );

        // New encryption with new key should work
        let ct2 = layer.encrypt(&poly, &ntt);
        let dec2 = layer.decrypt(&ct2, &ntt);

        for i in 0..TEST_N {
            let diff = if dec2.coeffs[i] >= poly.coeffs[i] {
                dec2.coeffs[i] - poly.coeffs[i]
            } else {
                poly.coeffs[i] - dec2.coeffs[i]
            };
            let signed_diff = std::cmp::min(diff, TEST_Q - diff);
            assert!(
                signed_diff < 1000,
                "New key decrypt should work: diff={} at coeff {}",
                signed_diff,
                i
            );
        }

        let _ = dec1; // suppress warning
    }

    #[test]
    fn test_outer_pair_roundtrip() {
        let ntt = test_ntt();
        let layer = OuterLayer::new(TEST_N, TEST_Q, TEST_ETA);

        let c0 = RingPolynomial::from_coeffs(vec![100; TEST_N], TEST_Q);
        let c1 = RingPolynomial::from_coeffs(vec![200; TEST_N], TEST_Q);

        let pair = OuterCiphertextPair::encrypt(&layer, &c0, &c1, &ntt);
        let (dec_c0, dec_c1) = pair.decrypt(&layer, &ntt);

        for i in 0..TEST_N {
            let diff0 = {
                let d = if dec_c0.coeffs[i] >= c0.coeffs[i] {
                    dec_c0.coeffs[i] - c0.coeffs[i]
                } else {
                    c0.coeffs[i] - dec_c0.coeffs[i]
                };
                std::cmp::min(d, TEST_Q - d)
            };
            assert!(diff0 < 1000, "c0 decrypt error at {}: {}", i, diff0);

            let diff1 = {
                let d = if dec_c1.coeffs[i] >= c1.coeffs[i] {
                    dec_c1.coeffs[i] - c1.coeffs[i]
                } else {
                    c1.coeffs[i] - dec_c1.coeffs[i]
                };
                std::cmp::min(d, TEST_Q - d)
            };
            assert!(diff1 < 1000, "c1 decrypt error at {}: {}", i, diff1);
        }
    }
}
