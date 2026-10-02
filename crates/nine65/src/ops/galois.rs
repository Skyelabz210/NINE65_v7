//! Galois Automorphisms for SIMD Slot Rotations
//!
//! BFV homomorphic encryption supports SIMD operations via batching.
//! When encoding N/2 values into a single ciphertext, Galois automorphisms
//! enable rotating these "slots" without decryption.
//!
//! ## Automorphisms
//!
//! For the ring R_q = Z_q[X]/(X^N + 1), the Galois automorphism σ_k maps:
//! - X → X^k where k is coprime to 2N (k must be odd)
//!
//! ## Slot Rotations
//!
//! - Left rotation by r: use exponent 5^r mod 2N (5 generates Z*_{2N})
//! - Right rotation by r: use exponent 5^(-r) mod 2N
//! - Conjugation: use exponent 2N - 1
//!
//! ## Key Switching
//!
//! Each rotation requires a Galois key (similar to relinearization key)
//! to transform the ciphertext after applying the automorphism to coefficients.

use super::encrypt::Ciphertext;
use crate::entropy::FheRng;
use crate::errors::{Nine65Error, Nine65Result};
use crate::ring::RingPolynomial;

#[cfg(test)]
use crate::entropy::ShadowHarvester;

use crate::arithmetic::NTTEngine;

/// Galois key for a specific automorphism exponent
///
/// Enables key switching after applying σ_k to a ciphertext.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", derive(bincode::Encode, bincode::Decode))]
pub struct GaloisKey {
    /// The automorphism exponent k
    pub exponent: usize,
    /// Key switching matrix (similar to evaluation key)
    /// Each element is (b, a) where b = -a·s + e + s(X^k) · P/q
    pub key_switch_a: Vec<RingPolynomial>,
    pub key_switch_b: Vec<RingPolynomial>,
}

impl GaloisKey {
    /// Validate Galois key structure and bounds
    ///
    /// Checks:
    /// - Exponent is odd (required for valid automorphism)
    /// - key_switch_a and key_switch_b have the same length
    /// - All polynomials have the expected degree N
    /// - All coefficients are < q
    ///
    /// This should be called after deserialization to ensure key integrity.
    pub fn validate(&self, expected_n: usize, expected_q: u64) -> Nine65Result<()> {
        // Check exponent is odd (required for valid automorphism in X^N + 1)
        if self.exponent.is_multiple_of(2) {
            return Err(Nine65Error::ConfigError {
                message: format!(
                    "Galois exponent {} is even; must be odd for X^N + 1 ring",
                    self.exponent
                ),
            });
        }

        // Check key switch matrices have matching lengths
        if self.key_switch_a.len() != self.key_switch_b.len() {
            return Err(Nine65Error::ConfigError {
                message: format!(
                    "Key switch matrix size mismatch: a={}, b={}",
                    self.key_switch_a.len(),
                    self.key_switch_b.len()
                ),
            });
        }

        // Check all polynomials have correct degree and coefficients in range
        for (i, poly) in self.key_switch_a.iter().enumerate() {
            if poly.coeffs.len() != expected_n {
                return Err(Nine65Error::InvalidPolynomialDegree {
                    got: poly.coeffs.len(),
                    expected: expected_n,
                });
            }
            if poly.q != expected_q {
                return Err(Nine65Error::ConfigError {
                    message: format!(
                        "key_switch_a[{}] modulus {} != expected {}",
                        i, poly.q, expected_q
                    ),
                });
            }
            for (j, &coeff) in poly.coeffs.iter().enumerate() {
                if coeff >= expected_q {
                    return Err(Nine65Error::ConfigError {
                        message: format!(
                            "key_switch_a[{}][{}] = {} >= q (out of bounds)",
                            i, j, coeff
                        ),
                    });
                }
            }
        }

        for (i, poly) in self.key_switch_b.iter().enumerate() {
            if poly.coeffs.len() != expected_n {
                return Err(Nine65Error::InvalidPolynomialDegree {
                    got: poly.coeffs.len(),
                    expected: expected_n,
                });
            }
            if poly.q != expected_q {
                return Err(Nine65Error::ConfigError {
                    message: format!(
                        "key_switch_b[{}] modulus {} != expected {}",
                        i, poly.q, expected_q
                    ),
                });
            }
            for (j, &coeff) in poly.coeffs.iter().enumerate() {
                if coeff >= expected_q {
                    return Err(Nine65Error::ConfigError {
                        message: format!(
                            "key_switch_b[{}][{}] = {} >= q (out of bounds)",
                            i, j, coeff
                        ),
                    });
                }
            }
        }

        Ok(())
    }
}

/// Collection of Galois keys for supported rotations
#[derive(Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", derive(bincode::Encode, bincode::Decode))]
pub struct GaloisKeySet {
    /// Map from rotation exponent to Galois key
    keys: std::collections::HashMap<usize, GaloisKey>,
}

#[cfg(feature = "serde")]
impl GaloisKey {
    /// Serialize to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Serialize to bincode bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        bincode::encode_to_vec(self, bincode::config::standard())
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }

    /// Deserialize from JSON with validation
    ///
    /// This is the **recommended** deserialization method for production use.
    /// It validates structural integrity and bounds before returning the key.
    pub fn from_json_validated(s: &str, expected_n: usize, expected_q: u64) -> Nine65Result<Self> {
        let key: Self = serde_json::from_str(s).map_err(|e| Nine65Error::ConfigError {
            message: e.to_string(),
        })?;
        key.validate(expected_n, expected_q)?;
        Ok(key)
    }

    /// Deserialize from bytes with validation
    ///
    /// This is the **recommended** deserialization method for production use.
    /// It validates structural integrity and bounds before returning the key.
    pub fn from_bytes_validated(
        bytes: &[u8],
        expected_n: usize,
        expected_q: u64,
    ) -> Nine65Result<Self> {
        let (key, consumed): (Self, usize) =
            bincode::decode_from_slice(bytes, bincode::config::standard()).map_err(|e| {
                Nine65Error::ConfigError {
                    message: e.to_string(),
                }
            })?;
        // `decode_from_slice` does not itself reject trailing bytes after a
        // well-formed value.
        if consumed != bytes.len() {
            return Err(Nine65Error::ConfigError {
                message: format!(
                    "Bincode payload has {} trailing byte(s) after a valid {}-byte Galois key",
                    bytes.len() - consumed,
                    consumed
                ),
            });
        }
        key.validate(expected_n, expected_q)?;
        Ok(key)
    }
}

#[cfg(feature = "serde")]
impl GaloisKeySet {
    /// Serialize to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Serialize to bincode bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        bincode::encode_to_vec(self, bincode::config::standard())
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }

    /// Deserialize from JSON with validation
    ///
    /// This is the **recommended** deserialization method for production use.
    /// It validates structural integrity and bounds of all keys before returning.
    pub fn from_json_validated(s: &str, expected_n: usize, expected_q: u64) -> Nine65Result<Self> {
        let keys: Self = serde_json::from_str(s).map_err(|e| Nine65Error::ConfigError {
            message: e.to_string(),
        })?;
        keys.validate(expected_n, expected_q)?;
        Ok(keys)
    }

    /// Deserialize from bytes with validation
    ///
    /// This is the **recommended** deserialization method for production use.
    /// It validates structural integrity and bounds of all keys before returning.
    pub fn from_bytes_validated(
        bytes: &[u8],
        expected_n: usize,
        expected_q: u64,
    ) -> Nine65Result<Self> {
        let (keys, consumed): (Self, usize) =
            bincode::decode_from_slice(bytes, bincode::config::standard()).map_err(|e| {
                Nine65Error::ConfigError {
                    message: e.to_string(),
                }
            })?;
        // See the matching comment in `GaloisKey::from_bytes_validated`.
        if consumed != bytes.len() {
            return Err(Nine65Error::ConfigError {
                message: format!(
                    "Bincode payload has {} trailing byte(s) after a valid {}-byte Galois keyset",
                    bytes.len() - consumed,
                    consumed
                ),
            });
        }
        keys.validate(expected_n, expected_q)?;
        Ok(keys)
    }
}

impl GaloisKeySet {
    /// Create an empty Galois key set
    pub fn new() -> Self {
        Self {
            keys: std::collections::HashMap::new(),
        }
    }

    /// Validate all Galois keys in the set
    ///
    /// Checks each key for:
    /// - Valid automorphism exponent (odd)
    /// - Correct polynomial degree N
    /// - All coefficients < q
    ///
    /// This should be called after deserialization to ensure key set integrity.
    pub fn validate(&self, expected_n: usize, expected_q: u64) -> Nine65Result<()> {
        for (exponent, key) in &self.keys {
            key.validate(expected_n, expected_q)
                .map_err(|e| Nine65Error::ConfigError {
                    message: format!("GaloisKey for exponent {}: {}", exponent, e),
                })?;
        }
        Ok(())
    }

    /// Add a Galois key for a specific exponent
    pub fn add_key(&mut self, key: GaloisKey) {
        self.keys.insert(key.exponent, key);
    }

    /// Get Galois key for a specific exponent
    pub fn get(&self, exponent: usize) -> Option<&GaloisKey> {
        self.keys.get(&exponent)
    }

    /// Check if a rotation is supported
    pub fn has_exponent(&self, exponent: usize) -> bool {
        self.keys.contains_key(&exponent)
    }

    /// Get all supported exponents
    pub fn exponents(&self) -> Vec<usize> {
        self.keys.keys().copied().collect()
    }
}

/// Engine for computing Galois automorphisms
pub struct GaloisEngine {
    /// Polynomial degree
    n: usize,
    /// Modulus
    q: u64,
    /// 2N for automorphism exponent arithmetic
    two_n: usize,
    /// Generator of Z*_{2N} (typically 5 for power-of-2 N)
    generator: usize,
    /// Precomputed inverse of generator
    generator_inv: usize,
}

impl GaloisEngine {
    /// Create a new Galois engine for ring Z_q[X]/(X^N + 1)
    pub fn new(n: usize, q: u64) -> Self {
        assert!(n.is_power_of_two(), "N must be a power of 2");

        let two_n = 2 * n;

        // Find generator of Z*_{2N}
        // For power-of-2 N, 5 is always a generator
        let generator = 5;

        // Compute multiplicative inverse of 5 mod 2N
        let generator_inv = Self::mod_inverse(generator, two_n);

        Self {
            n,
            q,
            two_n,
            generator,
            generator_inv,
        }
    }

    /// Get the exponent for left rotation by r slots
    pub fn left_rotation_exponent(&self, r: usize) -> usize {
        self.pow_mod(self.generator, r)
    }

    /// Get the exponent for right rotation by r slots
    pub fn right_rotation_exponent(&self, r: usize) -> usize {
        self.pow_mod(self.generator_inv, r)
    }

    /// Get the exponent for complex conjugation
    pub fn conjugation_exponent(&self) -> usize {
        self.two_n - 1
    }

    /// Apply Galois automorphism σ_k to a polynomial
    ///
    /// Maps a(X) → a(X^k) where the result is reduced mod (X^N + 1)
    pub fn apply_automorphism(&self, poly: &RingPolynomial, exponent: usize) -> RingPolynomial {
        debug_assert!(exponent % 2 == 1, "Exponent must be odd (coprime to 2N)");

        let mut result = vec![0u64; self.n];

        for i in 0..self.n {
            // X^i maps to X^{i*k}
            let new_exp = (i * exponent) % self.two_n;

            // Reduce mod X^N + 1:
            // X^j = X^{j mod N} if j/N is even
            // X^j = -X^{j mod N} if j/N is odd
            let reduced_exp = new_exp % self.n;
            let negated = (new_exp / self.n) % 2 == 1;

            if negated {
                // Subtract coefficient (add q - coeff)
                result[reduced_exp] = (result[reduced_exp] + self.q - poly.coeffs[i]) % self.q;
            } else {
                // Add coefficient
                result[reduced_exp] = (result[reduced_exp] + poly.coeffs[i]) % self.q;
            }
        }

        RingPolynomial::from_coeffs(result, self.q)
    }

    /// Apply automorphism to both components of a ciphertext
    ///
    /// Note: This only applies the permutation. Key switching must follow!
    pub fn apply_to_ciphertext_raw(&self, ct: &Ciphertext, exponent: usize) -> Ciphertext {
        Ciphertext {
            c0: self.apply_automorphism(&ct.c0, exponent),
            c1: self.apply_automorphism(&ct.c1, exponent),
        }
    }

    /// Compute k^exp mod 2N
    fn pow_mod(&self, base: usize, exp: usize) -> usize {
        let mut result = 1usize;
        let mut b = base % self.two_n;
        let mut e = exp;

        while e > 0 {
            if e % 2 == 1 {
                result = (result * b) % self.two_n;
            }
            e /= 2;
            b = (b * b) % self.two_n;
        }

        result
    }

    /// Modular inverse via extended Euclidean algorithm
    fn mod_inverse(a: usize, m: usize) -> usize {
        let mut mn = (m as i64, a as i64);
        let mut xy = (0i64, 1i64);

        while mn.1 != 0 {
            let q = mn.0 / mn.1;
            mn = (mn.1, mn.0 - q * mn.1);
            xy = (xy.1, xy.0 - q * xy.1);
        }

        while xy.0 < 0 {
            xy.0 += m as i64;
        }

        (xy.0 % m as i64) as usize
    }

    /// Generate Galois key for a specific exponent
    ///
    /// Requires the secret key and creates a key-switching matrix.
    pub fn generate_galois_key<R: FheRng>(
        &self,
        exponent: usize,
        secret_key: &RingPolynomial,
        ntt: &NTTEngine,
        eta: usize,
        decomp_bits: usize,
        rng: &mut R,
    ) -> GaloisKey {
        // Apply automorphism to secret key: s(X^k)
        let s_auto = self.apply_automorphism(secret_key, exponent);

        // Number of decomposition levels
        let num_levels = 64_usize.div_ceil(decomp_bits);
        let base = 1u64 << decomp_bits;

        let mut key_switch_a = Vec::with_capacity(num_levels);
        let mut key_switch_b = Vec::with_capacity(num_levels);

        // For each power of the base
        for l in 0..num_levels {
            let power = if l == 0 { 1u64 } else { base.pow(l as u32) };

            // a_l is uniform random
            let a = RingPolynomial::random_uniform_rng(self.n, self.q, rng);

            // e_l is small error
            let e = RingPolynomial::random_cbd_rng(self.n, self.q, eta, rng);

            // s_auto * power mod q
            let scaled_s_auto = s_auto.scalar_mul(power, ntt);

            // b_l = -a_l * s + e_l + s(X^k) * base^l
            let neg_a_s = a.mul(secret_key, ntt).neg(ntt);
            let b = neg_a_s.add(&e, ntt).add(&scaled_s_auto, ntt);

            key_switch_a.push(a);
            key_switch_b.push(b);
        }

        GaloisKey {
            exponent,
            key_switch_a,
            key_switch_b,
        }
    }

    /// Generate Galois keys for all rotations up to max_rotation
    pub fn generate_rotation_keys<R: FheRng>(
        &self,
        max_rotation: usize,
        secret_key: &RingPolynomial,
        ntt: &NTTEngine,
        eta: usize,
        decomp_bits: usize,
        rng: &mut R,
    ) -> GaloisKeySet {
        let mut key_set = GaloisKeySet::new();

        // Generate keys for left rotations 1 to max_rotation
        for r in 1..=max_rotation {
            let exp = self.left_rotation_exponent(r);
            let key = self.generate_galois_key(exp, secret_key, ntt, eta, decomp_bits, rng);
            key_set.add_key(key);
        }

        // Generate key for conjugation
        let conj_exp = self.conjugation_exponent();
        let conj_key = self.generate_galois_key(conj_exp, secret_key, ntt, eta, decomp_bits, rng);
        key_set.add_key(conj_key);

        key_set
    }
}

/// Evaluator extension for Galois operations
pub struct GaloisEvaluator<'a> {
    /// Galois engine for automorphisms
    galois: &'a GaloisEngine,
    /// NTT engine for polynomial arithmetic
    ntt: &'a NTTEngine,
    /// Galois keys for supported rotations
    keys: &'a GaloisKeySet,
    /// Decomposition bit width
    decomp_bits: usize,
}

impl<'a> GaloisEvaluator<'a> {
    /// Create a new Galois evaluator
    pub fn new(
        galois: &'a GaloisEngine,
        ntt: &'a NTTEngine,
        keys: &'a GaloisKeySet,
        decomp_bits: usize,
    ) -> Self {
        Self {
            galois,
            ntt,
            keys,
            decomp_bits,
        }
    }

    /// Rotate slots left by r positions
    pub fn rotate_left(&self, ct: &Ciphertext, r: usize) -> Option<Ciphertext> {
        let exponent = self.galois.left_rotation_exponent(r);
        self.apply_galois(ct, exponent)
    }

    /// Rotate slots right by r positions
    pub fn rotate_right(&self, ct: &Ciphertext, r: usize) -> Option<Ciphertext> {
        let exponent = self.galois.right_rotation_exponent(r);
        self.apply_galois(ct, exponent)
    }

    /// Apply complex conjugation to slots
    pub fn conjugate(&self, ct: &Ciphertext) -> Option<Ciphertext> {
        let exponent = self.galois.conjugation_exponent();
        self.apply_galois(ct, exponent)
    }

    /// Apply Galois automorphism with key switching
    fn apply_galois(&self, ct: &Ciphertext, exponent: usize) -> Option<Ciphertext> {
        let key = self.keys.get(exponent)?;

        // Step 1: Apply automorphism to ciphertext
        let ct_auto = self.galois.apply_to_ciphertext_raw(ct, exponent);

        // Step 2: Key switching on c1
        // Decompose c1 into base-2^decomp_bits digits
        let c1_decomposed = self.decompose(&ct_auto.c1);

        // Accumulate key-switched result
        let mut new_c0 = ct_auto.c0.clone();
        let mut new_c1 = RingPolynomial::zero(self.galois.n, self.galois.q);

        for (i, c1_digit) in c1_decomposed.iter().enumerate() {
            // new_c0 += c1_digit * key_b[i]
            let term_b = c1_digit.mul(&key.key_switch_b[i], self.ntt);
            new_c0 = new_c0.add(&term_b, self.ntt);

            // new_c1 += c1_digit * key_a[i]
            let term_a = c1_digit.mul(&key.key_switch_a[i], self.ntt);
            new_c1 = new_c1.add(&term_a, self.ntt);
        }

        Some(Ciphertext {
            c0: new_c0,
            c1: new_c1,
        })
    }

    /// Decompose polynomial into base-2^decomp_bits digits
    fn decompose(&self, poly: &RingPolynomial) -> Vec<RingPolynomial> {
        let base = 1u64 << self.decomp_bits;
        let num_levels = 64_usize.div_ceil(self.decomp_bits);

        let mut result = Vec::with_capacity(num_levels);

        for l in 0..num_levels {
            let shift = l * self.decomp_bits;
            let coeffs: Vec<u64> = poly
                .coeffs
                .iter()
                .map(|&c| (c >> shift) & (base - 1))
                .collect();
            result.push(RingPolynomial::from_coeffs(coeffs, poly.q));
        }

        result
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// THREAD SAFETY ASSERTIONS
// ═══════════════════════════════════════════════════════════════════════════

// Compile-time verification that Galois types are thread-safe.
// These assertions fail at compile time if the types don't implement Send/Sync.
const _: () = {
    const fn assert_send<T: Send>() {}
    const fn assert_sync<T: Sync>() {}

    // GaloisKey contains polynomials which are Send + Sync
    assert_send::<GaloisKey>();
    assert_sync::<GaloisKey>();

    // GaloisKeySet is a collection of GaloisKeys
    assert_send::<GaloisKeySet>();
    assert_sync::<GaloisKeySet>();

    // GaloisEngine is immutable after construction
    assert_send::<GaloisEngine>();
    assert_sync::<GaloisEngine>();
};

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PRIME: u64 = 998244353;

    #[test]
    fn test_galois_engine_creation() {
        let galois = GaloisEngine::new(1024, TEST_PRIME);

        // Check generator and inverse
        assert_eq!(galois.generator, 5);
        let prod = (galois.generator * galois.generator_inv) % galois.two_n;
        assert_eq!(
            prod, 1,
            "Generator inverse should satisfy g * g^-1 = 1 mod 2N"
        );
    }

    #[test]
    fn test_rotation_exponents() {
        let galois = GaloisEngine::new(8, TEST_PRIME);

        // 2N = 16, generator = 5
        // Left by 1: 5^1 mod 16 = 5
        // Left by 2: 5^2 mod 16 = 25 mod 16 = 9
        assert_eq!(galois.left_rotation_exponent(1), 5);
        assert_eq!(galois.left_rotation_exponent(2), 9);

        // Conjugation: 2N - 1 = 15
        assert_eq!(galois.conjugation_exponent(), 15);
    }

    #[test]
    fn test_automorphism_identity() {
        let galois = GaloisEngine::new(8, TEST_PRIME);

        let poly = RingPolynomial::from_coeffs(vec![1, 2, 3, 4, 5, 6, 7, 8], TEST_PRIME);

        // σ_1 should be identity
        let result = galois.apply_automorphism(&poly, 1);
        assert_eq!(result.coeffs, poly.coeffs);
    }

    #[test]
    fn test_automorphism_involution() {
        let galois = GaloisEngine::new(8, TEST_PRIME);

        let poly = RingPolynomial::from_coeffs(vec![1, 2, 3, 4, 5, 6, 7, 8], TEST_PRIME);

        // Apply σ_k twice should equal σ_{k^2 mod 2N}
        let exp = 5;
        let result1 = galois.apply_automorphism(&poly, exp);
        let result2 = galois.apply_automorphism(&result1, exp);

        let exp_squared = (exp * exp) % galois.two_n;
        let expected = galois.apply_automorphism(&poly, exp_squared);

        assert_eq!(result2.coeffs, expected.coeffs);
    }

    #[test]
    fn test_automorphism_preserves_structure() {
        let galois = GaloisEngine::new(8, TEST_PRIME);
        let ntt = NTTEngine::new(TEST_PRIME, 8);

        let a = RingPolynomial::from_coeffs(vec![1, 2, 0, 0, 0, 0, 0, 0], TEST_PRIME);
        let b = RingPolynomial::from_coeffs(vec![3, 4, 0, 0, 0, 0, 0, 0], TEST_PRIME);

        let exp = 5;

        // σ_k(a + b) = σ_k(a) + σ_k(b)
        let sum = a.add(&b, &ntt);
        let auto_sum = galois.apply_automorphism(&sum, exp);

        let auto_a = galois.apply_automorphism(&a, exp);
        let auto_b = galois.apply_automorphism(&b, exp);
        let sum_auto = auto_a.add(&auto_b, &ntt);

        assert_eq!(
            auto_sum.coeffs, sum_auto.coeffs,
            "Automorphism should be additive"
        );
    }

    #[test]
    fn test_galois_key_generation() {
        let n = 8;
        let galois = GaloisEngine::new(n, TEST_PRIME);
        let ntt = NTTEngine::new(TEST_PRIME, n);

        let mut rng = ShadowHarvester::with_seed(42);

        // Generate random secret key
        let secret_key = RingPolynomial::random_ternary(n, TEST_PRIME, &mut rng);

        // Generate Galois key for rotation by 1
        let exp = galois.left_rotation_exponent(1);
        let key = galois.generate_galois_key(exp, &secret_key, &ntt, 3, 8, &mut rng);

        assert_eq!(key.exponent, exp);
        assert!(!key.key_switch_a.is_empty());
        assert_eq!(key.key_switch_a.len(), key.key_switch_b.len());
    }

    #[test]
    fn test_galois_key_set() {
        let galois = GaloisEngine::new(8, TEST_PRIME);
        let ntt = NTTEngine::new(TEST_PRIME, 8);
        let mut rng = ShadowHarvester::with_seed(42);
        let secret_key = RingPolynomial::random_ternary(8, TEST_PRIME, &mut rng);

        let keys = galois.generate_rotation_keys(2, &secret_key, &ntt, 3, 8, &mut rng);

        // Should have keys for rotation 1, 2, and conjugation
        assert!(keys.has_exponent(galois.left_rotation_exponent(1)));
        assert!(keys.has_exponent(galois.left_rotation_exponent(2)));
        assert!(keys.has_exponent(galois.conjugation_exponent()));
    }

    #[test]
    fn test_decomposition() {
        let galois = GaloisEngine::new(8, TEST_PRIME);
        let ntt = NTTEngine::new(TEST_PRIME, 8);
        let keys = GaloisKeySet::new();

        let evaluator = GaloisEvaluator::new(&galois, &ntt, &keys, 8);

        // Test decomposition with base 256 (8 bits)
        let poly = RingPolynomial::from_coeffs(vec![0x1234, 0, 0, 0, 0, 0, 0, 0], TEST_PRIME);
        let decomposed = evaluator.decompose(&poly);

        // 0x1234 = 0x34 + 0x12 * 256
        assert_eq!(decomposed[0].coeffs[0], 0x34);
        assert_eq!(decomposed[1].coeffs[0], 0x12);
    }
}
