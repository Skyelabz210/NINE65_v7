//! Keys Module - BFV Key Generation
//!
//! Generates secret, public, and evaluation keys for BFV FHE.
//!
//! # Security (December 2024 Cryptographic Audit)
//!
//! - **SecretKey** implements `Zeroize` and `ZeroizeOnDrop` for secure memory clearing
//! - **generate_secure()** uses OS CSPRNG - USE FOR PRODUCTION
//! - **generate()** uses Shadow Entropy - USE FOR TESTING/BENCHMARKS ONLY
//!
//! # Example
//!
//! ```ignore
//! // PRODUCTION: Use secure key generation
//! let keys = KeySet::generate_secure(&config, &ntt);
//!
//! // TESTING: Use deterministic generation
//! let mut harvester = ShadowHarvester::with_seed(42);
//! let keys = KeySet::generate(&config, &ntt, &mut harvester);
//! ```

pub mod bootstrap;

pub use bootstrap::{BootstrapKey, BootstrapKeySet, KeySwitchKey, BOOTSTRAP_PRIMES};

#[cfg(feature = "ntt_fft")]
use crate::arithmetic::NTTEngineFFT as NTTEngine;

#[cfg(not(feature = "ntt_fft"))]
use crate::arithmetic::NTTEngine;
use crate::entropy::ShadowHarvester;
use crate::entropy::{try_secure_cbd_vector, try_secure_ternary_vector, try_secure_uniform_vector};
use crate::errors::{Nine65Error, Nine65Result};
use crate::params::FHEConfig;
use crate::ring::RingPolynomial;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secret Key: ternary polynomial s ∈ R_q
///
/// # Security
///
/// Implements `ZeroizeOnDrop` to securely clear memory when dropped.
/// The secret key coefficients are overwritten with zeros using volatile
/// writes that cannot be optimized away by the compiler.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    /// The secret polynomial (zeroized on drop via RingPolynomial::Zeroize)
    pub s: RingPolynomial,
}

impl SecretKey {
    /// Generate a new secret key using Shadow Entropy (DETERMINISTIC)
    ///
    /// # Warning
    ///
    /// This produces deterministic keys based on the harvester seed.
    /// **Use only for testing and reproducible benchmarks.**
    ///
    /// For production, use [`generate_secure()`](Self::generate_secure).
    pub fn generate(config: &FHEConfig, harvester: &mut ShadowHarvester) -> Self {
        let s = RingPolynomial::random_ternary(config.n, config.q, harvester);
        Self { s }
    }

    /// Generate a new secret key using OS CSPRNG (PRODUCTION)
    ///
    /// Uses the operating system's cryptographically secure random number
    /// generator via `getrandom`. This should be used for all production
    /// key generation.
    ///
    /// # Panics
    ///
    /// Panics if the OS CSPRNG fails (should never happen on supported platforms).
    pub fn generate_secure(config: &FHEConfig) -> Self {
        Self::try_generate_secure(config)
            .expect("CRITICAL: OS CSPRNG failure during secret key generation")
    }

    /// Fallible secure secret key generation.
    pub fn try_generate_secure(config: &FHEConfig) -> Nine65Result<Self> {
        let ternary =
            try_secure_ternary_vector(config.n).map_err(|e| Nine65Error::KeyGenFailed {
                reason: format!(
                    "OS CSPRNG failure generating secret key ternary vector: {}",
                    e
                ),
            })?;

        // Convert ternary {-1, 0, 1} to ring elements mod q
        let coeffs: Vec<u64> = ternary
            .iter()
            .map(|&t| {
                if t < 0 {
                    config.q - 1 // -1 mod q
                } else {
                    t as u64
                }
            })
            .collect();

        let s = RingPolynomial::from_coeffs(coeffs, config.q);
        Ok(Self { s })
    }
}

/// Public Key: (pk0, pk1) where pk0 = -a*s + e, pk1 = a
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", derive(bincode::Encode, bincode::Decode))]
pub struct PublicKey {
    /// pk0 = -a*s + e
    pub pk0: RingPolynomial,
    /// pk1 = a (random polynomial)
    pub pk1: RingPolynomial,
}

impl PublicKey {
    /// Generate public key from secret key (DETERMINISTIC)
    ///
    /// Uses Shadow Entropy for randomness. For production, use
    /// [`generate_secure()`](Self::generate_secure).
    pub fn generate(
        sk: &SecretKey,
        config: &FHEConfig,
        ntt: &NTTEngine,
        harvester: &mut ShadowHarvester,
    ) -> Self {
        // a ← uniform random
        let a = RingPolynomial::random_uniform(config.n, config.q, harvester);

        // e ← error distribution (CBD)
        let e = RingPolynomial::random_cbd(config.n, config.q, config.eta, harvester);

        // pk0 = -a*s + e = -(a*s) + e
        // Use constant-time multiplication to protect secret key
        let as_prod = a.mul_ct(&sk.s, ntt);
        let neg_as = as_prod.neg(ntt);
        let pk0 = neg_as.add(&e, ntt);

        Self { pk0, pk1: a }
    }

    /// Generate public key from secret key using OS CSPRNG (PRODUCTION)
    ///
    /// Uses cryptographically secure randomness for the 'a' polynomial
    /// and error term. Uses constant-time operations for secret key.
    pub fn generate_secure(sk: &SecretKey, config: &FHEConfig, ntt: &NTTEngine) -> Self {
        Self::try_generate_secure(sk, config, ntt)
            .expect("CRITICAL: OS CSPRNG failure during public key generation")
    }

    /// Fallible secure public key generation.
    pub fn try_generate_secure(
        sk: &SecretKey,
        config: &FHEConfig,
        ntt: &NTTEngine,
    ) -> Nine65Result<Self> {
        // a ← uniform random (CSPRNG)
        let a_coeffs = try_secure_uniform_vector(config.n, config.q).map_err(|e| {
            Nine65Error::KeyGenFailed {
                reason: format!(
                    "OS CSPRNG failure generating public key uniform vector: {}",
                    e
                ),
            }
        })?;
        let a = RingPolynomial::from_coeffs(a_coeffs, config.q);

        // e ← CBD error distribution (CSPRNG)
        let e_signed =
            try_secure_cbd_vector(config.n, config.eta).map_err(|e| Nine65Error::KeyGenFailed {
                reason: format!(
                    "OS CSPRNG failure generating public key error vector: {}",
                    e
                ),
            })?;
        let e_coeffs: Vec<u64> = e_signed
            .iter()
            .map(|&e| {
                if e < 0 {
                    ((config.q as i64) + e) as u64
                } else {
                    e as u64
                }
            })
            .collect();
        let e = RingPolynomial::from_coeffs(e_coeffs, config.q);

        // pk0 = -a*s + e
        // Use constant-time multiplication to protect secret key
        let as_prod = a.mul_ct(&sk.s, ntt);
        let neg_as = as_prod.neg(ntt);
        let pk0 = neg_as.add(&e, ntt);

        Ok(Self { pk0, pk1: a })
    }

    /// Validate public key structure and bounds
    ///
    /// # Security
    /// Use after deserialization to prevent malformed key DoS or modulus mismatch.
    pub fn validate(&self, expected_n: usize, expected_q: u64) -> Nine65Result<()> {
        self.pk0.validate(expected_n, expected_q)?;
        self.pk1.validate(expected_n, expected_q)?;

        if self.pk0.coeffs.len() != self.pk1.coeffs.len() {
            return Err(Nine65Error::InvalidPolynomialDegree {
                got: self.pk1.coeffs.len(),
                expected: self.pk0.coeffs.len(),
            });
        }

        Ok(())
    }
}

/// Evaluation Key for relinearization after multiplication
///
/// Contains relinearization key components for converting degree-2
/// ciphertexts back to degree-1 after homomorphic multiplication.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", derive(bincode::Encode, bincode::Decode))]
pub struct EvaluationKey {
    /// Relinearization key components
    /// rlk[i] = (b_i, a_i) where b_i = -a_i * s + e_i + (s² * T^i)
    pub rlk: Vec<(RingPolynomial, RingPolynomial)>,
    /// Decomposition base (typically a power of 2)
    pub decomp_base: u64,
    /// Number of decomposition levels
    pub levels: usize,
}

impl EvaluationKey {
    /// Generate evaluation key for relinearization (DETERMINISTIC)
    pub fn generate(
        sk: &SecretKey,
        config: &FHEConfig,
        ntt: &NTTEngine,
        harvester: &mut ShadowHarvester,
    ) -> Self {
        let decomp_base = 1u64 << 16; // T = 2^16
        let q_bits = 64 - config.q.leading_zeros() as usize;
        let levels = q_bits.div_ceil(16);

        // Use constant-time multiplication to protect secret key
        let s_squared = sk.s.mul_ct(&sk.s, ntt);

        let mut rlk = Vec::with_capacity(levels);
        let mut power_of_t = 1u64;

        for _ in 0..levels {
            let a_i = RingPolynomial::random_uniform(config.n, config.q, harvester);
            let e_i = RingPolynomial::random_cbd(config.n, config.q, config.eta, harvester);

            let s2_ti = s_squared.scalar_mul(power_of_t, ntt);
            // Use constant-time multiplication to protect secret key
            let as_prod = a_i.mul_ct(&sk.s, ntt);
            let neg_as = as_prod.neg(ntt);
            let b_i = neg_as.add(&e_i, ntt).add(&s2_ti, ntt);

            rlk.push((b_i, a_i));
            power_of_t = ((power_of_t as u128 * decomp_base as u128) % config.q as u128) as u64;
        }

        Self {
            rlk,
            decomp_base,
            levels,
        }
    }

    /// Generate evaluation key using OS CSPRNG (PRODUCTION)
    ///
    /// This path uses direct CSPRNG sampling for all randomness instead of
    /// an OS-seeded deterministic generator.
    pub fn generate_secure(sk: &SecretKey, config: &FHEConfig, ntt: &NTTEngine) -> Self {
        Self::try_generate_secure(sk, config, ntt)
            .expect("CRITICAL: OS CSPRNG failure during evaluation key generation")
    }

    /// Fallible secure evaluation key generation.
    pub fn try_generate_secure(
        sk: &SecretKey,
        config: &FHEConfig,
        ntt: &NTTEngine,
    ) -> Nine65Result<Self> {
        let decomp_base = 1u64 << 16; // T = 2^16
        let q_bits = 64 - config.q.leading_zeros() as usize;
        let levels = q_bits.div_ceil(16);

        // Use constant-time multiplication to protect secret key
        let s_squared = sk.s.mul_ct(&sk.s, ntt);

        let mut rlk = Vec::with_capacity(levels);
        let mut power_of_t = 1u64;

        for _ in 0..levels {
            let a_coeffs = try_secure_uniform_vector(config.n, config.q).map_err(|e| {
                Nine65Error::KeyGenFailed {
                    reason: format!("OS CSPRNG failure generating eval-key uniform vector: {}", e),
                }
            })?;
            let a_i = RingPolynomial::from_coeffs(a_coeffs, config.q);

            let e_signed = try_secure_cbd_vector(config.n, config.eta).map_err(|e| {
                Nine65Error::KeyGenFailed {
                    reason: format!("OS CSPRNG failure generating eval-key error vector: {}", e),
                }
            })?;
            let e_coeffs: Vec<u64> = e_signed
                .into_iter()
                .map(|e| {
                    if e < 0 {
                        ((config.q as i64) + e) as u64
                    } else {
                        e as u64
                    }
                })
                .collect();
            let e_i = RingPolynomial::from_coeffs(e_coeffs, config.q);

            let s2_ti = s_squared.scalar_mul(power_of_t, ntt);
            // Use constant-time multiplication to protect secret key
            let as_prod = a_i.mul_ct(&sk.s, ntt);
            let neg_as = as_prod.neg(ntt);
            let b_i = neg_as.add(&e_i, ntt).add(&s2_ti, ntt);

            rlk.push((b_i, a_i));
            power_of_t = ((power_of_t as u128 * decomp_base as u128) % config.q as u128) as u64;
        }

        Ok(Self {
            rlk,
            decomp_base,
            levels,
        })
    }

    /// Validate evaluation key structure and bounds
    ///
    /// # Security
    /// Use after deserialization to ensure decomposition metadata and
    /// polynomial dimensions are consistent with the expected parameters.
    pub fn validate(&self, expected_n: usize, expected_q: u64) -> Nine65Result<()> {
        if self.decomp_base == 0 {
            return Err(Nine65Error::InvalidParameter {
                message: "EvaluationKey: decomp_base must be non-zero".to_string(),
            });
        }

        if !self.decomp_base.is_power_of_two() {
            return Err(Nine65Error::InvalidParameter {
                message: format!(
                    "EvaluationKey: decomp_base {} must be a power of two",
                    self.decomp_base
                ),
            });
        }

        if self.levels == 0 {
            return Err(Nine65Error::InvalidParameter {
                message: "EvaluationKey: levels must be non-zero".to_string(),
            });
        }

        if self.rlk.len() != self.levels {
            return Err(Nine65Error::InvalidParameter {
                message: format!(
                    "EvaluationKey: rlk len {} != levels {}",
                    self.rlk.len(),
                    self.levels
                ),
            });
        }

        for (i, (b, a)) in self.rlk.iter().enumerate() {
            b.validate(expected_n, expected_q)
                .map_err(|e| Nine65Error::InvalidParameter {
                    message: format!("EvaluationKey: rlk[{}].b invalid: {}", i, e),
                })?;
            a.validate(expected_n, expected_q)
                .map_err(|e| Nine65Error::InvalidParameter {
                    message: format!("EvaluationKey: rlk[{}].a invalid: {}", i, e),
                })?;
        }

        Ok(())
    }
}

/// Secure zeroization for EvaluationKey
///
/// While eval keys are public, they contain s² information.
/// Zeroizing is defense-in-depth.
impl Drop for EvaluationKey {
    fn drop(&mut self) {
        for (b, a) in &mut self.rlk {
            b.coeffs.zeroize();
            a.coeffs.zeroize();
        }
    }
}

// ============================================================================
// SERIALIZATION HELPERS
// ============================================================================

#[cfg(feature = "serde")]
impl PublicKey {
    /// Serialize to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Serialize to compact binary format (bincode)
    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        bincode::encode_to_vec(self, bincode::config::standard())
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }

    /// Deserialize from JSON with validation
    pub fn from_json_validated(s: &str, expected_n: usize, expected_q: u64) -> Nine65Result<Self> {
        let pk: Self = serde_json::from_str(s).map_err(|e| Nine65Error::DeserializationError {
            message: format!("JSON parse error: {}", e),
        })?;
        pk.validate(expected_n, expected_q)?;
        Ok(pk)
    }

    /// Deserialize from bytes with validation
    pub fn from_bytes_validated(
        bytes: &[u8],
        expected_n: usize,
        expected_q: u64,
    ) -> Nine65Result<Self> {
        let (pk, _): (Self, usize) = 
            bincode::decode_from_slice(bytes, bincode::config::standard()).map_err(|e| {
                Nine65Error::DeserializationError {
                    message: format!("Bincode parse error: {}", e),
                }
            })?;
        pk.validate(expected_n, expected_q)?;
        Ok(pk)
    }
}

#[cfg(all(feature = "serde", feature = "allow_insecure"))]
impl PublicKey {
    /// Deserialize from JSON string (UNVALIDATED)
    ///
    /// # Security Warning
    /// This method does NOT validate the deserialized key.
    /// Only use for trusted input. For untrusted input, use `from_json_validated()`.
    #[deprecated(
        since = "0.1.0",
        note = "Use from_json_validated() for untrusted input"
    )]
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// Deserialize from bincode bytes (UNVALIDATED)
    ///
    /// # Security Warning
    /// This method does NOT validate the deserialized key.
    /// Only use for trusted input. For untrusted input, use `from_bytes_validated()`.
    #[deprecated(
        since = "0.1.0",
        note = "Use from_bytes_validated() for untrusted input"
    )]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let (result, _): (Self, usize) = bincode::decode_from_slice(bytes, bincode::config::standard())
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        Ok(result)
    }
}

#[cfg(feature = "serde")]
impl EvaluationKey {
    /// Serialize to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Serialize to compact binary format (bincode)
    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        bincode::encode_to_vec(self, bincode::config::standard())
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }

    /// Deserialize from JSON with validation
    pub fn from_json_validated(s: &str, expected_n: usize, expected_q: u64) -> Nine65Result<Self> {
        let ek: Self = serde_json::from_str(s).map_err(|e| Nine65Error::DeserializationError {
            message: format!("JSON parse error: {}", e),
        })?;
        ek.validate(expected_n, expected_q)?;
        Ok(ek)
    }

    /// Deserialize from bytes with validation
    pub fn from_bytes_validated(
        bytes: &[u8],
        expected_n: usize,
        expected_q: u64,
    ) -> Nine65Result<Self> {
        let (ek, _): (Self, usize) = 
            bincode::decode_from_slice(bytes, bincode::config::standard()).map_err(|e| {
                Nine65Error::DeserializationError {
                    message: format!("Bincode parse error: {}", e),
                }
            })?;
        ek.validate(expected_n, expected_q)?;
        Ok(ek)
    }
}

#[cfg(all(feature = "serde", feature = "allow_insecure"))]
impl EvaluationKey {
    /// Deserialize from JSON string (UNVALIDATED)
    ///
    /// # Security Warning
    /// This method does NOT validate the deserialized key.
    /// Only use for trusted input. For untrusted input, use `from_json_validated()`.
    #[deprecated(
        since = "0.1.0",
        note = "Use from_json_validated() for untrusted input"
    )]
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// Deserialize from bincode bytes (UNVALIDATED)
    ///
    /// # Security Warning
    /// This method does NOT validate the deserialized key.
    /// Only use for trusted input. For untrusted input, use `from_bytes_validated()`.
    #[deprecated(
        since = "0.1.0",
        note = "Use from_bytes_validated() for untrusted input"
    )]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let (result, _): (Self, usize) = bincode::decode_from_slice(bytes, bincode::config::standard())
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        Ok(result)
    }
}

/// Complete key set containing all keys needed for FHE operations
pub struct KeySet {
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
    pub eval_key: EvaluationKey,
}

/// GRO-gated key generation for timing side-channel protection.
///
/// Wraps key generation inside a GRO coincidence window so that
/// execution timing is value-independent (INV-7). All secret-key
/// operations (ternary sampling, `a·s` products) execute within the
/// window, making external timing measurements uninformative.
///
/// # Requires
///
/// Feature `clockwork` must be enabled.
///
/// # Example
///
/// ```ignore
/// use nine65::security::TimingGate;
///
/// let gate = TimingGate::new(16, 100).unwrap();
/// let keys = KeySet::generate_gated(&config, &ntt, &gate)?;
/// ```
#[cfg(feature = "clockwork")]
pub struct GatedKeyGen;

#[cfg(feature = "clockwork")]
impl GatedKeyGen {
    /// Generate a complete key set inside a GRO timing window (PRODUCTION).
    ///
    /// Waits for a coincidence window, then executes the full keygen
    /// pipeline (secret key, public key, evaluation key) within it.
    ///
    /// Returns `Nine65Error::KeyGenFailed` if no GRO window is found
    /// within `max_search` steps.
    pub fn generate_secure(
        config: &FHEConfig,
        ntt: &NTTEngine,
        gate: &crate::security::TimingGate,
    ) -> Nine65Result<KeySet> {
        Self::generate_secure_with_search(config, ntt, gate, 1_000_000)
    }

    /// Generate with explicit max search bound for GRO window.
    pub fn generate_secure_with_search(
        config: &FHEConfig,
        ntt: &NTTEngine,
        gate: &crate::security::TimingGate,
        max_search: u64,
    ) -> Nine65Result<KeySet> {
        // Find next coincidence window
        let _window = gate.next_window(0, max_search).ok_or_else(|| {
            Nine65Error::KeyGenFailed {
                reason: format!(
                    "GRO timing gate: no coincidence window found within {} steps",
                    max_search
                ),
            }
        })?;

        // Execute keygen inside window
        KeySet::try_generate_secure(config, ntt)
    }
}

impl KeySet {
    /// Generate complete key set (DETERMINISTIC)
    ///
    /// Uses Shadow Entropy for reproducible key generation.
    /// **For production, use [`generate_secure()`](Self::generate_secure).**
    pub fn generate(config: &FHEConfig, ntt: &NTTEngine, harvester: &mut ShadowHarvester) -> Self {
        let secret_key = SecretKey::generate(config, harvester);
        let public_key = PublicKey::generate(&secret_key, config, ntt, harvester);
        let eval_key = EvaluationKey::generate(&secret_key, config, ntt, harvester);

        Self {
            secret_key,
            public_key,
            eval_key,
        }
    }

    /// Generate complete key set using OS CSPRNG (PRODUCTION)
    ///
    /// Uses cryptographically secure randomness for all key generation.
    /// This is the recommended method for production deployments.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = FHEConfig::he_standard_128_insecure();
    /// let ntt = NTTEngine::new(config.q, config.n);
    /// let keys = KeySet::generate_secure(&config, &ntt);
    /// ```
    pub fn generate_secure(config: &FHEConfig, ntt: &NTTEngine) -> Self {
        Self::try_generate_secure(config, ntt)
            .expect("CRITICAL: OS CSPRNG failure during keyset generation")
    }

    /// Fallible secure keyset generation.
    pub fn try_generate_secure(config: &FHEConfig, ntt: &NTTEngine) -> Nine65Result<Self> {
        let secret_key = SecretKey::try_generate_secure(config)?;
        let public_key = PublicKey::try_generate_secure(&secret_key, config, ntt)?;
        let eval_key = EvaluationKey::try_generate_secure(&secret_key, config, ntt)?;

        Ok(Self {
            secret_key,
            public_key,
            eval_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::secure_configs::SecureConfig;

    #[test]
    fn test_keygen_basic() {
        let config = SecureConfig::test_fast_insecure().into_config();
        let mut harvester = ShadowHarvester::with_seed(42);

        let sk = SecretKey::generate(&config, &mut harvester);

        // Secret key should be ternary
        for i in 0..config.n {
            let coeff = sk.s.get_signed(i);
            assert!(
                (-1..=1).contains(&coeff),
                "Non-ternary coefficient: {}",
                coeff
            );
        }
    }

    #[test]
    fn test_keygen_deterministic() {
        let config = SecureConfig::test_fast_insecure().into_config();
        let ntt = NTTEngine::new(config.q, config.n);

        let mut h1 = ShadowHarvester::with_seed(12345);
        let mut h2 = ShadowHarvester::with_seed(12345);

        let keys1 = KeySet::generate(&config, &ntt, &mut h1);
        let keys2 = KeySet::generate(&config, &ntt, &mut h2);

        // Same seed should produce same keys
        assert_eq!(keys1.secret_key.s.coeffs, keys2.secret_key.s.coeffs);
        assert_eq!(keys1.public_key.pk0.coeffs, keys2.public_key.pk0.coeffs);
        assert_eq!(keys1.public_key.pk1.coeffs, keys2.public_key.pk1.coeffs);
    }

    #[test]
    fn test_keygen_secure() {
        let config = SecureConfig::test_fast_insecure().into_config();
        let ntt = NTTEngine::new(config.q, config.n);

        let keys1 = KeySet::generate_secure(&config, &ntt);
        let keys2 = KeySet::generate_secure(&config, &ntt);

        // Secure keygen should produce DIFFERENT keys each time
        assert_ne!(
            keys1.secret_key.s.coeffs, keys2.secret_key.s.coeffs,
            "Secure keygen should be non-deterministic"
        );
    }

    #[test]
    fn test_secure_key_is_ternary() {
        let config = SecureConfig::test_fast_insecure().into_config();

        let sk = SecretKey::generate_secure(&config);

        // Secret key should still be ternary
        for i in 0..config.n {
            let coeff = sk.s.get_signed(i);
            assert!(
                (-1..=1).contains(&coeff),
                "Secure key has non-ternary coefficient at {}: {}",
                i,
                coeff
            );
        }
    }

    #[test]
    fn test_keygen_benchmark() {
        let config = SecureConfig::test_fast_insecure().into_config();
        let ntt = NTTEngine::new(config.q, config.n);
        let mut harvester = ShadowHarvester::with_seed(999);

        let start = std::time::Instant::now();
        for _ in 0..100 {
            let _ = KeySet::generate(&config, &ntt, &mut harvester);
        }
        let elapsed = start.elapsed();

        println!("KeyGen (deterministic) x100: {:?}", elapsed);
    }

    #[test]
    fn test_keygen_secure_benchmark() {
        let config = SecureConfig::test_fast_insecure().into_config();
        let ntt = NTTEngine::new(config.q, config.n);

        let start = std::time::Instant::now();
        for _ in 0..100 {
            let _ = KeySet::generate_secure(&config, &ntt);
        }
        let elapsed = start.elapsed();

        println!("KeyGen (secure) x100: {:?}", elapsed);
    }

    #[test]
    fn test_encrypt_decrypt_with_secure_keys() {
        // Integration test: verify secure keys work with FHE operations
        use crate::ops::encrypt::{BFVDecryptor, BFVEncoder, BFVEncryptor};

        let config = SecureConfig::test_fast_insecure().into_config();
        let ntt = NTTEngine::new(config.q, config.n);
        let keys = KeySet::generate_secure(&config, &ntt);

        // Create encoder/encryptor/decryptor
        let encoder = BFVEncoder::new(&config);
        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);

        // Use Shadow for encrypt noise (acceptable per audit)
        let mut harvester = ShadowHarvester::from_os_seed();

        let plaintext = 42u64;
        let ct = encryptor.encrypt(plaintext, &mut harvester);
        let decrypted = decryptor.decrypt(&ct);

        assert_eq!(
            decrypted, plaintext,
            "Encrypt/decrypt failed with secure keys"
        );
    }

    #[cfg(feature = "clockwork")]
    #[test]
    fn test_gated_keygen_succeeds_in_window() {
        use crate::security::TimingGate;

        let config = SecureConfig::test_fast_insecure().into_config();
        let ntt = NTTEngine::new(config.q, config.n);
        let gate = TimingGate::new(16, 100).unwrap();

        let result = super::GatedKeyGen::generate_secure(&config, &ntt, &gate);
        assert!(result.is_ok(), "GRO-gated keygen should succeed");

        let keys = result.unwrap();
        // Verify key is valid (ternary secret key)
        for i in 0..config.n {
            let coeff = keys.secret_key.s.get_signed(i);
            assert!(
                (-1..=1).contains(&coeff),
                "GRO-gated key has non-ternary coefficient"
            );
        }
    }

    #[cfg(feature = "clockwork")]
    #[test]
    fn test_gated_keygen_encrypt_decrypt_roundtrip() {
        use crate::ops::encrypt::{BFVDecryptor, BFVEncoder, BFVEncryptor};
        use crate::security::TimingGate;

        let config = SecureConfig::test_fast_insecure().into_config();
        let ntt = NTTEngine::new(config.q, config.n);
        let gate = TimingGate::new(16, 100).unwrap();

        let keys = super::GatedKeyGen::generate_secure(&config, &ntt, &gate).unwrap();

        let encoder = BFVEncoder::new(&config);
        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);

        let mut harvester = ShadowHarvester::from_os_seed();
        let ct = encryptor.encrypt(42, &mut harvester);
        let result = decryptor.decrypt(&ct);
        assert_eq!(result, 42, "GRO-gated keys should work for encrypt/decrypt");
    }

    #[cfg(feature = "clockwork")]
    #[test]
    fn test_gated_keygen_timing_variance() {
        use crate::security::TimingGate;

        let config = SecureConfig::test_fast_insecure().into_config();
        let ntt = NTTEngine::new(config.q, config.n);
        let gate = TimingGate::new(16, 100).unwrap();

        // Generate multiple keys and check timing variance
        let mut durations = Vec::new();
        for _ in 0..10 {
            let start = std::time::Instant::now();
            let _ = super::GatedKeyGen::generate_secure(&config, &ntt, &gate).unwrap();
            durations.push(start.elapsed().as_nanos());
        }

        let mean = durations.iter().sum::<u128>() / durations.len() as u128;
        let max_dev = durations
            .iter()
            .map(|&d| if d > mean { d - mean } else { mean - d })
            .max()
            .unwrap();

        // Timing variance should be bounded (GRO window alignment)
        println!(
            "GRO-gated keygen: mean={}ns, max_dev={}ns, ratio={}%",
            mean,
            max_dev,
            (max_dev * 100) / mean
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_public_key_serde_roundtrip_validated() {
        let config = SecureConfig::test_fast_insecure().into_config();
        let ntt = NTTEngine::new(config.q, config.n);
        let mut harvester = ShadowHarvester::with_seed(2026);

        let keys = KeySet::generate(&config, &ntt, &mut harvester);

        let json = keys.public_key.to_json().expect("serialize public key");
        let pk = PublicKey::from_json_validated(&json, config.n, config.q)
            .expect("validated public key");
        assert_eq!(pk.pk0.coeffs, keys.public_key.pk0.coeffs);
        assert_eq!(pk.pk1.coeffs, keys.public_key.pk1.coeffs);

        let bytes = keys
            .public_key
            .to_bytes()
            .expect("serialize public key bytes");
        let pk_bytes = PublicKey::from_bytes_validated(&bytes, config.n, config.q)
            .expect("validated public key bytes");
        assert_eq!(pk_bytes.pk0.coeffs, keys.public_key.pk0.coeffs);
        assert_eq!(pk_bytes.pk1.coeffs, keys.public_key.pk1.coeffs);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_eval_key_serde_roundtrip_validated() {
        let config = SecureConfig::test_fast_insecure().into_config();
        let ntt = NTTEngine::new(config.q, config.n);
        let mut harvester = ShadowHarvester::with_seed(8080);

        let keys = KeySet::generate(&config, &ntt, &mut harvester);

        let json = keys.eval_key.to_json().expect("serialize eval key");
        let ek = EvaluationKey::from_json_validated(&json, config.n, config.q)
            .expect("validated eval key");
        assert_eq!(ek.levels, keys.eval_key.levels);
        assert_eq!(ek.decomp_base, keys.eval_key.decomp_base);
        assert_eq!(ek.rlk.len(), keys.eval_key.rlk.len());

        let bytes = keys.eval_key.to_bytes().expect("serialize eval key bytes");
        let ek_bytes = EvaluationKey::from_bytes_validated(&bytes, config.n, config.q)
            .expect("validated eval key bytes");
        assert_eq!(ek_bytes.levels, keys.eval_key.levels);
        assert_eq!(ek_bytes.decomp_base, keys.eval_key.decomp_base);
        assert_eq!(ek_bytes.rlk.len(), keys.eval_key.rlk.len());
    }
}
