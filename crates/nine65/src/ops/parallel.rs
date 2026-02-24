//! Parallel Encryption/Decryption for Throughput
//!
//! Provides parallel versions of encrypt and decrypt operations for
//! high-throughput scenarios. Uses Rayon for work-stealing parallelism.
//!
//! # Feature Flag
//!
//! Requires the `parallel` feature:
//! ```toml
//! [dependencies]
//! nine65 = { version = "0.1", features = ["parallel"] }
//! ```
//!
//! # Example
//!
//! ```ignore
//! use nine65::ops::parallel::ParallelEncryptor;
//!
//! let parallel = ParallelEncryptor::new(&pk, &encoder, &ntt, config.eta);
//!
//! // Encrypt 1000 messages in parallel
//! let messages: Vec<u64> = (0..1000).collect();
//! let ciphertexts = parallel.encrypt_batch_par(&messages);
//!
//! // Decrypt in parallel
//! let parallel_dec = ParallelDecryptor::new(&sk, &encoder, &ntt);
//! let decrypted = parallel_dec.decrypt_batch_par(&ciphertexts);
//! ```
//!
//! # Thread Safety
//!
//! All parallel operations use thread-local RNG instances derived from a master seed.
//! This ensures:
//! - No data races during encryption
//! - Deterministic results when using seeded mode
//! - Cryptographically independent ciphertexts

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[cfg(feature = "ntt_fft")]
use crate::arithmetic::NTTEngineFFT as NTTEngine;

#[cfg(not(feature = "ntt_fft"))]
use crate::arithmetic::NTTEngine;

use crate::entropy::ShadowHarvester;
use crate::errors::Nine65Result;
use crate::keys::{PublicKey, SecretKey};
use crate::ops::encrypt::{BFVDecryptor, BFVEncoder, BFVEncryptor, Ciphertext};

/// Parallel encryptor for high-throughput encryption
///
/// Encrypts multiple messages in parallel using Rayon's work-stealing scheduler.
/// Each thread uses an independent RNG derived from a counter, ensuring both
/// thread safety and deterministic behavior when using seeded mode.
pub struct ParallelEncryptor<'a> {
    pk: &'a PublicKey,
    encoder: &'a BFVEncoder,
    ntt: &'a NTTEngine,
    eta: usize,
}

impl<'a> ParallelEncryptor<'a> {
    /// Create a new parallel encryptor
    pub fn new(pk: &'a PublicKey, encoder: &'a BFVEncoder, ntt: &'a NTTEngine, eta: usize) -> Self {
        Self {
            pk,
            encoder,
            ntt,
            eta,
        }
    }

    /// Encrypt multiple messages in parallel (deterministic, for testing)
    ///
    /// Uses thread-local `ShadowHarvester` instances seeded from a counter.
    /// Results are deterministic for the same input and base seed.
    ///
    /// # Arguments
    /// * `messages` - Messages to encrypt (each must be < plaintext modulus)
    /// * `base_seed` - Base seed for RNG; each message gets `base_seed + index`
    ///
    /// # Warning
    /// This uses deterministic randomness. For production, use `encrypt_batch_par_secure`.
    #[cfg(feature = "parallel")]
    pub fn encrypt_batch_par_seeded(&self, messages: &[u64], base_seed: u64) -> Vec<Ciphertext> {
        messages
            .par_iter()
            .enumerate()
            .map(|(i, &m)| {
                let encryptor = BFVEncryptor::new(self.pk, self.encoder, self.ntt, self.eta);
                let mut rng = ShadowHarvester::with_seed(base_seed.wrapping_add(i as u64));
                encryptor.encrypt(m, &mut rng)
            })
            .collect()
    }

    /// Encrypt multiple messages in parallel (secure, for production)
    ///
    /// Uses cryptographically secure RNG for each encryption.
    /// Results are non-deterministic but cryptographically secure.
    ///
    /// # Arguments
    /// * `messages` - Messages to encrypt (each must be < plaintext modulus)
    #[cfg(feature = "parallel")]
    pub fn encrypt_batch_par_secure(&self, messages: &[u64]) -> Vec<Ciphertext> {
        messages
            .par_iter()
            .map(|&m| {
                let encryptor = BFVEncryptor::new(self.pk, self.encoder, self.ntt, self.eta);
                encryptor.encrypt_secure(m)
            })
            .collect()
    }

    /// Encrypt multiple messages in parallel with fallible interface
    ///
    /// Returns `Err` if any message is out of bounds.
    #[cfg(feature = "parallel")]
    pub fn try_encrypt_batch_par_secure(&self, messages: &[u64]) -> Nine65Result<Vec<Ciphertext>> {
        messages
            .par_iter()
            .map(|&m| {
                let encryptor = BFVEncryptor::new(self.pk, self.encoder, self.ntt, self.eta);
                encryptor.try_encrypt_secure(m)
            })
            .collect()
    }

    /// Encrypt polynomials in parallel
    ///
    /// For advanced use cases where pre-encoded plaintexts need encryption.
    #[cfg(feature = "parallel")]
    pub fn encrypt_polys_par_secure(
        &self,
        plaintexts: &[crate::ring::RingPolynomial],
    ) -> Vec<Ciphertext> {
        plaintexts
            .par_iter()
            .map(|pt| {
                let encryptor = BFVEncryptor::new(self.pk, self.encoder, self.ntt, self.eta);
                encryptor.encrypt_poly_secure(pt)
            })
            .collect()
    }

    // =========================================================================
    // SEQUENTIAL FALLBACKS (when `parallel` feature is disabled)
    // =========================================================================

    /// Sequential fallback for batch encryption (seeded)
    #[cfg(not(feature = "parallel"))]
    pub fn encrypt_batch_par_seeded(&self, messages: &[u64], base_seed: u64) -> Vec<Ciphertext> {
        let encryptor = BFVEncryptor::new(self.pk, self.encoder, self.ntt, self.eta);
        messages
            .iter()
            .enumerate()
            .map(|(i, &m)| {
                let mut rng = ShadowHarvester::with_seed(base_seed.wrapping_add(i as u64));
                encryptor.encrypt(m, &mut rng)
            })
            .collect()
    }

    /// Sequential fallback for batch encryption (secure)
    #[cfg(not(feature = "parallel"))]
    pub fn encrypt_batch_par_secure(&self, messages: &[u64]) -> Vec<Ciphertext> {
        let encryptor = BFVEncryptor::new(self.pk, self.encoder, self.ntt, self.eta);
        messages
            .iter()
            .map(|&m| encryptor.encrypt_secure(m))
            .collect()
    }

    /// Sequential fallback for try batch encryption (secure)
    #[cfg(not(feature = "parallel"))]
    pub fn try_encrypt_batch_par_secure(&self, messages: &[u64]) -> Nine65Result<Vec<Ciphertext>> {
        let encryptor = BFVEncryptor::new(self.pk, self.encoder, self.ntt, self.eta);
        messages
            .iter()
            .map(|&m| encryptor.try_encrypt_secure(m))
            .collect()
    }

    /// Sequential fallback for polynomial encryption
    #[cfg(not(feature = "parallel"))]
    pub fn encrypt_polys_par_secure(
        &self,
        plaintexts: &[crate::ring::RingPolynomial],
    ) -> Vec<Ciphertext> {
        let encryptor = BFVEncryptor::new(self.pk, self.encoder, self.ntt, self.eta);
        plaintexts
            .iter()
            .map(|pt| encryptor.encrypt_poly_secure(pt))
            .collect()
    }
}

/// Parallel decryptor for high-throughput decryption
///
/// Decrypts multiple ciphertexts in parallel using Rayon's work-stealing scheduler.
pub struct ParallelDecryptor<'a> {
    sk: &'a SecretKey,
    encoder: &'a BFVEncoder,
    ntt: &'a NTTEngine,
}

impl<'a> ParallelDecryptor<'a> {
    /// Create a new parallel decryptor
    pub fn new(sk: &'a SecretKey, encoder: &'a BFVEncoder, ntt: &'a NTTEngine) -> Self {
        Self { sk, encoder, ntt }
    }

    /// Decrypt multiple ciphertexts in parallel
    ///
    /// # Arguments
    /// * `ciphertexts` - Ciphertexts to decrypt
    #[cfg(feature = "parallel")]
    pub fn decrypt_batch_par(&self, ciphertexts: &[Ciphertext]) -> Vec<u64> {
        ciphertexts
            .par_iter()
            .map(|ct| {
                let decryptor = BFVDecryptor::new(self.sk, self.encoder, self.ntt);
                decryptor.decrypt(ct)
            })
            .collect()
    }

    /// Decrypt multiple ciphertexts to vectors in parallel
    ///
    /// For batch-encoded ciphertexts where each contains multiple values.
    #[cfg(feature = "parallel")]
    pub fn decrypt_vectors_par(
        &self,
        ciphertexts: &[Ciphertext],
        values_per_ct: usize,
    ) -> Vec<Vec<u64>> {
        ciphertexts
            .par_iter()
            .map(|ct| {
                let decryptor = BFVDecryptor::new(self.sk, self.encoder, self.ntt);
                decryptor.decrypt_vector(ct, values_per_ct)
            })
            .collect()
    }

    // =========================================================================
    // SEQUENTIAL FALLBACKS (when `parallel` feature is disabled)
    // =========================================================================

    /// Sequential fallback for batch decryption
    #[cfg(not(feature = "parallel"))]
    pub fn decrypt_batch_par(&self, ciphertexts: &[Ciphertext]) -> Vec<u64> {
        let decryptor = BFVDecryptor::new(self.sk, self.encoder, self.ntt);
        ciphertexts.iter().map(|ct| decryptor.decrypt(ct)).collect()
    }

    /// Sequential fallback for vector decryption
    #[cfg(not(feature = "parallel"))]
    pub fn decrypt_vectors_par(
        &self,
        ciphertexts: &[Ciphertext],
        values_per_ct: usize,
    ) -> Vec<Vec<u64>> {
        let decryptor = BFVDecryptor::new(self.sk, self.encoder, self.ntt);
        ciphertexts
            .iter()
            .map(|ct| decryptor.decrypt_vector(ct, values_per_ct))
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// THREAD SAFETY ASSERTIONS
// ═══════════════════════════════════════════════════════════════════════════

// Note: ParallelEncryptor and ParallelDecryptor are NOT Send/Sync because they
// hold references. They are designed to be created within the parallel scope
// that uses them. The underlying types (PublicKey, SecretKey, etc.) are Send/Sync.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeySet;
    use crate::params::secure_configs::SecureConfig;
    use crate::params::FHEConfig;

    fn setup() -> (FHEConfig, NTTEngine, KeySet, BFVEncoder) {
        let config = SecureConfig::test_fast_insecure().into_config();
        let ntt = NTTEngine::new(config.q, config.n);
        let mut harvester = ShadowHarvester::with_seed(42);
        let keys = KeySet::generate(&config, &ntt, &mut harvester);
        let encoder = BFVEncoder::new(&config);
        (config, ntt, keys, encoder)
    }

    #[test]
    fn test_parallel_encrypt_decrypt_roundtrip() {
        let (config, ntt, keys, encoder) = setup();

        let parallel_enc = ParallelEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let parallel_dec = ParallelDecryptor::new(&keys.secret_key, &encoder, &ntt);

        // Test with multiple messages
        let messages: Vec<u64> = (0..100).map(|i| i % config.t).collect();

        // Encrypt in parallel (seeded for determinism)
        let ciphertexts = parallel_enc.encrypt_batch_par_seeded(&messages, 12345);
        assert_eq!(ciphertexts.len(), 100);

        // Decrypt in parallel
        let decrypted = parallel_dec.decrypt_batch_par(&ciphertexts);
        assert_eq!(decrypted.len(), 100);

        // Verify roundtrip
        for (i, (&orig, &dec)) in messages.iter().zip(decrypted.iter()).enumerate() {
            assert_eq!(orig, dec, "Mismatch at index {}: {} != {}", i, orig, dec);
        }
    }

    #[test]
    fn test_parallel_encrypt_secure() {
        let (config, ntt, keys, encoder) = setup();

        let parallel_enc = ParallelEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let parallel_dec = ParallelDecryptor::new(&keys.secret_key, &encoder, &ntt);

        // Test secure encryption (uses OS CSPRNG)
        let messages: Vec<u64> = vec![42, 100, 255, 1000];
        let ciphertexts = parallel_enc.encrypt_batch_par_secure(&messages);

        // Verify decryption works
        let decrypted = parallel_dec.decrypt_batch_par(&ciphertexts);
        assert_eq!(decrypted, messages);
    }

    #[test]
    fn test_parallel_encrypt_deterministic() {
        let (config, ntt, keys, encoder) = setup();

        let parallel_enc = ParallelEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);

        let messages: Vec<u64> = (0..10).collect();

        // Same seed should produce same ciphertexts
        let ct1 = parallel_enc.encrypt_batch_par_seeded(&messages, 99999);
        let ct2 = parallel_enc.encrypt_batch_par_seeded(&messages, 99999);

        for (c1, c2) in ct1.iter().zip(ct2.iter()) {
            assert_eq!(c1.c0.coeffs, c2.c0.coeffs);
            assert_eq!(c1.c1.coeffs, c2.c1.coeffs);
        }
    }

    #[test]
    fn test_try_encrypt_batch_error() {
        let (config, ntt, keys, encoder) = setup();

        let parallel_enc = ParallelEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);

        // Include an out-of-bounds message
        let messages: Vec<u64> = vec![1, 2, config.t + 1, 4];

        let result = parallel_enc.try_encrypt_batch_par_secure(&messages);
        assert!(result.is_err(), "Should fail with out-of-bounds message");
    }

    #[test]
    fn test_parallel_throughput_benchmark() {
        let (config, ntt, keys, encoder) = setup();

        let parallel_enc = ParallelEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let parallel_dec = ParallelDecryptor::new(&keys.secret_key, &encoder, &ntt);

        let count = 1000;
        let messages: Vec<u64> = (0..count).map(|i| i % (config.t / 2)).collect();

        // Benchmark encryption
        let start = std::time::Instant::now();
        let ciphertexts = parallel_enc.encrypt_batch_par_seeded(&messages, 12345);
        let encrypt_time = start.elapsed();

        // Benchmark decryption
        let start = std::time::Instant::now();
        let decrypted = parallel_dec.decrypt_batch_par(&ciphertexts);
        let decrypt_time = start.elapsed();

        let enc_ns_per_msg = encrypt_time.as_nanos() / count as u128;
        println!(
            "Parallel encrypt {} messages: {:?} ({}.{:03} us/msg)",
            count,
            encrypt_time,
            enc_ns_per_msg / 1000,
            enc_ns_per_msg % 1000
        );
        let dec_ns_per_msg = decrypt_time.as_nanos() / count as u128;
        println!(
            "Parallel decrypt {} messages: {:?} ({}.{:03} us/msg)",
            count,
            decrypt_time,
            dec_ns_per_msg / 1000,
            dec_ns_per_msg % 1000
        );

        // Verify correctness
        assert_eq!(decrypted, messages);
    }
}
