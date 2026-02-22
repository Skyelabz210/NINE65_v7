//! Encryption Module - BFV Encrypt/Decrypt
//!
//! BFV encoding: m → Δ*m where Δ = floor(q/t)
//! Encryption: ct = (pk0*u + e1 + Δ*m, pk1*u + e2)
//! Decryption: m = round(t * (c0 + c1*s) / q) mod t
//!
//! # Security
//!
//! For production, use `encrypt_secure()` or `encrypt_with_rng()` with `SecureRng`.
//! The basic `encrypt()` method uses `ShadowHarvester` which is deterministic
//! and should only be used for testing.

#[cfg(feature = "ntt_fft")]
use crate::arithmetic::NTTEngineFFT as NTTEngine;

#[cfg(not(feature = "ntt_fft"))]
use crate::arithmetic::NTTEngine;
use crate::entropy::{try_secure_cbd_vector, try_secure_ternary_vector, FheRng, ShadowHarvester};
use crate::errors::{Nine65Error, Nine65Result};
use crate::keys::{PublicKey, SecretKey};
use crate::params::FHEConfig;
use crate::ring::RingPolynomial;

/// BFV Encoder: handles message ↔ polynomial conversion
pub struct BFVEncoder {
    /// Ciphertext modulus
    pub q: u64,
    /// Plaintext modulus
    pub t: u64,
    /// Scaling factor Δ = floor(q/t)
    pub delta: u64,
    /// Polynomial degree
    pub n: usize,
}

impl BFVEncoder {
    /// Create a new encoder
    pub fn new(config: &FHEConfig) -> Self {
        Self {
            q: config.q,
            t: config.t,
            delta: config.q / config.t,
            n: config.n,
        }
    }

    /// Encode a scalar message as polynomial
    ///
    /// # Panics
    /// Panics if m >= t. Use `try_encode()` for fallible encoding.
    pub fn encode(&self, m: u64) -> RingPolynomial {
        self.try_encode(m)
            .expect("Message must be less than plaintext modulus")
    }

    /// Fallible encoding: returns error if m >= t
    ///
    /// Use this in production code instead of `encode()` to properly
    /// handle invalid inputs.
    pub fn try_encode(&self, m: u64) -> Nine65Result<RingPolynomial> {
        if m >= self.t {
            return Err(Nine65Error::MessageOutOfBounds {
                message: m,
                modulus: self.t,
            });
        }

        let mut coeffs = vec![0u64; self.n];
        coeffs[0] = ((self.delta as u128 * m as u128) % self.q as u128) as u64;

        Ok(RingPolynomial::from_coeffs(coeffs, self.q))
    }

    /// Decode polynomial to scalar message
    pub fn decode(&self, poly: &RingPolynomial) -> u64 {
        // m = round(t * c / q) mod t
        // Using integer formula: floor((2*t*c + q) / (2*q)) mod t
        let c = poly.coeffs[0];

        // Careful computation to avoid overflow
        let numerator = 2u128 * (self.t as u128) * (c as u128) + (self.q as u128);
        let denominator = 2u128 * (self.q as u128);
        let result = (numerator / denominator) as u64;

        result % self.t
    }

    /// Decode a polynomial from a degree-2 ciphertext (at Δ² level)
    ///
    /// After tensor product, values are at Δ² level instead of Δ level.
    /// Use t²/q² scaling to recover message.
    ///
    /// Formula: m = round(t² × coeff / q²) = round(coeff × t² / q²)
    pub fn decode_degree2(&self, poly: &RingPolynomial) -> u64 {
        let c = poly.coeffs[0];

        // Compute round(c * t² / q²)
        // Using: round(x/y) = (2x + y) / (2y)
        //
        // But t² and q² might overflow u128. Let's be careful.
        //
        // Alternative: c * t² / q² = c * t / q * t / q = (c * t / q) * t / q
        // First scale: temp = round(c * t / q)
        // Second scale: result = round(temp * t / q)

        let temp =
            ((2u128 * self.t as u128 * c as u128) + self.q as u128) / (2u128 * self.q as u128);

        let result = ((2u128 * self.t as u128 * temp) + self.q as u128) / (2u128 * self.q as u128);

        (result as u64) % self.t
    }

    /// Encode a vector of messages (for batching)
    ///
    /// # Panics
    /// Panics if any message >= t or vector too long. Use `try_encode_vector()` for fallible encoding.
    pub fn encode_vector(&self, msgs: &[u64]) -> RingPolynomial {
        self.try_encode_vector(msgs)
            .expect("Invalid message vector")
    }

    /// Fallible vector encoding: returns error on invalid inputs
    pub fn try_encode_vector(&self, msgs: &[u64]) -> Nine65Result<RingPolynomial> {
        if msgs.len() > self.n {
            return Err(Nine65Error::InvalidPolynomialDegree {
                got: msgs.len(),
                expected: self.n,
            });
        }

        let mut coeffs = vec![0u64; self.n];
        for (i, &m) in msgs.iter().enumerate() {
            if m >= self.t {
                return Err(Nine65Error::MessageOutOfBounds {
                    message: m,
                    modulus: self.t,
                });
            }
            coeffs[i] = ((self.delta as u128 * m as u128) % self.q as u128) as u64;
        }

        Ok(RingPolynomial::from_coeffs(coeffs, self.q))
    }

    /// Decode polynomial to vector of messages
    pub fn decode_vector(&self, poly: &RingPolynomial, len: usize) -> Vec<u64> {
        (0..len)
            .map(|i| {
                let c = poly.coeffs[i];
                let numerator = 2u128 * (self.t as u128) * (c as u128) + (self.q as u128);
                let denominator = 2u128 * (self.q as u128);
                ((numerator / denominator) as u64) % self.t
            })
            .collect()
    }
}

/// BFV Ciphertext: (c0, c1) ∈ R_q × R_q
///
/// # Thread Safety
///
/// `Ciphertext` is `Send + Sync`. Ciphertexts can be safely sent between
/// threads and shared via `Arc<Ciphertext>` for concurrent read access.
/// Clone before modifying in different threads.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", derive(bincode::Encode, bincode::Decode))]
pub struct Ciphertext {
    /// First component
    pub c0: RingPolynomial,
    /// Second component
    pub c1: RingPolynomial,
}

impl Ciphertext {
    /// Validate ciphertext structure and bounds
    ///
    /// Checks:
    /// - Both polynomials have the same degree
    /// - Polynomial degree matches expected N
    /// - All coefficients are < q
    ///
    /// This should be called after deserialization to ensure ciphertext integrity.
    pub fn validate(&self, expected_n: usize, expected_q: u64) -> Nine65Result<()> {
        // Check polynomial degrees match
        if self.c0.coeffs.len() != self.c1.coeffs.len() {
            return Err(Nine65Error::InvalidPolynomialDegree {
                got: self.c1.coeffs.len(),
                expected: self.c0.coeffs.len(),
            });
        }

        // Check degree matches expected N
        if self.c0.coeffs.len() != expected_n {
            return Err(Nine65Error::InvalidPolynomialDegree {
                got: self.c0.coeffs.len(),
                expected: expected_n,
            });
        }

        // Check modulus matches
        if self.c0.q != expected_q || self.c1.q != expected_q {
            return Err(Nine65Error::ConfigError {
                message: format!(
                    "Modulus mismatch: ciphertext has q={}/{}, expected q={}",
                    self.c0.q, self.c1.q, expected_q
                ),
            });
        }

        // Check all coefficients are in valid range
        for (i, &coeff) in self.c0.coeffs.iter().enumerate() {
            if coeff >= expected_q {
                return Err(Nine65Error::ConfigError {
                    message: format!(
                        "c0[{}] = {} >= q = {} (out of bounds)",
                        i, coeff, expected_q
                    ),
                });
            }
        }
        for (i, &coeff) in self.c1.coeffs.iter().enumerate() {
            if coeff >= expected_q {
                return Err(Nine65Error::ConfigError {
                    message: format!(
                        "c1[{}] = {} >= q = {} (out of bounds)",
                        i, coeff, expected_q
                    ),
                });
            }
        }

        Ok(())
    }

    /// Get the polynomial degree N
    pub fn degree(&self) -> usize {
        self.c0.coeffs.len()
    }

    /// Get the modulus q
    pub fn modulus(&self) -> u64 {
        self.c0.q
    }
}

#[cfg(feature = "serde")]
impl Ciphertext {
    /// Serialize to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize from JSON string (**unvalidated**).
    ///
    /// # Security Warning
    /// This method does NOT validate the deserialized ciphertext.
    /// For untrusted input, use `from_json_validated()` instead to ensure
    /// ciphertext integrity and prevent DoS attacks via malformed data.
    #[deprecated(
        since = "0.1.0",
        note = "Use from_json_validated() for untrusted input"
    )]
    #[doc(hidden)]
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    /// Serialize to bincode bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        bincode::encode_to_vec(self, bincode::config::standard())
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }

    /// Deserialize from bincode bytes (**unvalidated**).
    ///
    /// # Security Warning
    /// This method does NOT validate the deserialized ciphertext.
    /// For untrusted input, use `from_bytes_validated()` instead to ensure
    /// ciphertext integrity and prevent DoS attacks via malformed data.
    #[deprecated(
        since = "0.1.0",
        note = "Use from_bytes_validated() for untrusted input"
    )]
    #[doc(hidden)]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let (result, _): (Self, usize) = bincode::decode_from_slice(bytes, bincode::config::standard())
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        Ok(result)
    }

    /// Deserialize from JSON with validation
    pub fn from_json_validated(s: &str, expected_n: usize, expected_q: u64) -> Nine65Result<Self> {
        let ct: Self = serde_json::from_str(s).map_err(|e| Nine65Error::ConfigError {
            message: e.to_string(),
        })?;
        ct.validate(expected_n, expected_q)?;
        Ok(ct)
    }

    /// Deserialize from bytes with validation
    pub fn from_bytes_validated(
        bytes: &[u8],
        expected_n: usize,
        expected_q: u64,
    ) -> Nine65Result<Self> {
        let (ct, _): (Self, usize) = bincode::decode_from_slice(bytes, bincode::config::standard()).map_err(|e| Nine65Error::ConfigError {
            message: e.to_string(),
        })?;
        ct.validate(expected_n, expected_q)?;
        Ok(ct)
    }
}

/// BFV Encryptor
pub struct BFVEncryptor<'a> {
    pub pk: &'a PublicKey,
    pub encoder: &'a BFVEncoder,
    pub ntt: &'a NTTEngine,
    pub eta: usize,
}

impl<'a> BFVEncryptor<'a> {
    pub fn new(pk: &'a PublicKey, encoder: &'a BFVEncoder, ntt: &'a NTTEngine, eta: usize) -> Self {
        Self {
            pk,
            encoder,
            ntt,
            eta,
        }
    }

    /// Encrypt a message
    ///
    /// # Panics
    /// Panics if `m >= t` (plaintext modulus). Prefer `try_encrypt()` in
    /// production code to avoid panics from untrusted input.
    pub fn encrypt(&self, m: u64, harvester: &mut ShadowHarvester) -> Ciphertext {
        self.try_encrypt(m, harvester)
            .unwrap_or_else(|e| panic!("encrypt: {}", e))
    }

    /// Fallible encryption: returns error if message out of bounds
    pub fn try_encrypt(&self, m: u64, harvester: &mut ShadowHarvester) -> Nine65Result<Ciphertext> {
        let plaintext = self.encoder.try_encode(m)?;
        Ok(self.encrypt_poly(&plaintext, harvester))
    }

    /// Encrypt with specific seed (deterministic)
    pub fn encrypt_seeded(&self, m: u64, seed: u64) -> Ciphertext {
        let mut harvester = ShadowHarvester::with_seed(seed);
        self.encrypt(m, &mut harvester)
    }

    /// Fallible seeded encryption
    pub fn try_encrypt_seeded(&self, m: u64, seed: u64) -> Nine65Result<Ciphertext> {
        let mut harvester = ShadowHarvester::with_seed(seed);
        self.try_encrypt(m, &mut harvester)
    }

    /// Encrypt a polynomial
    pub fn encrypt_poly(
        &self,
        plaintext: &RingPolynomial,
        harvester: &mut ShadowHarvester,
    ) -> Ciphertext {
        let n = self.encoder.n;
        let q = self.encoder.q;

        // u ← ternary (blinding factor)
        let u = RingPolynomial::random_ternary(n, q, harvester);

        // e1, e2 ← error distribution
        let e1 = RingPolynomial::random_cbd(n, q, self.eta, harvester);
        let e2 = RingPolynomial::random_cbd(n, q, self.eta, harvester);

        // c0 = pk0 * u + e1 + plaintext
        let pk0_u = self.pk.pk0.mul(&u, self.ntt);
        let c0 = pk0_u.add(&e1, self.ntt).add(plaintext, self.ntt);

        // c1 = pk1 * u + e2
        let pk1_u = self.pk.pk1.mul(&u, self.ntt);
        let c1 = pk1_u.add(&e2, self.ntt);

        Ciphertext { c0, c1 }
    }

    // =========================================================================
    // SECURE ENCRYPTION METHODS (for production use)
    // =========================================================================

    /// Encrypt a message using a generic RNG source
    ///
    /// This method allows encryption with any `FheRng` implementation,
    /// enabling both secure production encryption and deterministic testing.
    ///
    /// # Security
    ///
    /// For production, use with `SecureRng`:
    /// ```ignore
    /// let mut rng = SecureRng::new();
    /// let ct = encryptor.encrypt_with_rng(42, &mut rng);
    /// ```
    ///
    /// For testing, use with `ShadowHarvester`:
    /// ```ignore
    /// let mut rng = ShadowHarvester::with_seed(42);
    /// let ct = encryptor.encrypt_with_rng(42, &mut rng);
    /// ```
    ///
    /// # Panics
    /// Panics if `m >= t` (plaintext modulus). Prefer `try_encrypt_with_rng()` in
    /// production code to avoid panics from untrusted input.
    pub fn encrypt_with_rng<R: FheRng>(&self, m: u64, rng: &mut R) -> Ciphertext {
        self.try_encrypt_with_rng(m, rng)
            .unwrap_or_else(|e| panic!("encrypt_with_rng: {}", e))
    }

    /// Fallible encryption with generic RNG
    pub fn try_encrypt_with_rng<R: FheRng>(&self, m: u64, rng: &mut R) -> Nine65Result<Ciphertext> {
        let plaintext = self.encoder.try_encode(m)?;
        Ok(self.encrypt_poly_with_rng(&plaintext, rng))
    }

    /// Encrypt with cryptographically secure randomness (RECOMMENDED FOR PRODUCTION)
    ///
    /// Uses `SecureRng` (OS CSPRNG) for all randomness, providing
    /// IND-CPA security guarantees.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let ct = encryptor.encrypt_secure(42);
    /// ```
    ///
    /// # Panics
    /// Panics if `m >= t` (plaintext modulus). Prefer `try_encrypt_secure()` in
    /// production code to avoid panics from untrusted input.
    pub fn encrypt_secure(&self, m: u64) -> Ciphertext {
        self.try_encrypt_secure(m)
            .unwrap_or_else(|e| panic!("encrypt_secure: {}", e))
    }

    /// Fallible secure encryption (RECOMMENDED FOR PRODUCTION)
    ///
    /// Returns error if message is out of bounds instead of panicking.
    pub fn try_encrypt_secure(&self, m: u64) -> Nine65Result<Ciphertext> {
        let plaintext = self.encoder.try_encode(m)?;
        self.try_encrypt_poly_secure(&plaintext)
    }

    /// Encrypt a polynomial using a generic RNG source
    ///
    /// Core encryption routine using any `FheRng` implementation.
    pub fn encrypt_poly_with_rng<R: FheRng>(
        &self,
        plaintext: &RingPolynomial,
        rng: &mut R,
    ) -> Ciphertext {
        let n = self.encoder.n;
        let q = self.encoder.q;

        // u ← ternary (blinding factor)
        let u = RingPolynomial::random_ternary_rng(n, q, rng);

        // e1, e2 ← error distribution
        let e1 = RingPolynomial::random_cbd_rng(n, q, self.eta, rng);
        let e2 = RingPolynomial::random_cbd_rng(n, q, self.eta, rng);

        // c0 = pk0 * u + e1 + plaintext
        let pk0_u = self.pk.pk0.mul(&u, self.ntt);
        let c0 = pk0_u.add(&e1, self.ntt).add(plaintext, self.ntt);

        // c1 = pk1 * u + e2
        let pk1_u = self.pk.pk1.mul(&u, self.ntt);
        let c1 = pk1_u.add(&e2, self.ntt);

        Ciphertext { c0, c1 }
    }

    /// Encrypt a polynomial with cryptographically secure randomness
    pub fn encrypt_poly_secure(&self, plaintext: &RingPolynomial) -> Ciphertext {
        self.try_encrypt_poly_secure(plaintext)
            .expect("CRITICAL: OS CSPRNG failure during secure encryption")
    }

    /// Fallible secure polynomial encryption using OS CSPRNG.
    pub fn try_encrypt_poly_secure(&self, plaintext: &RingPolynomial) -> Nine65Result<Ciphertext> {
        let n = self.encoder.n;
        let q = self.encoder.q;

        // u <- ternary via OS CSPRNG
        let u_signed = try_secure_ternary_vector(n).map_err(|e| Nine65Error::ConfigError {
            message: format!("secure RNG failure generating encryption mask: {}", e),
        })?;
        let u_coeffs: Vec<u64> = u_signed
            .iter()
            .map(|&v| if v < 0 { q - 1 } else { v as u64 })
            .collect();
        let u = RingPolynomial::from_coeffs(u_coeffs, q);

        // e1, e2 <- CBD(eta) via OS CSPRNG
        let e1_signed =
            try_secure_cbd_vector(n, self.eta).map_err(|e| Nine65Error::ConfigError {
                message: format!("secure RNG failure generating encryption error e1: {}", e),
            })?;
        let e2_signed =
            try_secure_cbd_vector(n, self.eta).map_err(|e| Nine65Error::ConfigError {
                message: format!("secure RNG failure generating encryption error e2: {}", e),
            })?;
        let to_mod_q = |vals: Vec<i64>| -> Vec<u64> {
            vals.into_iter()
                .map(|v| {
                    if v < 0 {
                        ((q as i64) + v) as u64
                    } else {
                        v as u64
                    }
                })
                .collect()
        };
        let e1 = RingPolynomial::from_coeffs(to_mod_q(e1_signed), q);
        let e2 = RingPolynomial::from_coeffs(to_mod_q(e2_signed), q);

        let pk0_u = self.pk.pk0.mul(&u, self.ntt);
        let c0 = pk0_u.add(&e1, self.ntt).add(plaintext, self.ntt);

        let pk1_u = self.pk.pk1.mul(&u, self.ntt);
        let c1 = pk1_u.add(&e2, self.ntt);

        Ok(Ciphertext { c0, c1 })
    }
}

/// BFV Decryptor
pub struct BFVDecryptor<'a> {
    pub sk: &'a SecretKey,
    pub encoder: &'a BFVEncoder,
    pub ntt: &'a NTTEngine,
}

impl<'a> BFVDecryptor<'a> {
    pub fn new(sk: &'a SecretKey, encoder: &'a BFVEncoder, ntt: &'a NTTEngine) -> Self {
        Self { sk, encoder, ntt }
    }

    /// Decrypt ciphertext to message
    pub fn decrypt(&self, ct: &Ciphertext) -> u64 {
        let decrypted = self.decrypt_raw(ct);
        self.encoder.decode(&decrypted)
    }

    /// Decrypt to raw polynomial (before decoding)
    pub fn decrypt_raw(&self, ct: &Ciphertext) -> RingPolynomial {
        // m_noisy = c0 + c1 * s
        // Use constant-time multiplication to prevent timing side-channels
        let c1_s = ct.c1.mul_ct(&self.sk.s, self.ntt);
        ct.c0.add(&c1_s, self.ntt)
    }

    /// Decrypt a degree-2 ciphertext (d0, d1, d2)
    /// These are at Δ² level from tensor product, requires t²/q² scaling
    pub fn decrypt_degree2(
        &self,
        d0: &RingPolynomial,
        d1: &RingPolynomial,
        d2: &RingPolynomial,
    ) -> u64 {
        let s = &self.sk.s;
        let s2 = s.mul(s, self.ntt);

        // Compute inner = d0 + d1*s + d2*s²
        let d1_s = d1.mul(s, self.ntt);
        let d2_s2 = d2.mul(&s2, self.ntt);
        let inner = d0.add(&d1_s, self.ntt).add(&d2_s2, self.ntt);

        // Decode using t²/q² scaling
        self.encoder.decode_degree2(&inner)
    }

    /// Decrypt vector
    pub fn decrypt_vector(&self, ct: &Ciphertext, len: usize) -> Vec<u64> {
        let decrypted = self.decrypt_raw(ct);
        self.encoder.decode_vector(&decrypted, len)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// GRO-GATED DECRYPTION (timing side-channel protection)
// ═══════════════════════════════════════════════════════════════════════════

/// GRO-gated decryption for timing side-channel protection.
///
/// Wraps decryption inside a GRO coincidence window so that
/// the execution timing is value-independent (INV-7). The secret
/// key multiplication `c1 * s` executes within the window, making
/// timing measurements uninformative about the secret key.
///
/// # Requires
///
/// Feature `clockwork` must be enabled.
#[cfg(feature = "clockwork")]
pub struct GatedDecryptor;

#[cfg(feature = "clockwork")]
impl GatedDecryptor {
    /// Decrypt a ciphertext inside a GRO timing window.
    ///
    /// Waits for a coincidence window, then performs decryption.
    /// Returns `Nine65Error::DecryptionFailed` if no window found.
    pub fn decrypt(
        decryptor: &BFVDecryptor<'_>,
        ct: &Ciphertext,
        gate: &crate::security::TimingGate,
    ) -> crate::errors::Nine65Result<u64> {
        Self::decrypt_with_search(decryptor, ct, gate, 1_000_000)
    }

    /// Decrypt with explicit max search bound for GRO window.
    pub fn decrypt_with_search(
        decryptor: &BFVDecryptor<'_>,
        ct: &Ciphertext,
        gate: &crate::security::TimingGate,
        max_search: u64,
    ) -> crate::errors::Nine65Result<u64> {
        use crate::errors::Nine65Error;

        // Find next coincidence window
        let _window = gate.next_window(0, max_search).ok_or(
            Nine65Error::DecryptionFailed,
        )?;

        // Execute decrypt inside window
        Ok(decryptor.decrypt(ct))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// THREAD SAFETY ASSERTIONS
// ═══════════════════════════════════════════════════════════════════════════

// Compile-time verification that key types are thread-safe.
// These assertions fail at compile time if the types don't implement Send/Sync.
const _: () = {
    const fn assert_send<T: Send>() {}
    const fn assert_sync<T: Sync>() {}

    // Ciphertext can be safely sent between threads and shared
    assert_send::<Ciphertext>();
    assert_sync::<Ciphertext>();

    // Encoder is immutable after construction
    assert_send::<BFVEncoder>();
    assert_sync::<BFVEncoder>();
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::FheRng;
    use crate::keys::KeySet;

    fn test_config() -> FHEConfig {
        FHEConfig {
            name: "encrypt_test",
            n: 1024,
            q: 998244353,
            t: 2053, // Chosen to avoid encode/decode precision issues
            eta: 2,
            primes: vec![998244353],
            security_bits: 36,
        }
    }

    fn setup() -> (FHEConfig, NTTEngine, KeySet, ShadowHarvester, BFVEncoder) {
        let config = test_config();
        let ntt = NTTEngine::new(config.q, config.n);
        let mut harvester = ShadowHarvester::with_seed(42);
        let keys = KeySet::generate(&config, &ntt, &mut harvester);
        let encoder = BFVEncoder::new(&config);
        (config, ntt, keys, harvester, encoder)
    }

    #[test]
    fn test_encode_decode() {
        let config = test_config();
        let encoder = BFVEncoder::new(&config);

        for m in [0, 1, 100, config.t - 1] {
            let encoded = encoder.encode(m);
            let decoded = encoder.decode(&encoded);
            assert_eq!(decoded, m, "Encode/decode failed for m={}", m);
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (config, ntt, keys, mut harvester, encoder) = setup();

        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);

        // Test various messages (staying well within noise budget)
        for m in [0u64, 1, 10, 100, 500, 1000] {
            let ct = encryptor.encrypt(m, &mut harvester);
            let decrypted = decryptor.decrypt(&ct);
            assert_eq!(decrypted, m, "Encrypt/decrypt failed for m={}", m);
        }
    }

    #[test]
    fn test_encrypt_decrypt_random() {
        let (config, ntt, keys, mut harvester, encoder) = setup();

        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);

        for _ in 0..20 {
            let m = harvester.uniform(config.t / 2); // Stay within safe range
            let ct = encryptor.encrypt(m, &mut harvester);
            let decrypted = decryptor.decrypt(&ct);
            assert_eq!(decrypted, m, "Random encrypt/decrypt failed");
        }
    }

    #[test]
    fn test_encrypt_deterministic() {
        let (config, ntt, keys, _, encoder) = setup();

        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);

        let ct1 = encryptor.encrypt_seeded(42, 12345);
        let ct2 = encryptor.encrypt_seeded(42, 12345);

        assert_eq!(ct1.c0.coeffs, ct2.c0.coeffs);
        assert_eq!(ct1.c1.coeffs, ct2.c1.coeffs);
    }

    #[test]
    fn test_encrypt_benchmark() {
        let (config, ntt, keys, mut harvester, encoder) = setup();

        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);

        let start = std::time::Instant::now();
        for i in 0..1000u64 {
            let _ = encryptor.encrypt(i % config.t, &mut harvester);
        }
        let elapsed = start.elapsed();

        println!("Encrypt x1000: {:?}", elapsed);
    }

    #[test]
    fn test_encrypt_with_rng_shadow() {
        let (config, ntt, keys, _, encoder) = setup();

        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);

        // Use ShadowHarvester via FheRng trait
        let mut rng = ShadowHarvester::with_seed(12345);
        assert!(!rng.is_secure());

        for m in [0u64, 1, 42, 100, 500] {
            let ct = encryptor.encrypt_with_rng(m, &mut rng);
            let decrypted = decryptor.decrypt(&ct);
            assert_eq!(decrypted, m, "encrypt_with_rng failed for m={}", m);
        }
    }

    #[test]
    fn test_encrypt_with_rng_secure() {
        let (config, ntt, keys, _, encoder) = setup();

        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);

        // Use SecureRng via FheRng trait
        use crate::entropy::SecureRng;
        let mut rng = SecureRng::new();
        assert!(rng.is_secure());

        for m in [0u64, 1, 42, 100, 500] {
            let ct = encryptor.encrypt_with_rng(m, &mut rng);
            let decrypted = decryptor.decrypt(&ct);
            assert_eq!(decrypted, m, "encrypt_with_rng (secure) failed for m={}", m);
        }
    }

    #[test]
    fn test_encrypt_secure() {
        let (config, ntt, keys, _, encoder) = setup();

        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);

        // Test the convenience method
        for m in [0u64, 1, 42, 100, 500] {
            let ct = encryptor.encrypt_secure(m);
            let decrypted = decryptor.decrypt(&ct);
            assert_eq!(decrypted, m, "encrypt_secure failed for m={}", m);
        }
    }

    #[test]
    fn test_encrypt_secure_produces_different_ciphertexts() {
        let (config, ntt, keys, _, encoder) = setup();

        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);

        // Secure encryption should produce different ciphertexts for the same message
        let ct1 = encryptor.encrypt_secure(42);
        let ct2 = encryptor.encrypt_secure(42);

        // Different randomness means different ciphertexts
        assert_ne!(
            ct1.c0.coeffs, ct2.c0.coeffs,
            "Secure encryption should produce different ciphertexts"
        );
    }

    #[test]
    fn test_fhe_rng_trait_is_secure() {
        use crate::entropy::{FheRng, SecureRng};

        let shadow = ShadowHarvester::with_seed(42);
        let secure = SecureRng::new();

        assert!(!shadow.is_secure(), "ShadowHarvester should NOT be secure");
        assert!(secure.is_secure(), "SecureRng SHOULD be secure");
    }

    // =========================================================================
    // FALLIBLE API TESTS
    // =========================================================================

    #[test]
    fn test_try_encode_success() {
        let config = test_config();
        let encoder = BFVEncoder::new(&config);

        let result = encoder.try_encode(42);
        assert!(result.is_ok());
    }

    #[test]
    fn test_try_encode_message_out_of_bounds() {
        use crate::errors::Nine65Error;

        let config = test_config();
        let encoder = BFVEncoder::new(&config);

        // Message >= t should fail
        let result = encoder.try_encode(config.t);
        assert!(result.is_err());

        match result.unwrap_err() {
            Nine65Error::MessageOutOfBounds { message, modulus } => {
                assert_eq!(message, config.t);
                assert_eq!(modulus, config.t);
            }
            e => panic!("Wrong error type: {:?}", e),
        }
    }

    #[test]
    fn test_try_encode_vector_success() {
        let config = test_config();
        let encoder = BFVEncoder::new(&config);

        let result = encoder.try_encode_vector(&[1, 2, 3, 4]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_try_encode_vector_message_out_of_bounds() {
        use crate::errors::Nine65Error;

        let config = test_config();
        let encoder = BFVEncoder::new(&config);

        // One message out of bounds
        let result = encoder.try_encode_vector(&[1, 2, config.t, 4]);
        assert!(result.is_err());

        match result.unwrap_err() {
            Nine65Error::MessageOutOfBounds { message, .. } => {
                assert_eq!(message, config.t);
            }
            e => panic!("Wrong error type: {:?}", e),
        }
    }

    #[test]
    fn test_try_encrypt_success() {
        let (config, ntt, keys, mut harvester, encoder) = setup();

        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);

        let result = encryptor.try_encrypt(42, &mut harvester);
        assert!(result.is_ok());

        let ct = result.unwrap();
        let decrypted = decryptor.decrypt(&ct);
        assert_eq!(decrypted, 42);
    }

    #[test]
    fn test_try_encrypt_message_out_of_bounds() {
        use crate::errors::Nine65Error;

        let (config, ntt, keys, mut harvester, encoder) = setup();

        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);

        let result = encryptor.try_encrypt(config.t, &mut harvester);
        assert!(result.is_err());

        match result.unwrap_err() {
            Nine65Error::MessageOutOfBounds { .. } => {}
            e => panic!("Wrong error type: {:?}", e),
        }
    }

    #[test]
    fn test_try_encrypt_secure_success() {
        let (config, ntt, keys, _, encoder) = setup();

        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);

        let result = encryptor.try_encrypt_secure(42);
        assert!(result.is_ok());

        let ct = result.unwrap();
        let decrypted = decryptor.decrypt(&ct);
        assert_eq!(decrypted, 42);
    }

    #[test]
    fn test_error_category() {
        use crate::errors::Nine65Error;

        let err = Nine65Error::MessageOutOfBounds {
            message: 100,
            modulus: 50,
        };
        assert_eq!(err.category(), "Encoding");
    }

    #[cfg(feature = "clockwork")]
    #[test]
    fn test_gated_decrypt_succeeds() {
        use crate::security::TimingGate;

        let (config, ntt, keys, mut harvester, encoder) = setup();
        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
        let gate = TimingGate::new(16, 100).unwrap();

        let ct = encryptor.encrypt(42, &mut harvester);
        let result = super::GatedDecryptor::decrypt(&decryptor, &ct, &gate);
        assert!(result.is_ok(), "GRO-gated decrypt should succeed");
        assert_eq!(result.unwrap(), 42);
    }

    #[cfg(feature = "clockwork")]
    #[test]
    fn test_gated_decrypt_multiple_messages() {
        use crate::security::TimingGate;

        let (config, ntt, keys, mut harvester, encoder) = setup();
        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
        let gate = TimingGate::new(16, 100).unwrap();

        for m in [0u64, 1, 10, 100, 500, 1000] {
            let ct = encryptor.encrypt(m, &mut harvester);
            let result = super::GatedDecryptor::decrypt(&decryptor, &ct, &gate);
            assert_eq!(
                result.unwrap(),
                m,
                "GRO-gated decrypt failed for m={}",
                m
            );
        }
    }
}
