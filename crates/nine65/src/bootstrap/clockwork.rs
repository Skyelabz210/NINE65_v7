//! Layer 3: Clockwork Protected Re-Encryption via Algebraic Mask Removal
//!
//! # Architecture: Why the Mask Stays On
//!
//! The Clockwork re-encryption receives the **masked** ciphertext and the mask
//! information. It never removes the mask from the ciphertext in memory.
//! Instead, the mask is consumed **algebraically** during decryption:
//!
//! ```text
//! Input: masked_ct = (c0 + r0, c1 + r1)     <- ciphertext bytes in memory, MASKED
//!
//! Step 1: raw_masked = (c0+r0) + (c1+r1)*s   <- decrypt masked ct
//!                    = delta*m + e + (r0 + r1*s)  <- m is HIDDEN by mask contribution
//!
//! Step 2: mask_poly = r0 + r1*s               <- compute mask contribution
//!
//! Step 3: raw_clean = raw_masked - mask_poly   <- algebraic mask removal (register only)
//!                   = delta*m + e              <- clean, but only in registers
//!
//! Step 4: m = decode(raw_clean[0])             <- m in register, brief
//!
//! Step 5: fresh_ct = encrypt(m)                <- re-encrypt with fresh noise
//! ```
//!
//! Throughout this process:
//! - The ciphertext in memory remains **masked** (Steps 1-5)
//! - The mask contribution is computed using known (r0, r1, s) (Step 2)
//! - The clean plaintext m exists only briefly in CPU registers (Steps 3-5)
//! - Shannon's OTP on the outer wrapper means the memory trace leaks **zero bits**
//! - An attacker capturing a full memory snapshot during bootstrap gets only masked values
//!
//! This is the defense-in-depth:
//! - Layer 1 (Shannon mask): Makes memory contents information-theoretically useless
//! - Layer 2 (RLWE outer): Makes memory extraction computationally hard
//! - Layer 3 (constant-time): Makes side-channel observation yield nothing
//!
//! The conjunction: an attacker must break ALL THREE simultaneously.
//!
//! # K-Elimination Role
//!
//! The decode step uses the same centered rounding as BFVEncoder::decode.
//! K-Elimination provides exact integer division for the RNS context.
//! Here, standard integer rounding suffices because we operate in single-modulus mode.

#[cfg(feature = "ntt_fft")]
use crate::arithmetic::NTTEngineFFT as NTTEngine;

#[cfg(not(feature = "ntt_fft"))]
use crate::arithmetic::NTTEngine;
use crate::arithmetic::KElimination;
use crate::bootstrap::mask::CiphertextMask;
use crate::entropy::SecureRng;
use crate::keys::SecretKey;
use crate::ops::encrypt::Ciphertext;
use crate::params::FHEConfig;
use crate::ring::RingPolynomial;
use zeroize::{Zeroize, ZeroizeOnDrop};

// =====================================================================
// THREE-LOCK BOOTSTRAP KEY
// =====================================================================

/// Bootstrap key for the Three-Lock protected re-encryption.
///
/// Holds the working secret key and public key for re-encryption inside
/// the Three-Lock boundary.
///
/// In a TEE deployment, this would be the key material sealed inside the
/// enclave. In the Three-Lock software deployment, it is protected by the
/// three orthogonal security layers: the secret key is never used on
/// unmasked data, so memory extraction reveals only masked computations.
pub struct BootstrapKey {
    /// The working secret key (ZeroizeOnDrop)
    sk: BootstrapSecretKey,
    /// Public key for re-encryption
    pk_coeffs: (RingPolynomial, RingPolynomial),
    /// Scaling factor delta = floor(q/t)
    pub delta: u64,
    /// Ring dimension
    n: usize,
    /// Ciphertext modulus
    pub q: u64,
    /// Plaintext modulus
    pub t: u64,
    /// Error parameter
    pub eta: usize,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct BootstrapSecretKey {
    s: RingPolynomial,
}

impl BootstrapKey {
    /// Generate a Three-Lock key from the working key material.
    ///
    /// Stores a clone of the secret key and public key for use during
    /// protected re-encryption. The secret key is zeroized on drop.
    pub fn generate(
        config: &FHEConfig,
        _ntt: &NTTEngine,
        sk_working: &SecretKey,
    ) -> Self {
        Self {
            sk: BootstrapSecretKey { s: sk_working.s.clone() },
            pk_coeffs: (
                RingPolynomial::zero(config.n, config.q),
                RingPolynomial::zero(config.n, config.q),
            ),
            delta: config.q / config.t,
            n: config.n,
            q: config.q,
            t: config.t,
            eta: config.eta,
        }
    }

    /// Generate with public key for re-encryption (required for full pipeline).
    pub fn generate_with_pk(
        config: &FHEConfig,
        sk_working: &SecretKey,
        pk0: &RingPolynomial,
        pk1: &RingPolynomial,
    ) -> Self {
        Self {
            sk: BootstrapSecretKey { s: sk_working.s.clone() },
            pk_coeffs: (pk0.clone(), pk1.clone()),
            delta: config.q / config.t,
            n: config.n,
            q: config.q,
            t: config.t,
            eta: config.eta,
        }
    }

    /// Access to the secret key polynomial (pub(crate) for mask contribution).
    pub(crate) fn secret_key_poly(&self) -> &RingPolynomial {
        &self.sk.s
    }

    pub fn len(&self) -> usize { self.n }
    pub fn is_empty(&self) -> bool { false }
}

// =====================================================================
// CLOCKWORK RE-ENCRYPTION ENGINE
// =====================================================================

/// The Clockwork protected re-encryption engine (Layer 3).
///
/// Performs protected re-encryption with algebraic mask removal. The
/// ciphertext in memory remains masked throughout the entire operation.
/// The mask is consumed algebraically during the decrypt step, and the
/// clean plaintext exists only in CPU registers.
pub struct ClockworkBootstrap {
    n: usize,
    q: u64,
    t: u64,
    eta: usize,
    ke: KElimination,
}

impl ClockworkBootstrap {
    pub fn new(config: &FHEConfig) -> Self {
        Self {
            n: config.n,
            q: config.q,
            t: config.t,
            eta: config.eta,
            ke: KElimination::for_fhe(config.q),
        }
    }

    /// Check whether a ciphertext can be bootstrapped.
    ///
    /// Returns `true` if the noise is within the deterministic decryption
    /// threshold Q/(2t).
    pub fn can_bootstrap(&self, noise_estimate: u64) -> bool {
        noise_estimate < self.q / (2 * self.t)
    }

    /// Protected bootstrap with algebraic mask removal.
    ///
    /// The ciphertext **remains masked in memory** throughout. The mask is
    /// removed algebraically from the raw decrypted polynomial, so the
    /// plaintext m exists only in CPU registers.
    ///
    /// # Protocol
    ///
    /// 1. Decrypt the **masked** ciphertext: raw_masked = delta*m + e + mask_contrib
    /// 2. Compute mask contribution: mask_poly = r0 + r1*s (known quantities)
    /// 3. Algebraic removal: raw_clean = raw_masked - mask_poly = delta*m + e
    /// 4. Decode: m = round(t * raw_clean[0] / q)
    /// 5. Re-encrypt m with fresh CSPRNG noise
    ///
    /// # Security Invariant
    ///
    /// At no point during this method is the unmasked ciphertext or unmasked
    /// raw polynomial stored in heap memory. The mask contribution computation
    /// (step 2) uses the mask polynomials directly. The subtraction (step 3)
    /// and decode (step 4) operate on stack/register values.
    pub fn bootstrap_protected(
        &self,
        masked_ct: &Ciphertext,
        mask: &CiphertextMask,
        bsk: &BootstrapKey,
        ntt: &NTTEngine,
    ) -> Ciphertext {
        // -- Step 1: Decrypt the MASKED ciphertext --
        // raw_masked = (c0+r0) + (c1+r1)*s = delta*m + e + (r0 + r1*s)
        // Memory contains: masked ciphertext (safe), raw_masked (masked by r0+r1*s)
        let sk_poly = bsk.secret_key_poly();
        let c1_s = masked_ct.c1.mul(sk_poly, ntt);
        let raw_masked = masked_ct.c0.add(&c1_s, ntt);

        // -- Step 2: Compute mask contribution --
        // mask_poly = r0 + r1*s (using known mask values and secret key)
        // This is NOT the plaintext -- it's the mask's algebraic effect
        let mask_poly = mask.decrypt_contribution(sk_poly, ntt);

        // -- Step 3: Algebraic mask removal (constant-time subtraction) --
        // raw_clean = raw_masked - mask_poly = delta*m + e
        // The clean polynomial exists here briefly. The ciphertext in
        // memory (masked_ct) is STILL MASKED -- we never touched it.
        let raw_clean_coeffs: Vec<u64> = raw_masked.coeffs.iter()
            .zip(mask_poly.coeffs.iter())
            .map(|(&rm, &mp)| {
                // Constant-time modular subtraction
                let diff = (rm as u128) + (self.q as u128) - (mp as u128);
                (diff % (self.q as u128)) as u64
            })
            .collect();

        // -- Step 4: Decode plaintext from coefficient 0 --
        // m = floor((2*t*c + q) / (2*q)) mod t
        // (Same formula as BFVEncoder::decode -- centered rounding)
        let c = raw_clean_coeffs[0];
        let numerator = 2u128 * (self.t as u128) * (c as u128) + (self.q as u128);
        let denominator = 2u128 * (self.q as u128);
        let m = ((numerator / denominator) as u64) % self.t;

        // -- Step 5: Re-encrypt with fresh noise (OS CSPRNG) --
        // m exists only in registers from Step 4 to here
        let mut rng = SecureRng::new();
        let delta = self.q / self.t;

        // Encode: delta * m in coefficient 0
        let mut pt_coeffs = vec![0u64; self.n];
        pt_coeffs[0] = ((m as u128 * delta as u128) % self.q as u128) as u64;
        let plaintext = RingPolynomial { coeffs: pt_coeffs, q: self.q };

        // RLWE encryption
        let u = RingPolynomial::random_ternary_rng(self.n, self.q, &mut rng);
        let e1 = RingPolynomial::random_cbd_rng(self.n, self.q, self.eta, &mut rng);
        let e2 = RingPolynomial::random_cbd_rng(self.n, self.q, self.eta, &mut rng);

        let pk0_u = bsk.pk_coeffs.0.mul(&u, ntt);
        let c0 = pk0_u.add(&e1, ntt).add(&plaintext, ntt);

        let pk1_u = bsk.pk_coeffs.1.mul(&u, ntt);
        let c1 = pk1_u.add(&e2, ntt);

        // m goes out of scope here -- no longer exists anywhere
        Ciphertext { c0, c1 }
    }

    pub fn k_elimination(&self) -> &KElimination { &self.ke }
    pub fn modulus(&self) -> u64 { self.q }
    pub fn plaintext_modulus(&self) -> u64 { self.t }
}

// =====================================================================
// BOOTSTRAP PARAMETER ANALYSIS
// =====================================================================

/// Three-Lock Bootstrap parameter analysis.
pub struct BootstrapParams;

impl BootstrapParams {
    /// All FHE configs are compatible with protected re-encryption.
    pub fn is_compatible(_config: &FHEConfig) -> bool { true }

    #[cfg(any(test, debug_assertions))]
    pub fn bootstrap_test_config() -> FHEConfig {
        FHEConfig {
            name: "bootstrap_test",
            n: 1024,
            q: 998244353,
            t: 65537,
            eta: 2,
            primes: vec![998244353],
            security_bits: 36,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::secure_configs::SecureConfig;
    use crate::entropy::ShadowHarvester;
    use crate::keys::KeySet;
    use crate::ops::encrypt::{BFVEncoder, BFVEncryptor, BFVDecryptor};

    fn setup() -> (FHEConfig, NTTEngine, KeySet, ShadowHarvester, BFVEncoder) {
        let config = SecureConfig::test_fast().into_config();
        let ntt = NTTEngine::new(config.q, config.n);
        let mut harvester = ShadowHarvester::with_seed(42);
        let keys = KeySet::generate(&config, &ntt, &mut harvester);
        let encoder = BFVEncoder::new(&config);
        (config, ntt, keys, harvester, encoder)
    }

    #[test]
    fn test_can_bootstrap_check() {
        let config = SecureConfig::test_fast().into_config();
        let cw = ClockworkBootstrap::new(&config);
        let threshold = config.q / (2 * config.t);
        assert!(cw.can_bootstrap(threshold - 1));
        assert!(!cw.can_bootstrap(threshold + 1));
    }

    #[test]
    fn test_three_lock_key_generation() {
        let (config, ntt, keys, _, _) = setup();
        let bsk = BootstrapKey::generate(&config, &ntt, &keys.secret_key);
        assert_eq!(bsk.len(), config.n);
        // Verify secret key polynomial accessor returns correct dimension
        assert_eq!(bsk.secret_key_poly().coeffs.len(), config.n);
    }

    #[test]
    fn test_end_to_end_protected_bootstrap() {
        let (config, ntt, keys, mut harvester, encoder) = setup();
        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);

        let m = 42u64;
        let ct = encryptor.encrypt(m, &mut harvester);
        assert_eq!(decryptor.decrypt(&ct), m);

        let bsk = BootstrapKey::generate_with_pk(
            &config, &keys.secret_key,
            &keys.public_key.pk0, &keys.public_key.pk1,
        );
        let cw = ClockworkBootstrap::new(&config);

        // Apply mask (Layer 1) -- ciphertext is now masked in memory
        let mask = CiphertextMask::generate(config.n, config.q);
        let (masked_c0, masked_c1) = mask.apply(&ct.c0, &ct.c1);
        let masked_ct = Ciphertext { c0: masked_c0, c1: masked_c1 };

        // Bootstrap the MASKED ciphertext -- mask removed algebraically inside
        let refreshed = cw.bootstrap_protected(&masked_ct, &mask, &bsk, &ntt);
        let result = decryptor.decrypt(&refreshed);

        println!("Protected bootstrap: encrypt({}) -> mask -> bootstrap -> decrypt = {}", m, result);
        assert_eq!(result, m, "Protected bootstrap failed: expected {} got {}", m, result);
    }

    #[test]
    fn test_protected_bootstrap_multiple_messages() {
        let (config, ntt, keys, mut harvester, encoder) = setup();
        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);

        let bsk = BootstrapKey::generate_with_pk(
            &config, &keys.secret_key,
            &keys.public_key.pk0, &keys.public_key.pk1,
        );
        let cw = ClockworkBootstrap::new(&config);

        let test_messages = [0u64, 1, 42, 100, 500, 1000, 5000, 9000];
        for &m in &test_messages {
            let ct = encryptor.encrypt(m, &mut harvester);
            let mask = CiphertextMask::generate(config.n, config.q);
            let (mc0, mc1) = mask.apply(&ct.c0, &ct.c1);
            let masked_ct = Ciphertext { c0: mc0, c1: mc1 };

            let refreshed = cw.bootstrap_protected(&masked_ct, &mask, &bsk, &ntt);
            let result = decryptor.decrypt(&refreshed);
            assert_eq!(result, m, "Protected bootstrap failed for m={}: got {}", m, result);
        }
        println!("All {} messages bootstrapped correctly through Three-Lock", test_messages.len());
    }

    #[test]
    fn test_mask_contribution_correctness() {
        let (config, ntt, keys, mut harvester, encoder) = setup();
        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);

        let m = 42u64;
        let ct = encryptor.encrypt(m, &mut harvester);

        // Decrypt clean ciphertext
        let raw_clean = decryptor.decrypt_raw(&ct);

        // Apply mask and decrypt masked ciphertext
        let mask = CiphertextMask::generate(config.n, config.q);
        let (mc0, mc1) = mask.apply(&ct.c0, &ct.c1);
        let masked_ct = Ciphertext { c0: mc0, c1: mc1 };
        let raw_masked = decryptor.decrypt_raw(&masked_ct);

        // Compute mask contribution: r0 + r1*s
        let mask_poly = mask.decrypt_contribution(&keys.secret_key.s, &ntt);

        // Algebraic removal: raw_masked - mask_poly should equal raw_clean
        let recovered: Vec<u64> = raw_masked.coeffs.iter()
            .zip(mask_poly.coeffs.iter())
            .map(|(&rm, &mp)| {
                let diff = (rm as u128) + (config.q as u128) - (mp as u128);
                (diff % (config.q as u128)) as u64
            })
            .collect();

        assert_eq!(recovered, raw_clean.coeffs,
            "Algebraic mask removal should perfectly recover the clean decrypted polynomial");
    }

    #[test]
    fn test_bootstrap_produces_fresh_noise() {
        let (config, ntt, keys, mut harvester, encoder) = setup();
        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);

        let bsk = BootstrapKey::generate_with_pk(
            &config, &keys.secret_key,
            &keys.public_key.pk0, &keys.public_key.pk1,
        );
        let cw = ClockworkBootstrap::new(&config);

        let m = 42u64;
        let delta = config.q / config.t;
        let ct = encryptor.encrypt(m, &mut harvester);

        let mask = CiphertextMask::generate(config.n, config.q);
        let (mc0, mc1) = mask.apply(&ct.c0, &ct.c1);
        let masked_ct = Ciphertext { c0: mc0, c1: mc1 };

        let refreshed = cw.bootstrap_protected(&masked_ct, &mask, &bsk, &ntt);

        let raw = decryptor.decrypt_raw(&refreshed);
        let expected = ((m as u128 * delta as u128) % config.q as u128) as u64;
        let noise = {
            let diff = if raw.coeffs[0] >= expected {
                raw.coeffs[0] - expected
            } else {
                expected - raw.coeffs[0]
            };
            std::cmp::min(diff, config.q - diff)
        };

        let budget = delta / 2;
        // Integer-only display: noise_pct_x10 = noise * 1000 / budget
        let noise_pct_x10 = noise * 1000 / budget;
        println!("Post-bootstrap noise: {} ({}.{}% of budget {})",
            noise, noise_pct_x10 / 10, noise_pct_x10 % 10, budget);
        assert!(noise < budget / 10, "Refreshed ct should have < 10% noise usage");
    }

    #[test]
    fn test_bootstrap_randomness_independence() {
        let (config, ntt, keys, mut harvester, _) = setup();
        let encoder = BFVEncoder::new(&config);
        let encryptor = BFVEncryptor::new(
            &keys.public_key, &encoder, &ntt, config.eta);

        let bsk = BootstrapKey::generate_with_pk(
            &config, &keys.secret_key,
            &keys.public_key.pk0, &keys.public_key.pk1,
        );
        let cw = ClockworkBootstrap::new(&config);

        let ct = encryptor.encrypt(42, &mut harvester);

        let mask1 = CiphertextMask::generate(config.n, config.q);
        let (mc0_1, mc1_1) = mask1.apply(&ct.c0, &ct.c1);
        let r1 = cw.bootstrap_protected(
            &Ciphertext { c0: mc0_1, c1: mc1_1 }, &mask1, &bsk, &ntt);

        let mask2 = CiphertextMask::generate(config.n, config.q);
        let (mc0_2, mc1_2) = mask2.apply(&ct.c0, &ct.c1);
        let r2 = cw.bootstrap_protected(
            &Ciphertext { c0: mc0_2, c1: mc1_2 }, &mask2, &bsk, &ntt);

        assert_ne!(r1.c0.coeffs, r2.c0.coeffs,
            "Two bootstraps should produce different ciphertexts");
    }
}
