//! Three-Lock Bootstrap -- Nested Defense-in-Depth for Protected Re-Encryption
//!
//! # Why Three Locks?
//!
//! Re-encryption requires knowing the plaintext m. For one split second,
//! m must exist -- in a register, on a bus, somewhere physical. The
//! Three-Lock construction exists to protect that split second with
//! three simultaneous, orthogonal security barriers.
//!
//! # Nested Architecture
//!
//! ```text
//! +-------------------------------------------------------------+
//! |  SHANNON (Layer 1 -- outermost)                              |
//! |  Information-theoretic mask over EVERYTHING below             |
//! |  All memory traces during bootstrap are uniformly random      |
//! |                                                               |
//! |  +-----------------------------------------------------------+
//! |  |  MONTGOMERY (Layer 2 -- middle)                           |
//! |  |  RLWE encryption around the masked ciphertext             |
//! |  |  Even if Shannon somehow fails, RLWE must still be broken |
//! |  |                                                           |
//! |  |  +-------------------------------------------------------+
//! |  |  |  CLOCKWORK (Layer 3 -- innermost)                     |
//! |  |  |  Protected re-encryption                              |
//! |  |  |  m exists briefly in registers, shielded by both      |
//! |  |  |  Shannon AND Montgomery                               |
//! |  |  +-------------------------------------------------------+
//! |  +-----------------------------------------------------------+
//! +-------------------------------------------------------------+
//! ```
//!
//! # Pipeline
//!
//! ```text
//! INPUT: exhausted ct = (c0, c1) under sk_working
//!
//! LOCK (apply from outside in):
//!   Shannon:    masked_ct = (c0 + r0, c1 + r1)
//!   Montgomery: outer_ct = RLWE.Enc(sk_outer, masked_ct)
//!
//! UNLOCK + REFRESH (peel from outside in, Clockwork stays inside):
//!   Montgomery: dec -> masked_ct              <- Shannon still active
//!   Clockwork:  decrypt masked_ct with sk     <- gets delta*m + e + mask_contribution
//!               subtract mask algebraically   <- m in registers, protected
//!               re-encrypt(m) -> fresh_ct     <- done, m discarded
//!
//! OUTPUT: fresh ct under sk_working, full noise budget
//! ```
//!
//! The mask is NEVER removed from the ciphertext in memory. The outer RLWE
//! is decrypted to yield the still-masked ciphertext. Clockwork receives the
//! masked ciphertext and the mask, removes the mask algebraically during
//! decryption, and re-encrypts. At every point, memory contains only
//! Shannon-masked values.

use crate::arithmetic::NTTEngine;

use crate::bootstrap::clockwork::{BootstrapKey, ClockworkBootstrap};
use crate::bootstrap::mask::CiphertextMask;
use crate::bootstrap::outer::{OuterCiphertextPair, OuterLayer};
use crate::ops::encrypt::Ciphertext;
use crate::params::FHEConfig;

/// Statistics from a single Three-Lock Bootstrap execution.
///
/// All timing values are in nanoseconds (integer). Display methods
/// use integer arithmetic only (no floating-point).
#[derive(Clone, Debug)]
pub struct BootstrapStats {
    /// Time to apply Shannon mask (Layer 1)
    pub shannon_mask_ns: u64,
    /// Time for Montgomery outer RLWE encrypt (Layer 2)
    pub montgomery_encrypt_ns: u64,
    /// Time for Montgomery outer RLWE decrypt (peeling Layer 2)
    pub montgomery_decrypt_ns: u64,
    /// Time for Clockwork protected re-encryption (Layer 3, inside both locks)
    pub clockwork_ns: u64,
    /// Total wall-clock time
    pub total_ns: u64,
    /// Whether the outer key was rotated after this bootstrap
    pub key_rotated: bool,
}

impl BootstrapStats {
    /// Total time in microseconds (integer division).
    pub fn total_us(&self) -> u64 {
        self.total_ns / 1000
    }

    /// Overhead ratio x100 (100 = 1.0x, 250 = 2.5x).
    pub fn overhead_ratio_x100(&self) -> u64 {
        if self.clockwork_ns == 0 {
            return 0;
        }
        self.total_ns * 100 / self.clockwork_ns
    }
}

impl std::fmt::Display for BootstrapStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Integer-only display: all times in microseconds
        write!(
            f,
            "Three-Lock: {}us total ({}us shannon, {}us mont_enc, \
                   {}us mont_dec, {}us clockwork) \
                   overhead={}.{}x rotated={}",
            self.total_ns / 1000,
            self.shannon_mask_ns / 1000,
            self.montgomery_encrypt_ns / 1000,
            self.montgomery_decrypt_ns / 1000,
            self.clockwork_ns / 1000,
            self.overhead_ratio_x100() / 100,
            self.overhead_ratio_x100() % 100,
            self.key_rotated,
        )
    }
}

/// Security tier controlling key rotation policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityTier {
    /// Per-bootstrap outer key rotation. TEE + watchdog + Faraday cage.
    Tier1Maximum,
    /// Per-session outer key rotation. Bare metal + TRESOR + IOMMU.
    Tier2Production,
    /// Static outer key. Standard cloud VM.
    Tier3Commodity,
}

/// The Three-Lock Bootstrap.
///
/// Nested defense-in-depth: Shannon wraps Montgomery wraps Clockwork.
/// The plaintext m is protected by all three layers during the
/// unavoidable split-second it exists during re-encryption.
pub struct ThreeLockBootstrap {
    clockwork: ClockworkBootstrap,
    outer: OuterLayer,
    n: usize,
    q: u64,
    tier: SecurityTier,
    bootstrap_count: u64,
}

impl ThreeLockBootstrap {
    pub fn new(config: &FHEConfig, tier: SecurityTier) -> Self {
        Self {
            clockwork: ClockworkBootstrap::new(config),
            outer: OuterLayer::new(config.n, config.q, config.eta),
            n: config.n,
            q: config.q,
            tier,
            bootstrap_count: 0,
        }
    }

    /// Execute the Three-Lock Bootstrap with full nested protection.
    ///
    /// This is the **hot-path** method: zero `Instant::now()` syscalls.
    /// For timing instrumentation, use [`bootstrap_timed`](Self::bootstrap_timed).
    ///
    /// The mask passes through to Clockwork -- it is never removed from
    /// the ciphertext in memory. Clockwork handles mask removal
    /// algebraically during decryption.
    pub fn bootstrap(
        &mut self,
        ct: &Ciphertext,
        bsk: &BootstrapKey,
        ntt: &NTTEngine,
    ) -> Ciphertext {
        // =============================================================
        // LOCK PHASE: Apply layers from outside in
        // =============================================================

        // Layer 1 -- Shannon: mask the ciphertext.
        // From this point on, ALL memory traces are uniformly random.
        let mask = CiphertextMask::generate(self.n, self.q);
        let (masked_c0, masked_c1) = mask.apply(&ct.c0, &ct.c1);

        // Layer 2 -- Montgomery: RLWE-encrypt the masked ciphertext.
        let outer_pair = OuterCiphertextPair::encrypt(&self.outer, &masked_c0, &masked_c1, ntt);

        // =============================================================
        // UNLOCK + REFRESH: Peel Montgomery, pass mask through to Clockwork
        // =============================================================

        // Peel Layer 2 -- Montgomery decrypt.
        // Result is the STILL-MASKED ciphertext. Shannon is still active.
        let (dec_c0, dec_c1) = outer_pair.decrypt(&self.outer, ntt);

        // Layer 3 -- Clockwork: protected re-encryption.
        // Receives the MASKED ciphertext and the mask.
        // Removes the mask ALGEBRAICALLY during decryption (in registers).
        let masked_ct = Ciphertext {
            c0: dec_c0,
            c1: dec_c1,
        };
        let refreshed = self
            .clockwork
            .bootstrap_protected(&masked_ct, &mask, bsk, ntt);
        // mask and masked_ct drop here -- zeroized by ZeroizeOnDrop

        // =============================================================
        // POST-BOOTSTRAP: Key rotation per tier policy
        // =============================================================

        if self.tier == SecurityTier::Tier1Maximum {
            self.outer.rotate_key();
        }
        self.bootstrap_count += 1;
        refreshed
    }

    /// Execute the Three-Lock Bootstrap with per-phase timing instrumentation.
    ///
    /// Wraps [`bootstrap`](Self::bootstrap) logic with `Instant::now()` calls
    /// around each phase. Use this variant for profiling and diagnostics.
    /// **Not** recommended for production hot paths due to syscall overhead.
    pub fn bootstrap_timed(
        &mut self,
        ct: &Ciphertext,
        bsk: &BootstrapKey,
        ntt: &NTTEngine,
    ) -> (Ciphertext, BootstrapStats) {
        let total_start = std::time::Instant::now();

        // Layer 1 -- Shannon mask
        let t0 = std::time::Instant::now();
        let mask = CiphertextMask::generate(self.n, self.q);
        let (masked_c0, masked_c1) = mask.apply(&ct.c0, &ct.c1);
        let shannon_mask_ns = t0.elapsed().as_nanos() as u64;

        // Layer 2 -- Montgomery RLWE encrypt
        let t1 = std::time::Instant::now();
        let outer_pair = OuterCiphertextPair::encrypt(&self.outer, &masked_c0, &masked_c1, ntt);
        let montgomery_encrypt_ns = t1.elapsed().as_nanos() as u64;

        // Peel Layer 2 -- Montgomery decrypt (still masked)
        let t2 = std::time::Instant::now();
        let (dec_c0, dec_c1) = outer_pair.decrypt(&self.outer, ntt);
        let montgomery_decrypt_ns = t2.elapsed().as_nanos() as u64;

        // Layer 3 -- Clockwork with algebraic mask removal
        let t3 = std::time::Instant::now();
        let masked_ct = Ciphertext {
            c0: dec_c0,
            c1: dec_c1,
        };
        let refreshed = self
            .clockwork
            .bootstrap_protected(&masked_ct, &mask, bsk, ntt);
        let clockwork_ns = t3.elapsed().as_nanos() as u64;

        // Post-bootstrap key rotation per tier policy
        let key_rotated = match self.tier {
            SecurityTier::Tier1Maximum => {
                self.outer.rotate_key();
                true
            }
            _ => false,
        };
        self.bootstrap_count += 1;

        let total_ns = total_start.elapsed().as_nanos() as u64;
        let stats = BootstrapStats {
            shannon_mask_ns,
            montgomery_encrypt_ns,
            montgomery_decrypt_ns,
            clockwork_ns,
            total_ns,
            key_rotated,
        };
        (refreshed, stats)
    }

    /// Execute bootstrap without timing statistics.
    ///
    /// Alias for [`bootstrap`](Self::bootstrap). Retained for backward
    /// compatibility -- the primary `bootstrap()` method is already
    /// timing-free.
    #[inline]
    pub fn bootstrap_fast(
        &mut self,
        ct: &Ciphertext,
        bsk: &BootstrapKey,
        ntt: &NTTEngine,
    ) -> Ciphertext {
        self.bootstrap(ct, bsk, ntt)
    }

    pub fn can_bootstrap(&self, noise_estimate: u64) -> bool {
        self.clockwork.can_bootstrap(noise_estimate)
    }
    pub fn rotate_outer_key(&mut self) {
        self.outer.rotate_key();
    }
    pub fn tier(&self) -> SecurityTier {
        self.tier
    }
    pub fn bootstrap_count(&self) -> u64 {
        self.bootstrap_count
    }
    pub fn clockwork(&self) -> &ClockworkBootstrap {
        &self.clockwork
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::mask::CiphertextMask;
    use crate::bootstrap::outer::OuterLayer;
    use crate::entropy::ShadowHarvester;
    use crate::keys::KeySet;
    use crate::ops::encrypt::{BFVDecryptor, BFVEncoder, BFVEncryptor};
    use crate::params::secure_configs::SecureConfig;
    use crate::ring::RingPolynomial;

    fn setup() -> (FHEConfig, NTTEngine, KeySet, ShadowHarvester, BFVEncoder) {
        let config = SecureConfig::test_fast_insecure().into_config();
        let ntt = NTTEngine::new(config.q, config.n);
        let mut harvester = ShadowHarvester::with_seed(42);
        let keys = KeySet::generate(&config, &ntt, &mut harvester);
        let encoder = BFVEncoder::new(&config);
        (config, ntt, keys, harvester, encoder)
    }

    fn make_bsk(config: &FHEConfig, keys: &KeySet) -> BootstrapKey {
        BootstrapKey::generate_with_pk(
            config,
            &keys.secret_key,
            &keys.public_key.pk0,
            &keys.public_key.pk1,
        )
    }

    // =================================================================
    // END-TO-END CORRECTNESS
    // =================================================================

    #[test]
    fn test_three_lock_end_to_end_single() {
        let (config, ntt, keys, mut harvester, encoder) = setup();
        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);

        let m = 42u64;
        let ct = encryptor.encrypt(m, &mut harvester);
        assert_eq!(decryptor.decrypt(&ct), m);

        let bsk = make_bsk(&config, &keys);
        let mut tl = ThreeLockBootstrap::new(&config, SecurityTier::Tier2Production);

        let (refreshed, stats) = tl.bootstrap_timed(&ct, &bsk, &ntt);
        let result = decryptor.decrypt(&refreshed);

        println!(
            "Three-Lock E2E: encrypt({}) -> bootstrap -> decrypt = {}",
            m, result
        );
        println!("  {}", stats);
        assert_eq!(result, m, "E2E FAILURE: expected {} got {}", m, result);
    }

    #[test]
    fn test_three_lock_end_to_end_multiple() {
        let (config, ntt, keys, mut harvester, encoder) = setup();
        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);

        let bsk = make_bsk(&config, &keys);
        let mut tl = ThreeLockBootstrap::new(&config, SecurityTier::Tier2Production);

        let msgs = [0u64, 1, 42, 100, 500, 1000, 5000, 9000];
        for &m in &msgs {
            let ct = encryptor.encrypt(m, &mut harvester);
            let refreshed = tl.bootstrap(&ct, &bsk, &ntt);
            let result = decryptor.decrypt(&refreshed);
            assert_eq!(result, m, "Three-Lock failed for m={}: got {}", m, result);
        }
        println!("Three-Lock E2E: {}/{} correct", msgs.len(), msgs.len());
    }

    #[test]
    fn test_three_lock_fast_path() {
        let (config, ntt, keys, mut harvester, encoder) = setup();
        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);

        let bsk = make_bsk(&config, &keys);
        let mut tl = ThreeLockBootstrap::new(&config, SecurityTier::Tier3Commodity);

        let ct = encryptor.encrypt(42, &mut harvester);
        let refreshed = tl.bootstrap_fast(&ct, &bsk, &ntt);
        assert_eq!(decryptor.decrypt(&refreshed), 42);
    }

    // =================================================================
    // SECURITY PROPERTIES
    // =================================================================

    #[test]
    fn test_tier1_key_rotation() {
        let (config, ntt, keys, mut harvester, encoder) = setup();
        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);

        let ct = encryptor.encrypt(42, &mut harvester);
        let bsk = make_bsk(&config, &keys);

        let mut tl = ThreeLockBootstrap::new(&config, SecurityTier::Tier1Maximum);
        let (r1, s1) = tl.bootstrap_timed(&ct, &bsk, &ntt);
        assert!(s1.key_rotated);
        assert_eq!(decryptor.decrypt(&r1), 42);

        let (r2, s2) = tl.bootstrap_timed(&ct, &bsk, &ntt);
        assert!(s2.key_rotated);
        assert_eq!(decryptor.decrypt(&r2), 42);
        assert_eq!(tl.bootstrap_count(), 2);
    }

    #[test]
    fn test_mask_never_removed_from_ciphertext() {
        let (config, ntt, _, _, _) = setup();
        let poly = RingPolynomial::from_coeffs(vec![42; config.n], config.q);

        let mask = CiphertextMask::generate(config.n, config.q);
        let (masked, _) = mask.apply(&poly, &poly);

        assert_ne!(
            masked.coeffs, poly.coeffs,
            "Masked should differ from original"
        );

        // After outer encrypt/decrypt (Montgomery round-trip), still masked
        let outer = OuterLayer::new(config.n, config.q, config.eta);
        let outer_ct = outer.encrypt(&masked, &ntt);
        let after_montgomery = outer.decrypt(&outer_ct, &ntt);

        assert_ne!(
            after_montgomery.coeffs, poly.coeffs,
            "After Montgomery round-trip, data must still be masked"
        );

        // But the mask can be algebraically removed
        let recovered = mask.mask_c0.remove(&after_montgomery);
        let max_diff: u64 = recovered
            .coeffs
            .iter()
            .zip(poly.coeffs.iter())
            .map(|(&a, &b)| {
                let d = if a >= b { a - b } else { b - a };
                std::cmp::min(d, config.q - d)
            })
            .max()
            .unwrap_or(0);
        assert!(
            max_diff < config.q / 4,
            "After algebraic mask removal, should recover original + small noise"
        );
    }

    #[test]
    fn test_refreshed_ciphertext_is_fresh() {
        let (config, ntt, keys, mut harvester, encoder) = setup();
        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);

        let bsk = make_bsk(&config, &keys);
        let mut tl = ThreeLockBootstrap::new(&config, SecurityTier::Tier2Production);

        let m = 42u64;
        let delta = config.q / config.t;

        let ct = encryptor.encrypt(m, &mut harvester);
        let refreshed = tl.bootstrap(&ct, &bsk, &ntt);

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

        // Integer-only display
        let noise_pct_x10 = noise * 1000 / budget;
        println!(
            "Post-Three-Lock noise: {} ({}.{}% of budget {})",
            noise,
            noise_pct_x10 / 10,
            noise_pct_x10 % 10,
            budget
        );
        assert!(
            noise < budget / 10,
            "Refreshed ciphertext should have < 10% noise usage"
        );
    }

    #[test]
    fn test_outer_layer_bounded_noise() {
        let (config, ntt, _, _, _) = setup();
        let outer = OuterLayer::new(config.n, config.q, config.eta);
        let poly = RingPolynomial::from_coeffs(vec![42; config.n], config.q);

        let ct = outer.encrypt(&poly, &ntt);
        let dec = outer.decrypt(&ct, &ntt);

        let max_noise: u64 = poly
            .coeffs
            .iter()
            .zip(dec.coeffs.iter())
            .map(|(&o, &d)| {
                let diff = if d >= o { d - o } else { o - d };
                std::cmp::min(diff, config.q - diff)
            })
            .max()
            .unwrap_or(0);
        assert!(max_noise < config.q / 4);
    }

    // =================================================================
    // BENCHMARKS
    // =================================================================

    #[test]
    fn test_three_lock_benchmark() {
        let (config, ntt, keys, mut harvester, encoder) = setup();
        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);

        let ct = encryptor.encrypt(42, &mut harvester);
        let bsk = make_bsk(&config, &keys);
        let mut tl = ThreeLockBootstrap::new(&config, SecurityTier::Tier2Production);

        // Warm-up (hot path, no timing overhead)
        let _ = tl.bootstrap(&ct, &bsk, &ntt);

        let iterations = 5u64;
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let _ = tl.bootstrap(&ct, &bsk, &ntt);
        }
        let per_us = start.elapsed().as_micros() as u64 / iterations;

        // Final iteration with per-phase instrumentation
        let (refreshed, stats) = tl.bootstrap_timed(&ct, &bsk, &ntt);
        println!("Three-Lock: {}us avg ({} iters)", per_us, iterations);
        println!("  {}", stats);

        assert_eq!(decryptor.decrypt(&refreshed), 42);
    }
}
