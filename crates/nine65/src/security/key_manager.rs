//! Key Lifecycle Manager for NINE65 FHE secret keys.
//!
//! Wraps Clockwork's [`KeyLifecycle`] to manage NINE65's secret keys
//! with share splitting, automatic resharing, and volatile zeroing.
//!
//! # Security Model
//!
//! The full secret key `s` is NEVER stored after initialization.
//! Only the share pair `(s1, s2)` where `s1 + s2 ≡ s (mod q)` exists
//! in memory. Periodic resharing with fresh randomness ensures that
//! compromise of one share at time T reveals nothing about shares at
//! time T+1 (forward secrecy via T13).
//!
//! Memory zeroing uses volatile writes (via Clockwork's A4 primitive)
//! to prevent compiler dead-store elimination.

use clockwork_core::key_lifecycle::{KeyLifecycle, KeyState};

/// Key lifecycle manager for NINE65 secret keys.
///
/// Provides share splitting, automatic resharing, and secure zeroing
/// for FHE secret keys. Delegates to Clockwork's `KeyLifecycle`.
pub struct KeyManager {
    inner: KeyLifecycle,
}

impl KeyManager {
    /// Create a new key manager.
    ///
    /// - `q`: the RLWE modulus (fixed, INV-1)
    /// - `reshare_interval`: operations between automatic reshares
    pub fn new(q: u64, reshare_interval: u64) -> Self {
        Self {
            inner: KeyLifecycle::new(q, reshare_interval),
        }
    }

    /// Initialize with a secret key and randomness.
    ///
    /// Splits `s` into `(s1, s2)` where `s1 + s2 ≡ s (mod q)`.
    /// After this call, the full secret `s` exists only as shares.
    pub fn initialize(&mut self, s: u64, r: u64) -> Result<(), &'static str> {
        self.inner.initialize(s, r)
    }

    /// Record that a key-dependent operation was performed.
    /// Returns `true` if resharing is now needed.
    pub fn record_operation(&mut self) -> bool {
        self.inner.record_operation()
    }

    /// Reshare with fresh randomness.
    ///
    /// Old shares are zeroed, new shares computed such that
    /// `s1' + s2' ≡ s (mod q)` still holds.
    pub fn reshare(&mut self, r: u64) -> Result<(), &'static str> {
        self.inner.reshare(r)
    }

    /// Reconstruct the secret key for decrypt.
    ///
    /// WARNING: puts the full key in memory briefly. Zero after use.
    pub fn reconstruct_for_decrypt(&self) -> Result<u64, &'static str> {
        self.inner.reconstruct_for_decrypt()
    }

    /// Zero all key material and transition to ZEROED state.
    /// No further operations possible after this.
    pub fn destroy(&mut self) {
        self.inner.destroy();
    }

    /// Current lifecycle state.
    pub fn state(&self) -> KeyState {
        self.inner.state()
    }

    /// Number of reshares performed.
    pub fn reshare_count(&self) -> u64 {
        self.inner.reshare_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_manager_split_and_reconstruct() {
        let q = 998244353u64; // NINE65 NTT prime
        let mut mgr = KeyManager::new(q, 1000);
        mgr.initialize(42, 12345).unwrap();
        assert_eq!(mgr.reconstruct_for_decrypt().unwrap(), 42);
    }

    #[test]
    fn key_manager_reshares_on_schedule() {
        let q = 998244353u64;
        let mut mgr = KeyManager::new(q, 10);
        mgr.initialize(42, 12345).unwrap();

        // Record 9 ops — not yet time to reshare
        for _ in 0..9 {
            assert!(!mgr.record_operation());
        }
        // 10th op triggers reshare
        assert!(mgr.record_operation());

        mgr.reshare(99999).unwrap();
        assert_eq!(mgr.reconstruct_for_decrypt().unwrap(), 42);
        assert_eq!(mgr.reshare_count(), 1);
    }

    #[test]
    fn key_manager_multiple_reshares() {
        let q = 998244353u64;
        let secret = 777u64;
        let mut mgr = KeyManager::new(q, 5);
        mgr.initialize(secret, 11111).unwrap();

        let mut rng: u64 = 0xCAFE_BABE;
        for reshare_num in 0..100 {
            for _ in 0..5 {
                mgr.record_operation();
            }
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            mgr.reshare(rng % q).unwrap();
            assert_eq!(
                mgr.reconstruct_for_decrypt().unwrap(),
                secret,
                "Secret lost after reshare {reshare_num}"
            );
        }
        assert_eq!(mgr.reshare_count(), 100);
    }

    #[test]
    fn key_manager_zeros_on_drop() {
        let q = 998244353u64;
        let mut mgr = KeyManager::new(q, 1000);
        mgr.initialize(42, 12345).unwrap();
        mgr.destroy();
        assert!(mgr.reconstruct_for_decrypt().is_err());
        assert_eq!(mgr.state(), KeyState::Zeroed);
    }

    #[test]
    fn key_manager_rejects_double_init() {
        let q = 998244353u64;
        let mut mgr = KeyManager::new(q, 1000);
        mgr.initialize(42, 12345).unwrap();
        assert!(mgr.initialize(43, 99999).is_err());
    }

    #[test]
    fn key_manager_large_prime_modulus() {
        // Use a large NTT-friendly prime
        let q = 4611686018427387761u64; // 62-bit prime
        let secret = 123456789u64;
        let mut mgr = KeyManager::new(q, 100);
        mgr.initialize(secret, 987654321).unwrap();
        assert_eq!(mgr.reconstruct_for_decrypt().unwrap(), secret);

        mgr.reshare(111111111).unwrap();
        assert_eq!(mgr.reconstruct_for_decrypt().unwrap(), secret);
    }
}
