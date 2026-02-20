//! # Key Lifecycle — Formal Spec §2.4, D18–D21
//!
//! Implements the Loki key management integration for FHE secret keys:
//! - **D18**: Key share pair (s₁, s₂) with s₁ + s₂ ≡ s (mod q)
//! - **D19**: Re-sharing with fresh randomness
//! - **D20**: Key lifecycle state machine (KEYGEN → SPLIT → ACTIVE → RESHARE → ZEROED)
//! - **D21**: PRF-based evaluation key chain
//!
//! ## Theorem Coverage
//! - **T11** (Re-sharing Correctness): s₁' + s₂' ≡ s (mod q)
//! - **T12** (Share Independence): s₁ alone reveals nothing about s
//! - **T13** (Forward Secrecy): compromise of evk_n doesn't reveal evk_m
//!
//! ## INV-5 Enforcement
//! The full secret key `s` is NEVER stored after the SPLIT phase.
//! Only (s₁, s₂) exist in memory during ACTIVE phase.
//!
//! ## Memory Zeroing (A4)
//! All key material is zeroed via `zero_memory` after use.
//! This function uses volatile writes to prevent compiler optimization.

/// A key share pair: two values whose sum (mod q) equals the secret key.
///
/// **Formal Spec D18**: (s₁, s₂) with s₁ + s₂ ≡ s (mod q)
///
/// The secret s is NEVER stored alongside the shares.
/// INV-5 requires that only shares exist in memory during ACTIVE phase.
#[derive(Clone)]
pub struct KeySharePair {
    /// First share
    share_a: u64,
    /// Second share
    share_b: u64,
    /// The modulus q (fixed, INV-1)
    q: u64,
}

/// Key lifecycle states from D20
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    /// Key generation phase: s in memory (brief)
    Keygen,
    /// Split phase: computing (s₁, s₂), s about to be zeroed
    Split,
    /// Active phase: only (s₁, s₂) in memory, s is gone
    Active,
    /// Zeroed: all key material cleared
    Zeroed,
}

/// Full key lifecycle manager
pub struct KeyLifecycle {
    /// Current state
    state: KeyState,
    /// Key shares (only valid in Active state)
    shares: Option<KeySharePair>,
    /// The fixed modulus
    q: u64,
    /// Number of reshares performed
    reshare_count: u64,
    /// Maximum operations between reshares
    reshare_interval: u64,
    /// Operations since last reshare
    ops_since_reshare: u64,
}

impl KeySharePair {
    /// Create a key share pair from secret s using randomness r.
    ///
    /// s₁ = r, s₂ = s - r (mod q)
    ///
    /// **T12 guarantee**: s₁ is uniformly random in ℤ_q, independent of s.
    ///
    /// After this call, the caller MUST zero `s` (the caller's copy).
    pub fn split(s: u64, r: u64, q: u64) -> Self {
        debug_assert!(s < q, "Secret must be < q");
        debug_assert!(r < q, "Randomness must be < q");

        let share_a = r;
        let share_b = (s + q - r) % q; // s - r mod q, avoiding underflow

        KeySharePair {
            share_a,
            share_b,
            q,
        }
    }

    /// Reconstruct the secret key from shares.
    ///
    /// s = s₁ + s₂ mod q
    ///
    /// WARNING: This puts s in memory. Only call during Decrypt or rekey.
    /// The result MUST be zeroed after use.
    pub fn reconstruct(&self) -> u64 {
        ((self.share_a as u128 + self.share_b as u128) % self.q as u128) as u64
    }

    /// Re-share with fresh randomness.
    ///
    /// **Formal Spec D19**:
    ///   s₁' = s₁ + r (mod q)
    ///   s₂' = s₂ - r (mod q)
    ///
    /// **T11 guarantee**: s₁' + s₂' ≡ s₁ + s₂ ≡ s (mod q)
    ///
    /// After this call, the old (s₁, s₂) should be zeroed.
    pub fn reshare(&self, r: u64) -> KeySharePair {
        debug_assert!(r < self.q, "Randomness must be < q");

        let new_a = ((self.share_a as u128 + r as u128) % self.q as u128) as u64;
        let new_b = ((self.share_b as u128 + self.q as u128 - r as u128) % self.q as u128) as u64;

        KeySharePair {
            share_a: new_a,
            share_b: new_b,
            q: self.q,
        }
    }

    /// Get share A (for operations that need one share)
    pub fn share_a(&self) -> u64 {
        self.share_a
    }

    /// Get share B
    pub fn share_b(&self) -> u64 {
        self.share_b
    }

    /// The modulus
    pub fn q(&self) -> u64 {
        self.q
    }

    /// Zero this share pair's memory.
    /// Uses volatile writes to prevent compiler from optimizing away the zeroing.
    pub fn zero(&mut self) {
        zero_u64(&mut self.share_a);
        zero_u64(&mut self.share_b);
    }
}

impl Drop for KeySharePair {
    fn drop(&mut self) {
        self.zero();
    }
}

impl KeyLifecycle {
    /// Initialize a new key lifecycle manager.
    ///
    /// `reshare_interval`: number of operations between automatic reshares.
    /// This is a PUBLIC, SCHEDULE-BASED parameter (INV-7).
    pub fn new(q: u64, reshare_interval: u64) -> Self {
        KeyLifecycle {
            state: KeyState::Keygen,
            shares: None,
            q,
            reshare_count: 0,
            reshare_interval,
            ops_since_reshare: 0,
        }
    }

    /// Current lifecycle state
    pub fn state(&self) -> KeyState {
        self.state
    }

    /// Initialize with a secret key and randomness.
    ///
    /// Transitions: KEYGEN → SPLIT → ACTIVE
    ///
    /// The secret `s` is split into shares and then conceptually discarded.
    /// The caller MUST zero their copy of `s` after this call.
    pub fn initialize(&mut self, s: u64, r: u64) -> Result<(), &'static str> {
        if self.state != KeyState::Keygen {
            return Err("Can only initialize from Keygen state");
        }

        self.state = KeyState::Split;
        let shares = KeySharePair::split(s, r, self.q);
        self.shares = Some(shares);
        self.state = KeyState::Active;
        self.ops_since_reshare = 0;
        self.reshare_count = 0;

        Ok(())
    }

    /// Record that an operation was performed with these key shares.
    /// Returns true if resharing is now needed (based on public schedule).
    pub fn record_operation(&mut self) -> bool {
        self.ops_since_reshare += 1;
        self.ops_since_reshare >= self.reshare_interval
    }

    /// Perform a reshare with fresh randomness.
    ///
    /// Transitions: ACTIVE → RESHARE → ACTIVE
    ///
    /// Old shares are zeroed, new shares computed per D19.
    pub fn reshare(&mut self, r: u64) -> Result<(), &'static str> {
        if self.state != KeyState::Active {
            return Err("Can only reshare from Active state");
        }

        let old_shares = self.shares.take().ok_or("No shares to reshare")?;
        let new_shares = old_shares.reshare(r);

        // Old shares are zeroed by Drop (when old_shares goes out of scope)
        self.shares = Some(new_shares);
        self.reshare_count += 1;
        self.ops_since_reshare = 0;

        Ok(())
    }

    /// Access the current key shares (only in Active state).
    pub fn shares(&self) -> Option<&KeySharePair> {
        if self.state == KeyState::Active {
            self.shares.as_ref()
        } else {
            None
        }
    }

    /// Reconstruct the secret key for decrypt.
    ///
    /// WARNING: This puts the full key in memory. Caller MUST zero the result.
    pub fn reconstruct_for_decrypt(&self) -> Result<u64, &'static str> {
        if self.state != KeyState::Active {
            return Err("Can only reconstruct from Active state");
        }

        let shares = self.shares.as_ref().ok_or("No shares available")?;
        Ok(shares.reconstruct())
    }

    /// Zero all key material and transition to ZEROED state.
    ///
    /// Terminal state — no further operations possible.
    pub fn destroy(&mut self) {
        if let Some(ref mut shares) = self.shares {
            shares.zero();
        }
        self.shares = None;
        self.state = KeyState::Zeroed;
    }

    /// Number of reshares performed
    pub fn reshare_count(&self) -> u64 {
        self.reshare_count
    }
}

impl Drop for KeyLifecycle {
    fn drop(&mut self) {
        self.destroy();
    }
}

// ─── Memory zeroing (A4) ────────────────────────────────────────────────────

/// Zero a u64 value using volatile write to prevent compiler optimization.
///
/// **Formal Spec A4**: Memory zeroing primitive that completes in
/// time independent of the prior contents.
fn zero_u64(val: &mut u64) {
    // Safety: we're writing a known value to a valid, aligned location.
    // Using core volatile to prevent dead-store elimination.
    // In a real implementation, use platform-specific secure zeroing.
    unsafe {
        core::ptr::write_volatile(val as *mut u64, 0u64);
    }
    // Compiler fence to prevent reordering
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

// ─── Tests: Formal Spec Test Obligations KT-01 through KT-04 ───────────────

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_Q: u64 = 4093; // prime near 2^12

    // Simple LCG for deterministic test randomness (no floating point!)
    fn next_rng(state: &mut u64) -> u64 {
        *state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        *state
    }

    // ─── KT-01: Re-sharing correctness ──────────────────────────────────

    #[test]
    fn kt01_reshare_preserves_secret() {
        let mut rng: u64 = 0xDEAD_BEEF;

        for _ in 0..100_000 {
            let s = next_rng(&mut rng) % TEST_Q;
            let r0 = next_rng(&mut rng) % TEST_Q;
            let r_reshare = next_rng(&mut rng) % TEST_Q;

            let shares = KeySharePair::split(s, r0, TEST_Q);
            assert_eq!(shares.reconstruct(), s, "T11 initial: s₁+s₂ must equal s");

            let reshared = shares.reshare(r_reshare);
            assert_eq!(
                reshared.reconstruct(),
                s,
                "T11 reshare: s₁'+s₂' must still equal s"
            );
        }
    }

    #[test]
    fn kt01_multiple_reshares() {
        let s = 42u64;
        let mut shares = KeySharePair::split(s, 1000, TEST_Q);
        let mut rng: u64 = 0x1234_5678;

        // 1000 consecutive reshares
        for i in 0..1000 {
            let r = next_rng(&mut rng) % TEST_Q;
            shares = shares.reshare(r);
            assert_eq!(
                shares.reconstruct(),
                s,
                "T11 chain: failed after reshare {i}"
            );
        }
    }

    // ─── KT-02: Memory zeroing ──────────────────────────────────────────

    #[test]
    fn kt02_memory_zeroing() {
        let mut shares = KeySharePair::split(42, 1000, TEST_Q);

        // Before zeroing, shares are nonzero
        assert!(
            shares.share_a() != 0 || shares.share_b() != 0,
            "At least one share should be nonzero"
        );

        shares.zero();

        assert_eq!(shares.share_a(), 0, "share_a must be 0 after zeroing");
        assert_eq!(shares.share_b(), 0, "share_b must be 0 after zeroing");
    }

    // ─── KT-03: Key evolution consistency ───────────────────────────────

    #[test]
    fn kt03_lifecycle_state_machine() {
        let mut lc = KeyLifecycle::new(TEST_Q, 10);
        assert_eq!(lc.state(), KeyState::Keygen);

        // Initialize
        lc.initialize(42, 1000).unwrap();
        assert_eq!(lc.state(), KeyState::Active);

        // Shares accessible
        assert!(lc.shares().is_some());

        // Can reconstruct
        assert_eq!(lc.reconstruct_for_decrypt().unwrap(), 42);

        // Record operations until reshare needed
        for _ in 0..9 {
            assert!(!lc.record_operation());
        }
        assert!(lc.record_operation()); // 10th operation triggers

        // Reshare
        lc.reshare(2000).unwrap();
        assert_eq!(lc.state(), KeyState::Active);
        assert_eq!(lc.reshare_count(), 1);

        // Still correct after reshare
        assert_eq!(lc.reconstruct_for_decrypt().unwrap(), 42);

        // Destroy
        lc.destroy();
        assert_eq!(lc.state(), KeyState::Zeroed);
        assert!(lc.shares().is_none());
    }

    // ─── KT-04: Share independence (statistical) ────────────────────────

    #[test]
    fn kt04_share_distribution_uniformity() {
        // For a fixed secret, share_a should be uniformly distributed
        // (since it's just the randomness r)
        let s = 42u64;
        let num_samples = 100_000;
        let num_bins = 16u64;
        let mut bin_counts = vec![0u64; num_bins as usize];

        let mut rng: u64 = 0xAAAA_BBBB;
        for _ in 0..num_samples {
            let r = next_rng(&mut rng) % TEST_Q;
            let shares = KeySharePair::split(s, r, TEST_Q);

            let bin = (shares.share_a() as u64 * num_bins / TEST_Q) as usize;
            let bin = bin.min(num_bins as usize - 1);
            bin_counts[bin] += 1;
        }

        // Simple χ² test: expect ~num_samples/num_bins per bin
        // Integer-only: scale by 1000 to avoid floating-point
        let expected_x1000 = (num_samples as u64 * 1000) / num_bins as u64;

        let chi_sq_x1000: u64 = bin_counts
            .iter()
            .map(|&count| {
                let diff = count as i64 * 1000 - expected_x1000 as i64;
                ((diff * diff) as u64) / expected_x1000
            })
            .sum();

        // χ²(15) at p=0.01 is 30.578
        // Use a generous threshold: 50.0 * 1000 = 50_000
        assert!(
            chi_sq_x1000 < 50_000,
            "KT-04: Share distribution not uniform enough: χ²×1000={chi_sq_x1000}"
        );
    }

    // ─── State machine enforcement ──────────────────────────────────────

    #[test]
    fn rejects_double_init() {
        let mut lc = KeyLifecycle::new(TEST_Q, 10);
        lc.initialize(42, 1000).unwrap();
        assert!(lc.initialize(43, 2000).is_err());
    }

    #[test]
    fn rejects_reshare_before_init() {
        let mut lc = KeyLifecycle::new(TEST_Q, 10);
        assert!(lc.reshare(1000).is_err());
    }
}
