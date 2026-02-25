//! # Fold/Unfold Operators — Algebraic State Obfuscation
//!
//! The Fold operator renders RNS state algebraically meaningless before
//! zeroing, ensuring that no intermediate state can be recovered from
//! memory forensics.
//!
//! ## Mechanism
//!
//! 1. **Fold**: Multiply each RNS limb by a pseudorandom mask derived from
//!    the Montgomery quotient stream. This destroys the algebraic relationship
//!    between limbs, making CRT reconstruction impossible.
//!
//! 2. **Unfold**: (Used only during active computation) Reverse the fold
//!    by dividing out the mask. This is only possible while the fold key
//!    is in memory.
//!
//! 3. **Permanent Fold**: Fold + zeroize the fold key. After this, the
//!    original state is irrecoverable.

use zeroize::Zeroize;

use crate::arithmetic::MontgomeryContext;
use crate::entropy::shadow::ShadowHarvester;

/// State of a fold operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FoldState {
    /// Data is in plaintext (unfolded) RNS form
    Unfolded,
    /// Data is algebraically folded (masked)
    Folded,
    /// Data has been permanently folded and the key destroyed
    PermanentlyFolded,
    /// Data has been zeroed (terminal state)
    Zeroed,
}

/// Fold operator for RNS limb obfuscation.
///
/// Uses Montgomery multiplication to apply pseudorandom masks to each
/// RNS limb, destroying the CRT relationship between them.
pub struct FoldOperator {
    /// Fold masks — one per RNS limb
    masks: Vec<u64>,
    /// Montgomery contexts for each RNS modulus
    mont_contexts: Vec<MontgomeryContext>,
    /// Current fold state
    state: FoldState,
    /// Fold generation counter (incremented on each fold cycle)
    generation: u64,
}

impl FoldOperator {
    /// Create a new fold operator for the given RNS moduli.
    ///
    /// Generates pseudorandom fold masks from the provided seed using
    /// the Shadow Entropy harvester.
    pub fn new(moduli: &[u64], seed: u64) -> Self {
        let mut harvester = ShadowHarvester::with_seed(seed);
        let mont_contexts: Vec<MontgomeryContext> =
            moduli.iter().map(|&q| MontgomeryContext::new(q)).collect();

        let masks: Vec<u64> = moduli
            .iter()
            .zip(mont_contexts.iter())
            .map(|(&q, _mont)| {
                // Generate a non-zero mask in [1, q-1]
                loop {
                    let raw = harvester.next_u64();
                    let mask = raw % q;
                    if mask != 0 {
                        return mask;
                    }
                }
            })
            .collect();

        Self {
            masks,
            mont_contexts,
            state: FoldState::Unfolded,
            generation: 0,
        }
    }

    /// Fold the RNS limbs: multiply each limb by its corresponding mask.
    ///
    /// After folding, the CRT relationship between limbs is destroyed
    /// and the original value cannot be reconstructed without unfolding.
    ///
    /// # Returns
    /// `true` if folding succeeded, `false` if state doesn't allow folding.
    pub fn fold(&mut self, limbs: &mut [u64]) -> bool {
        if self.state != FoldState::Unfolded {
            return false;
        }
        if limbs.len() != self.masks.len() {
            return false;
        }

        for i in 0..limbs.len() {
            // Apply mask via Montgomery multiplication for constant-time operation
            limbs[i] = self.mont_contexts[i].montgomery_mul(
                self.mont_contexts[i].to_montgomery(limbs[i]),
                self.mont_contexts[i].to_montgomery(self.masks[i]),
            );
            limbs[i] = self.mont_contexts[i].from_montgomery(limbs[i]);
        }

        self.state = FoldState::Folded;
        self.generation = self.generation.wrapping_add(1);
        true
    }

    /// Unfold the RNS limbs: remove the fold mask to restore original values.
    ///
    /// This is only possible while the fold key is still in memory.
    ///
    /// # Returns
    /// `true` if unfolding succeeded, `false` if state doesn't allow unfolding.
    pub fn unfold(&mut self, limbs: &mut [u64]) -> bool {
        if self.state != FoldState::Folded {
            return false;
        }
        if limbs.len() != self.masks.len() {
            return false;
        }

        for i in 0..limbs.len() {
            // Compute modular inverse of mask
            let mask_inv = mod_inverse(self.masks[i], self.mont_contexts[i].q);
            limbs[i] = self.mont_contexts[i].montgomery_mul(
                self.mont_contexts[i].to_montgomery(limbs[i]),
                self.mont_contexts[i].to_montgomery(mask_inv),
            );
            limbs[i] = self.mont_contexts[i].from_montgomery(limbs[i]);
        }

        self.state = FoldState::Unfolded;
        true
    }

    /// Permanently fold: fold the data and then destroy the fold key.
    ///
    /// After this operation, the original data is irrecoverable.
    /// This is used as the first step in the destruction sequence.
    pub fn permanent_fold(&mut self, limbs: &mut [u64]) -> bool {
        if self.state == FoldState::Zeroed || self.state == FoldState::PermanentlyFolded {
            return false;
        }

        // If not already folded, fold first
        if self.state == FoldState::Unfolded && !self.fold(limbs) {
            return false;
        }

        // Destroy the fold masks
        self.masks.zeroize();
        self.state = FoldState::PermanentlyFolded;
        true
    }

    /// Zero all state. Terminal operation — the FoldOperator is unusable after this.
    pub fn zero(&mut self) {
        self.masks.zeroize();
        self.state = FoldState::Zeroed;
        self.generation = 0;
    }

    /// Get the current fold state.
    pub fn state(&self) -> FoldState {
        self.state
    }

    /// Get the fold generation counter.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Get the number of RNS limbs this operator handles.
    pub fn num_limbs(&self) -> usize {
        self.mont_contexts.len()
    }
}

impl Drop for FoldOperator {
    fn drop(&mut self) {
        self.zero();
    }
}

/// Compute modular inverse of `a` modulo `m` using extended Euclidean algorithm.
///
/// Returns `a^(-1) mod m`. Panics if `gcd(a, m) != 1`.
fn mod_inverse(a: u64, m: u64) -> u64 {
    let (mut old_r, mut r) = (m as i128, a as i128);
    let (mut old_s, mut s) = (0i128, 1i128);

    while r != 0 {
        let quotient = old_r / r;
        let temp_r = r;
        r = old_r - quotient * r;
        old_r = temp_r;

        let temp_s = s;
        s = old_s - quotient * s;
        old_s = temp_s;
    }

    debug_assert_eq!(old_r, 1, "mod_inverse requires gcd(a, m) == 1");

    // Normalize to positive
    let result = old_s % m as i128;
    if result < 0 {
        (result + m as i128) as u64
    } else {
        result as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mod_inverse() {
        assert_eq!(mod_inverse(3, 7), 5); // 3*5 = 15 ≡ 1 (mod 7)
        assert_eq!(mod_inverse(5, 11), 9); // 5*9 = 45 ≡ 1 (mod 11)
        assert_eq!(mod_inverse(7, 13), 2); // 7*2 = 14 ≡ 1 (mod 13)
    }

    #[test]
    fn test_fold_unfold_roundtrip() {
        let moduli = vec![7681u64, 12289, 40961];
        let mut op = FoldOperator::new(&moduli, 42);

        let original = vec![100u64, 200, 300];
        let mut limbs = original.clone();

        // Fold
        assert!(op.fold(&mut limbs));
        assert_eq!(op.state(), FoldState::Folded);

        // Values should be different after folding
        assert_ne!(limbs, original);

        // Unfold
        assert!(op.unfold(&mut limbs));
        assert_eq!(op.state(), FoldState::Unfolded);

        // Values should be restored
        assert_eq!(limbs, original);
    }

    #[test]
    fn test_fold_unfold_multiple_cycles() {
        let moduli = vec![7681u64, 12289];
        let mut op = FoldOperator::new(&moduli, 99);
        let original = vec![42u64, 137];

        for _ in 0..5 {
            let mut limbs = original.clone();
            assert!(op.fold(&mut limbs));
            assert!(op.unfold(&mut limbs));
            assert_eq!(limbs, original);
        }
        assert_eq!(op.generation(), 5);
    }

    #[test]
    fn test_permanent_fold_irreversible() {
        let moduli = vec![7681u64, 12289, 40961];
        let mut op = FoldOperator::new(&moduli, 42);
        let mut limbs = vec![100u64, 200, 300];

        assert!(op.permanent_fold(&mut limbs));
        assert_eq!(op.state(), FoldState::PermanentlyFolded);

        // Cannot unfold after permanent fold
        assert!(!op.unfold(&mut limbs));
    }

    #[test]
    fn test_fold_wrong_size_rejected() {
        let moduli = vec![7681u64, 12289];
        let mut op = FoldOperator::new(&moduli, 42);
        let mut limbs = vec![100u64, 200, 300]; // wrong size

        assert!(!op.fold(&mut limbs));
    }

    #[test]
    fn test_zero_state() {
        let moduli = vec![7681u64];
        let mut op = FoldOperator::new(&moduli, 42);
        op.zero();
        assert_eq!(op.state(), FoldState::Zeroed);

        let mut limbs = vec![100u64];
        assert!(!op.fold(&mut limbs));
    }

    #[test]
    fn test_different_seeds_different_masks() {
        let moduli = vec![7681u64, 12289];
        let mut op1 = FoldOperator::new(&moduli, 1);
        let mut op2 = FoldOperator::new(&moduli, 2);

        let mut limbs1 = vec![100u64, 200];
        let mut limbs2 = vec![100u64, 200];

        op1.fold(&mut limbs1);
        op2.fold(&mut limbs2);

        // Different seeds should produce different folded values
        assert_ne!(limbs1, limbs2);
    }
}
