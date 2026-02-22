//! # Destruction Sequence — Atomic Fold + Zero + Receipt
//!
//! The destruction sequence is the core lifecycle event for kiosk units.
//! It atomically:
//!
//! 1. **Folds** the RNS state (algebraic obfuscation)
//! 2. **Zeros** all memory via `zeroize`
//! 3. **Generates** a SHA-256 receipt proving destruction
//!
//! The sequence is designed to complete in <20µs, far faster than a
//! single FHE multiplication, ensuring no observable window exists
//! where intermediate state could be captured.

use std::time::Instant;
use zeroize::Zeroize;

use crate::kiosk::fold::FoldOperator;
use crate::kiosk::receipt::{ReceiptData, ReceiptHash};

/// A destruction receipt containing proof of proper self-destruction.
#[derive(Clone, Debug)]
pub struct DestructionReceipt {
    /// The SHA-256 hash proving destruction
    pub hash: ReceiptHash,
    /// The receipt data (for verification)
    pub data: ReceiptData,
    /// Duration of the destruction sequence in nanoseconds
    pub duration_nanos: u64,
}

/// The destruction sequence executor.
///
/// Manages the atomic Fold + Zero + Receipt lifecycle event.
pub struct DestructionSequence {
    /// Unit identifier
    unit_id: u64,
    /// Unit type discriminant
    unit_type: u8,
    /// Operations counter
    operations_performed: u64,
    /// Whether destruction has already occurred
    destroyed: bool,
}

impl DestructionSequence {
    /// Create a new destruction sequence for a unit.
    pub fn new(unit_id: u64, unit_type: u8) -> Self {
        Self {
            unit_id,
            unit_type,
            operations_performed: 0,
            destroyed: false,
        }
    }

    /// Record that an operation was performed.
    pub fn record_operation(&mut self) {
        self.operations_performed = self.operations_performed.saturating_add(1);
    }

    /// Record multiple operations at once.
    pub fn record_operations(&mut self, count: u64) {
        self.operations_performed = self.operations_performed.saturating_add(count);
    }

    /// Get the current operation count.
    pub fn operations_performed(&self) -> u64 {
        self.operations_performed
    }

    /// Check if this unit has already been destroyed.
    pub fn is_destroyed(&self) -> bool {
        self.destroyed
    }

    /// Execute the destruction sequence.
    ///
    /// This is an atomic operation that:
    /// 1. Permanently folds the RNS limbs (algebraic obfuscation)
    /// 2. Zeros all limb data
    /// 3. Zeros the fold operator state
    /// 4. Generates a SHA-256 receipt
    ///
    /// # Returns
    /// `Some(DestructionReceipt)` if destruction succeeded,
    /// `None` if already destroyed or fold failed.
    pub fn execute(
        &mut self,
        fold_op: &mut FoldOperator,
        limbs: &mut [u64],
        final_entropy: u64,
    ) -> Option<DestructionReceipt> {
        if self.destroyed {
            return None;
        }

        let start = Instant::now();

        // Step 1: Permanent fold (algebraic obfuscation)
        if !fold_op.permanent_fold(limbs) {
            return None;
        }

        let fold_generation = fold_op.generation();

        // Step 2: Zero all limb data
        limbs.zeroize();

        // Step 3: Zero the fold operator
        fold_op.zero();

        // Step 4: Generate receipt
        let duration_nanos = start.elapsed().as_nanos() as u64;
        let timestamp_nanos = duration_nanos; // Relative to destruction start

        let receipt_data = ReceiptData {
            unit_id: self.unit_id,
            fold_generation,
            final_entropy,
            timestamp_nanos,
            operations_performed: self.operations_performed,
            unit_type: self.unit_type,
        };

        let hash = receipt_data.compute_hash();

        self.destroyed = true;

        Some(DestructionReceipt {
            hash,
            data: receipt_data,
            duration_nanos,
        })
    }
}

impl Drop for DestructionSequence {
    fn drop(&mut self) {
        // If not explicitly destroyed, force zero
        self.unit_id = 0;
        self.operations_performed = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kiosk::fold::{FoldOperator, FoldState};
    use crate::kiosk::receipt::ReceiptVerifier;

    #[test]
    fn test_destruction_sequence_basic() {
        let moduli = vec![7681u64, 12289, 40961];
        let mut fold_op = FoldOperator::new(&moduli, 42);
        let mut limbs = vec![100u64, 200, 300];
        let mut seq = DestructionSequence::new(0xBEEF, 0);

        seq.record_operations(5);

        let receipt = seq.execute(&mut fold_op, &mut limbs, 1000);
        assert!(receipt.is_some());

        let receipt = receipt.unwrap();
        assert_eq!(receipt.data.unit_id, 0xBEEF);
        assert_eq!(receipt.data.operations_performed, 5);
        assert_eq!(receipt.data.unit_type, 0);

        // Verify limbs are zeroed
        assert_eq!(limbs, vec![0, 0, 0]);

        // Verify fold operator is zeroed
        assert_eq!(fold_op.state(), FoldState::Zeroed);
    }

    #[test]
    fn test_destruction_receipt_verifiable() {
        let moduli = vec![7681u64, 12289];
        let mut fold_op = FoldOperator::new(&moduli, 99);
        let mut limbs = vec![42u64, 137];
        let mut seq = DestructionSequence::new(0xCAFE, 1);
        seq.record_operation();

        let receipt = seq.execute(&mut fold_op, &mut limbs, 500).unwrap();

        // Receipt should verify
        assert!(ReceiptVerifier::verify(&receipt.data, &receipt.hash));
    }

    #[test]
    fn test_double_destruction_prevented() {
        let moduli = vec![7681u64];
        let mut fold_op = FoldOperator::new(&moduli, 42);
        let mut limbs = vec![100u64];
        let mut seq = DestructionSequence::new(1, 0);

        // First destruction succeeds
        assert!(seq.execute(&mut fold_op, &mut limbs, 0).is_some());

        // Second destruction fails
        let mut fold_op2 = FoldOperator::new(&moduli, 42);
        let mut limbs2 = vec![100u64];
        assert!(seq.execute(&mut fold_op2, &mut limbs2, 0).is_none());
        assert!(seq.is_destroyed());
    }

    #[test]
    fn test_destruction_is_fast() {
        let moduli = vec![7681u64, 12289, 40961, 65537];
        let mut fold_op = FoldOperator::new(&moduli, 42);
        let mut limbs = vec![100u64, 200, 300, 400];
        let mut seq = DestructionSequence::new(1, 0);
        seq.record_operations(100);

        let receipt = seq.execute(&mut fold_op, &mut limbs, 0).unwrap();

        // Destruction should complete in reasonable time
        // Target: <20µs = 20_000ns
        // Allow some slack for CI environments
        assert!(
            receipt.duration_nanos < 1_000_000, // 1ms generous upper bound
            "Destruction took {}ns, expected < 1ms",
            receipt.duration_nanos
        );
    }

    #[test]
    fn test_operation_counter() {
        let mut seq = DestructionSequence::new(1, 0);
        assert_eq!(seq.operations_performed(), 0);

        seq.record_operation();
        assert_eq!(seq.operations_performed(), 1);

        seq.record_operations(10);
        assert_eq!(seq.operations_performed(), 11);
    }
}
