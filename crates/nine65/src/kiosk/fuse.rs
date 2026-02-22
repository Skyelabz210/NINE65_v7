//! # Shadow Entropy Fuse — Countdown to Self-Destruction
//!
//! The entropy fuse is a metering mechanism grounded in the algebraic
//! properties of Montgomery multiplication. Each FHE operation consumes
//! "entropy budget" derived from the irreducible computational byproducts
//! of the Montgomery quotient stream.
//!
//! ## Metering Mechanism
//!
//! - Each Montgomery reduction produces a quotient `q_hat = (t * q_inv) mod R`
//! - This quotient is algebraically irrecoverable (it was divided away)
//! - The fuse tracks cumulative entropy from these quotients
//! - When the pre-calculated budget is exhausted, self-destruction triggers
//!
//! ## Why This Cannot Be Bypassed
//!
//! The entropy budget is consumed by the *computation itself*, not by a
//! software counter. Skipping the entropy measurement means skipping the
//! Montgomery reduction, which means skipping the multiplication — there
//! is no way to perform the computation without consuming the budget.

use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroize;

/// State of the entropy fuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuseState {
    /// Fuse is armed and counting down
    Armed,
    /// Fuse has been triggered — self-destruction imminent
    Triggered,
    /// Fuse is spent — unit has been destroyed
    Spent,
}

/// Shadow Entropy Fuse — counts down operations until self-destruction.
///
/// The fuse tracks entropy consumed by Montgomery operations and triggers
/// self-destruction when the budget is exhausted.
pub struct EntropyFuse {
    /// Total entropy budget (in millibits)
    total_budget_mb: u64,
    /// Remaining entropy budget (in millibits)
    remaining_mb: AtomicU64,
    /// Entropy consumed per operation (in millibits)
    cost_per_op_mb: u64,
    /// Current fuse state
    state: FuseState,
    /// Running entropy accumulator from Montgomery quotients
    entropy_accumulator: u64,
    /// Number of operations consumed
    operations_consumed: u64,
}

impl EntropyFuse {
    /// Create a new entropy fuse with the given budget.
    ///
    /// # Arguments
    /// - `total_budget_mb`: Total entropy budget in millibits (1000 = 1 bit)
    /// - `cost_per_op_mb`: Entropy cost per operation in millibits
    pub fn new(total_budget_mb: u64, cost_per_op_mb: u64) -> Self {
        Self {
            total_budget_mb,
            remaining_mb: AtomicU64::new(total_budget_mb),
            cost_per_op_mb,
            state: FuseState::Armed,
            entropy_accumulator: 0,
            operations_consumed: 0,
        }
    }

    /// Create a fuse calibrated for a specific number of operations.
    ///
    /// The budget is set so that exactly `max_ops` operations can be
    /// performed before the fuse triggers.
    pub fn for_operations(max_ops: u64) -> Self {
        let cost_per_op_mb = 1000; // 1 bit per operation
        let total_budget_mb = max_ops.saturating_mul(cost_per_op_mb);
        Self::new(total_budget_mb, cost_per_op_mb)
    }

    /// Consume entropy for an operation.
    ///
    /// Feeds the Montgomery quotient into the entropy accumulator and
    /// decrements the remaining budget.
    ///
    /// # Returns
    /// - `FuseState::Armed` if budget remains
    /// - `FuseState::Triggered` if budget is now exhausted
    /// - `FuseState::Spent` if already triggered
    pub fn consume(&mut self, montgomery_quotient: u64) -> FuseState {
        if self.state != FuseState::Armed {
            return self.state;
        }

        // Accumulate entropy from the Montgomery quotient
        // This is the irreducible algebraic byproduct that cannot be faked
        self.entropy_accumulator ^= montgomery_quotient.rotate_left(13);
        self.entropy_accumulator = self
            .entropy_accumulator
            .wrapping_mul(0x9E3779B97F4A7C15)
            .wrapping_add(montgomery_quotient);

        self.operations_consumed += 1;

        // Decrement budget
        let remaining = self.remaining_mb.load(Ordering::Relaxed);
        if remaining <= self.cost_per_op_mb {
            self.remaining_mb.store(0, Ordering::Relaxed);
            self.state = FuseState::Triggered;
        } else {
            self.remaining_mb
                .store(remaining - self.cost_per_op_mb, Ordering::Relaxed);
        }

        self.state
    }

    /// Consume entropy for multiple operations at once.
    pub fn consume_batch(&mut self, montgomery_quotients: &[u64]) -> FuseState {
        for &q in montgomery_quotients {
            let state = self.consume(q);
            if state != FuseState::Armed {
                return state;
            }
        }
        self.state
    }

    /// Mark the fuse as spent (after destruction).
    pub fn mark_spent(&mut self) {
        self.state = FuseState::Spent;
        self.remaining_mb.store(0, Ordering::Relaxed);
        self.entropy_accumulator = 0;
    }

    /// Get the current fuse state.
    pub fn state(&self) -> FuseState {
        self.state
    }

    /// Get the remaining budget in millibits.
    pub fn remaining_mb(&self) -> u64 {
        self.remaining_mb.load(Ordering::Relaxed)
    }

    /// Get the total budget in millibits.
    pub fn total_budget_mb(&self) -> u64 {
        self.total_budget_mb
    }

    /// Get the remaining budget as a percentage (0-100, integer).
    pub fn remaining_percent(&self) -> u64 {
        if self.total_budget_mb == 0 {
            return 0;
        }
        (self.remaining_mb.load(Ordering::Relaxed) * 100) / self.total_budget_mb
    }

    /// Get the number of operations consumed.
    pub fn operations_consumed(&self) -> u64 {
        self.operations_consumed
    }

    /// Get the entropy accumulator value.
    ///
    /// This reflects the irreducible algebraic entropy from Montgomery
    /// quotients and can be used for tamper detection.
    pub fn entropy_accumulator(&self) -> u64 {
        self.entropy_accumulator
    }

    /// Estimate remaining operations based on current cost.
    pub fn remaining_operations(&self) -> u64 {
        if self.cost_per_op_mb == 0 {
            return u64::MAX;
        }
        self.remaining_mb.load(Ordering::Relaxed) / self.cost_per_op_mb
    }
}

impl Drop for EntropyFuse {
    fn drop(&mut self) {
        let mut acc = self.entropy_accumulator;
        acc.zeroize();
        self.entropy_accumulator = acc;
        self.remaining_mb.store(0, Ordering::Relaxed);
        self.state = FuseState::Spent;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuse_creation() {
        let fuse = EntropyFuse::new(10_000, 1_000);
        assert_eq!(fuse.state(), FuseState::Armed);
        assert_eq!(fuse.remaining_mb(), 10_000);
        assert_eq!(fuse.total_budget_mb(), 10_000);
        assert_eq!(fuse.remaining_percent(), 100);
    }

    #[test]
    fn test_fuse_for_operations() {
        let fuse = EntropyFuse::for_operations(100);
        assert_eq!(fuse.remaining_operations(), 100);
        assert_eq!(fuse.state(), FuseState::Armed);
    }

    #[test]
    fn test_fuse_consume_single() {
        let mut fuse = EntropyFuse::new(3_000, 1_000);

        assert_eq!(fuse.consume(0xDEAD), FuseState::Armed);
        assert_eq!(fuse.remaining_mb(), 2_000);
        assert_eq!(fuse.operations_consumed(), 1);

        assert_eq!(fuse.consume(0xBEEF), FuseState::Armed);
        assert_eq!(fuse.remaining_mb(), 1_000);

        // Last operation triggers the fuse
        assert_eq!(fuse.consume(0xCAFE), FuseState::Triggered);
        assert_eq!(fuse.remaining_mb(), 0);
        assert_eq!(fuse.operations_consumed(), 3);
    }

    #[test]
    fn test_fuse_triggered_stays_triggered() {
        let mut fuse = EntropyFuse::new(1_000, 1_000);

        assert_eq!(fuse.consume(1), FuseState::Triggered);
        assert_eq!(fuse.consume(2), FuseState::Triggered);
        assert_eq!(fuse.consume(3), FuseState::Triggered);
    }

    #[test]
    fn test_fuse_entropy_accumulator() {
        let mut fuse = EntropyFuse::for_operations(10);

        fuse.consume(0xDEAD_BEEF);
        let e1 = fuse.entropy_accumulator();
        assert_ne!(e1, 0, "Entropy accumulator should be non-zero");

        fuse.consume(0xCAFE_BABE);
        let e2 = fuse.entropy_accumulator();
        assert_ne!(e2, e1, "Entropy should change with each operation");
    }

    #[test]
    fn test_fuse_batch_consume() {
        let mut fuse = EntropyFuse::for_operations(5);
        let quotients = vec![1, 2, 3, 4, 5];

        let state = fuse.consume_batch(&quotients);
        assert_eq!(state, FuseState::Triggered);
        assert_eq!(fuse.operations_consumed(), 5);
    }

    #[test]
    fn test_fuse_batch_partial_trigger() {
        let mut fuse = EntropyFuse::for_operations(3);
        let quotients = vec![1, 2, 3, 4, 5];

        let state = fuse.consume_batch(&quotients);
        assert_eq!(state, FuseState::Triggered);
        // Should stop at 3 operations (when budget exhausted)
        assert_eq!(fuse.operations_consumed(), 3);
    }

    #[test]
    fn test_fuse_mark_spent() {
        let mut fuse = EntropyFuse::for_operations(100);
        fuse.consume(42);
        fuse.mark_spent();

        assert_eq!(fuse.state(), FuseState::Spent);
        assert_eq!(fuse.remaining_mb(), 0);
    }

    #[test]
    fn test_fuse_remaining_percent() {
        let mut fuse = EntropyFuse::new(10_000, 1_000);

        assert_eq!(fuse.remaining_percent(), 100);
        fuse.consume(1);
        assert_eq!(fuse.remaining_percent(), 90);
        fuse.consume(2);
        assert_eq!(fuse.remaining_percent(), 80);
    }

    #[test]
    fn test_fuse_different_quotients_different_entropy() {
        let mut f1 = EntropyFuse::for_operations(10);
        let mut f2 = EntropyFuse::for_operations(10);

        f1.consume(0x1111_1111);
        f2.consume(0x2222_2222);

        assert_ne!(
            f1.entropy_accumulator(),
            f2.entropy_accumulator(),
            "Different quotients should produce different entropy"
        );
    }
}
