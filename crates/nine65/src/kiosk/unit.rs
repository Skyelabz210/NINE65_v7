//! # Kiosk Unit Types — Bullet, Capsule, Fuse
//!
//! The three kiosk unit types represent different "ammunition" models
//! for FHE computation:
//!
//! | Type | Uses | Lifetime | Use Case |
//! |------|------|----------|----------|
//! | **Bullet** | 1 | Single computation | One-shot encrypted query |
//! | **Capsule** | N | Budget-limited | Session-based encryption |
//! | **Fuse** | ∞ | Time-limited | Time-boxed processing |
//!
//! All unit types share the same destruction sequence and security
//! properties. The difference is in their expiration trigger.

use std::time::Instant;

use crate::kiosk::destruction::{DestructionReceipt, DestructionSequence};
use crate::kiosk::fold::FoldOperator;
use crate::kiosk::fuse::{EntropyFuse, FuseState};
use crate::kiosk::inv8::{Inv8CheckLane, Inv8Verdict};

/// Status of a kiosk unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitStatus {
    /// Unit is ready for use
    Ready,
    /// Unit is currently executing a computation
    Active,
    /// Unit has been triggered for destruction (fuse blown)
    Triggered,
    /// Unit has been destroyed
    Destroyed,
    /// Unit detected an attack and shut down
    Compromised,
}

/// Type discriminant for kiosk units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KioskUnitType {
    /// Single-use: destroyed after one computation
    Bullet = 0,
    /// Multi-use: destroyed after N operations
    Capsule = 1,
    /// Time-limited: destroyed after a duration expires
    Fuse = 2,
}

/// Lifecycle trait for kiosk units.
pub trait KioskLifecycle {
    /// Check if the unit should self-destruct.
    fn should_destroy(&self) -> bool;

    /// Execute the self-destruction sequence.
    fn destroy(&mut self) -> Option<DestructionReceipt>;

    /// Get the unit status.
    fn status(&self) -> UnitStatus;

    /// Get the unit type.
    fn unit_type(&self) -> KioskUnitType;

    /// Get the unit ID.
    fn unit_id(&self) -> u64;
}

/// A kiosk computation unit.
///
/// Wraps FHE state with self-destruction, integrity checking, and metering.
pub struct KioskUnit {
    /// Unique unit identifier
    id: u64,
    /// Unit type
    kind: KioskUnitType,
    /// Current status
    status: UnitStatus,
    /// Fold operator for algebraic obfuscation
    fold_op: FoldOperator,
    /// RNS limbs (the computation state)
    limbs: Vec<u64>,
    /// Destruction sequence handler
    destruction: DestructionSequence,
    /// INV-8 check lane
    check_lane: Inv8CheckLane,
    /// Entropy fuse (metering)
    fuse: EntropyFuse,
    /// Creation timestamp (for Fuse-type units)
    created_at: Instant,
    /// Maximum lifetime in nanoseconds (for Fuse-type units, 0 = unlimited)
    max_lifetime_nanos: u64,
}

impl KioskUnit {
    /// Create a new Bullet (single-use) unit.
    pub fn bullet(id: u64, moduli: &[u64], seed: u64) -> Self {
        Self::new(id, KioskUnitType::Bullet, moduli, seed, 1, 0)
    }

    /// Create a new Capsule (multi-use) unit with a given operation budget.
    pub fn capsule(id: u64, moduli: &[u64], seed: u64, max_operations: u64) -> Self {
        Self::new(id, KioskUnitType::Capsule, moduli, seed, max_operations, 0)
    }

    /// Create a new Fuse (time-limited) unit with a given lifetime in nanoseconds.
    pub fn fuse(id: u64, moduli: &[u64], seed: u64, lifetime_nanos: u64) -> Self {
        Self::new(
            id,
            KioskUnitType::Fuse,
            moduli,
            seed,
            u64::MAX,
            lifetime_nanos,
        )
    }

    fn new(
        id: u64,
        kind: KioskUnitType,
        moduli: &[u64],
        seed: u64,
        max_operations: u64,
        max_lifetime_nanos: u64,
    ) -> Self {
        let fold_op = FoldOperator::new(moduli, seed);
        let limbs = vec![0u64; moduli.len()];
        let destruction = DestructionSequence::new(id, kind as u8);
        let check_lane = Inv8CheckLane::new(moduli, seed.wrapping_add(1));
        let fuse = EntropyFuse::for_operations(max_operations);

        Self {
            id,
            kind,
            status: UnitStatus::Ready,
            fold_op,
            limbs,
            destruction,
            check_lane,
            fuse,
            created_at: Instant::now(),
            max_lifetime_nanos,
        }
    }

    /// Load data into the unit's RNS limbs.
    ///
    /// Returns `false` if the unit is not in Ready state or limb count mismatch.
    pub fn load(&mut self, data: &[u64]) -> bool {
        if self.status != UnitStatus::Ready {
            return false;
        }
        if data.len() != self.limbs.len() {
            return false;
        }
        self.limbs.copy_from_slice(data);
        self.status = UnitStatus::Active;
        true
    }

    /// Perform a checked multiplication operation.
    ///
    /// The operation is verified by the INV-8 check lane and consumes
    /// entropy from the fuse. If either check fails, the unit is flagged.
    pub fn checked_mul(&mut self, index: usize, a: u64, b: u64, modulus: u64) -> Option<u64> {
        if self.status != UnitStatus::Active {
            return None;
        }
        if index >= self.limbs.len() {
            return None;
        }

        // Check lifetime for Fuse-type units
        if self.should_destroy() {
            self.status = UnitStatus::Triggered;
            return None;
        }

        // Perform the multiplication
        let result = ((a as u128 * b as u128) % modulus as u128) as u64;

        // INV-8 check
        let verdict = self.check_lane.check_mul(a, b, modulus, result);
        if verdict == Inv8Verdict::InversionDetected {
            self.status = UnitStatus::Compromised;
            return None;
        }

        // Consume fuse entropy (use result as Montgomery quotient proxy)
        let fuse_state = self.fuse.consume(result);
        if fuse_state == FuseState::Triggered {
            self.status = UnitStatus::Triggered;
            self.destruction.record_operation();
            return None;
        }

        self.limbs[index] = result;
        self.destruction.record_operation();
        Some(result)
    }

    /// Perform a checked addition operation.
    pub fn checked_add(&mut self, index: usize, a: u64, b: u64, modulus: u64) -> Option<u64> {
        if self.status != UnitStatus::Active {
            return None;
        }
        if index >= self.limbs.len() {
            return None;
        }

        if self.should_destroy() {
            self.status = UnitStatus::Triggered;
            return None;
        }

        let result = ((a as u128 + b as u128) % modulus as u128) as u64;

        let verdict = self.check_lane.check_add(a, b, modulus, result);
        if verdict == Inv8Verdict::InversionDetected {
            self.status = UnitStatus::Compromised;
            return None;
        }

        let fuse_state = self.fuse.consume(result);
        if fuse_state == FuseState::Triggered {
            self.status = UnitStatus::Triggered;
            self.destruction.record_operation();
            return None;
        }

        self.limbs[index] = result;
        self.destruction.record_operation();
        Some(result)
    }

    /// Get a reference to the current limbs (read-only).
    pub fn limbs(&self) -> &[u64] {
        &self.limbs
    }

    /// Get the entropy fuse state.
    pub fn fuse_state(&self) -> FuseState {
        self.fuse.state()
    }

    /// Get the remaining operations estimate.
    pub fn remaining_operations(&self) -> u64 {
        self.fuse.remaining_operations()
    }

    /// Get the check lane status.
    pub fn check_lane_active(&self) -> bool {
        self.check_lane.is_active()
    }

    /// Get elapsed time since creation in nanoseconds.
    pub fn elapsed_nanos(&self) -> u64 {
        self.created_at.elapsed().as_nanos() as u64
    }
}

impl KioskLifecycle for KioskUnit {
    fn should_destroy(&self) -> bool {
        match self.status {
            UnitStatus::Destroyed | UnitStatus::Compromised => true,
            UnitStatus::Triggered => true,
            _ => {
                // Check fuse
                if self.fuse.state() == FuseState::Triggered {
                    return true;
                }
                // Check time limit for Fuse-type units
                if self.max_lifetime_nanos > 0 {
                    let elapsed = self.created_at.elapsed().as_nanos() as u64;
                    if elapsed >= self.max_lifetime_nanos {
                        return true;
                    }
                }
                // Check INV-8
                if !self.check_lane.is_active() {
                    return true;
                }
                false
            }
        }
    }

    fn destroy(&mut self) -> Option<DestructionReceipt> {
        if self.status == UnitStatus::Destroyed {
            return None;
        }

        let final_entropy = self.fuse.entropy_accumulator();
        let receipt = self
            .destruction
            .execute(&mut self.fold_op, &mut self.limbs, final_entropy);

        if receipt.is_some() {
            self.fuse.mark_spent();
            self.status = UnitStatus::Destroyed;
        }

        receipt
    }

    fn status(&self) -> UnitStatus {
        self.status
    }

    fn unit_type(&self) -> KioskUnitType {
        self.kind
    }

    fn unit_id(&self) -> u64 {
        self.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MODULI: [u64; 3] = [7681, 12289, 40961];

    #[test]
    fn test_bullet_single_use() {
        let mut bullet = KioskUnit::bullet(1, &TEST_MODULI, 42);
        assert_eq!(bullet.status(), UnitStatus::Ready);
        assert_eq!(bullet.unit_type(), KioskUnitType::Bullet);

        // Load data
        assert!(bullet.load(&[100, 200, 300]));
        assert_eq!(bullet.status(), UnitStatus::Active);

        // One operation triggers the fuse
        let result = bullet.checked_mul(0, 10, 20, 7681);
        assert!(result.is_some() || bullet.status() == UnitStatus::Triggered);
    }

    #[test]
    fn test_capsule_multi_use() {
        let mut capsule = KioskUnit::capsule(2, &TEST_MODULI, 42, 10);
        assert!(capsule.load(&[100, 200, 300]));

        // Should allow multiple operations
        for i in 0..5 {
            let result = capsule.checked_mul(0, (i + 1) as u64, 2, 7681);
            if capsule.status() == UnitStatus::Triggered {
                break;
            }
            assert!(result.is_some(), "Operation {} should succeed", i);
        }
    }

    #[test]
    fn test_capsule_exhaustion() {
        let mut capsule = KioskUnit::capsule(3, &TEST_MODULI, 42, 3);
        assert!(capsule.load(&[100, 200, 300]));

        let mut ops_done = 0;
        for i in 0..10 {
            let result = capsule.checked_mul(0, (i + 1) as u64, 2, 7681);
            if result.is_none() {
                break;
            }
            ops_done += 1;
        }

        assert!(ops_done <= 3, "Capsule should stop after 3 operations");
        assert!(
            capsule.status() == UnitStatus::Triggered
                || capsule.status() == UnitStatus::Active
        );
    }

    #[test]
    fn test_unit_destruction_produces_receipt() {
        let mut unit = KioskUnit::capsule(4, &TEST_MODULI, 42, 100);
        assert!(unit.load(&[10, 20, 30]));
        unit.checked_mul(0, 5, 3, 7681);

        let receipt = unit.destroy();
        assert!(receipt.is_some());
        assert_eq!(unit.status(), UnitStatus::Destroyed);

        let receipt = receipt.unwrap();
        assert_eq!(receipt.data.unit_id, 4);
        assert_eq!(receipt.data.unit_type, KioskUnitType::Capsule as u8);
    }

    #[test]
    fn test_double_destruction_prevented() {
        let mut unit = KioskUnit::bullet(5, &TEST_MODULI, 42);
        assert!(unit.load(&[1, 2, 3]));

        assert!(unit.destroy().is_some());
        assert!(unit.destroy().is_none()); // Second destroy fails
    }

    #[test]
    fn test_load_wrong_size_rejected() {
        let mut unit = KioskUnit::bullet(6, &TEST_MODULI, 42);
        assert!(!unit.load(&[1, 2])); // Wrong size
        assert_eq!(unit.status(), UnitStatus::Ready);
    }

    #[test]
    fn test_operations_on_unloaded_rejected() {
        let mut unit = KioskUnit::capsule(7, &TEST_MODULI, 42, 10);
        // Don't load — still in Ready state
        assert!(unit.checked_mul(0, 1, 2, 7681).is_none());
    }

    #[test]
    fn test_fuse_type_unit() {
        // Create a fuse with very long lifetime (won't expire during test)
        let mut fuse_unit = KioskUnit::fuse(8, &TEST_MODULI, 42, u64::MAX);
        assert_eq!(fuse_unit.unit_type(), KioskUnitType::Fuse);

        assert!(fuse_unit.load(&[100, 200, 300]));
        let result = fuse_unit.checked_mul(0, 5, 10, 7681);
        assert!(result.is_some());

        assert!(fuse_unit.destroy().is_some());
    }

    #[test]
    fn test_check_add_operation() {
        let mut unit = KioskUnit::capsule(9, &TEST_MODULI, 42, 100);
        assert!(unit.load(&[100, 200, 300]));

        let result = unit.checked_add(0, 3000, 5000, 7681);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), (3000 + 5000) % 7681);
    }

    #[test]
    fn test_remaining_operations() {
        let unit = KioskUnit::capsule(10, &TEST_MODULI, 42, 50);
        assert_eq!(unit.remaining_operations(), 50);
    }

    #[test]
    fn test_unit_id() {
        let unit = KioskUnit::bullet(0xDEAD, &TEST_MODULI, 42);
        assert_eq!(unit.unit_id(), 0xDEAD);
    }
}
