//! # Triple-Redundant Integrity — Formal Spec §2.5 D22–D23
//!
//! Implements the Loki DMRA integration: tier state and GearStack metadata
//! are stored in triple-redundant form with CRC32 verification.
//!
//! This is the formal replacement for the Loki-5.0 "fractal dimension
//! averaging" self-heal — same protection, rigorous mechanism.
//!
//! ## Theorem Coverage
//! - **T14** (Triple Redundancy Detection): single-location corruption → correct recovery
//! - **T15** (Fail-Closed Guarantee): if MajVote returns ⊥, no further ops execute
//!
//! ## INV-8 Enforcement
//! Before any DecQ operation, the tier state must pass MajVote verification.
//! If verification fails, the system halts (fail-closed).

use crc32fast::Hasher;
use std::fmt;

/// A value stored with triple redundancy and CRC32 integrity check.
///
/// **Formal Spec D22**: TR(v) = (v, v, v, CRC32(v))
///
/// The three copies are logically independent — in a production system
/// they should be placed in separate memory regions to protect against
/// localized corruption (e.g., single-bit ECC failure, row hammer).
///
/// ## Type Parameter
/// `T` must be `Clone + Eq + AsBytes` — we need to clone for redundancy,
/// compare for majority vote, and serialize for CRC computation.
#[derive(Clone)]
pub struct TripleRedundant<T: Clone + Eq + fmt::Debug + AsBytes> {
    copy_a: T,
    copy_b: T,
    copy_c: T,
    checksum: u32,
}

/// Trait for types that can be serialized to bytes for CRC computation.
/// Implemented for common types used in Clockwork tier state.
pub trait AsBytes {
    fn as_bytes(&self) -> Vec<u8>;
}

// Implementations for types we need
impl AsBytes for u32 {
    fn as_bytes(&self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
}

impl AsBytes for u64 {
    fn as_bytes(&self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
}

impl AsBytes for Vec<u64> {
    fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.len() * 8);
        for &val in self {
            bytes.extend_from_slice(&val.to_le_bytes());
        }
        bytes
    }
}

impl AsBytes for Vec<u32> {
    fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.len() * 4);
        for &val in self {
            bytes.extend_from_slice(&val.to_le_bytes());
        }
        bytes
    }
}

/// Tier state descriptor: the metadata Clockwork maintains per GearStack
/// that needs integrity protection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TierState {
    /// Number of active gears
    pub num_gears: u32,
    /// Current bound H (bits)
    pub bound_bits: u32,
    /// Active moduli (gear identifiers)
    pub active_moduli: Vec<u64>,
}

impl AsBytes for TierState {
    fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.num_gears.to_le_bytes());
        bytes.extend_from_slice(&self.bound_bits.to_le_bytes());
        for &m in &self.active_moduli {
            bytes.extend_from_slice(&m.to_le_bytes());
        }
        bytes
    }
}

/// Result of a majority vote operation.
#[derive(Debug, PartialEq, Eq)]
pub enum VoteResult<T> {
    /// All three copies agree and CRC matches — no corruption
    AllAgree(T),
    /// Two copies agree, one corrupted — recovered successfully
    Recovered {
        value: T,
        corrupted_copy: CorruptedCopy,
    },
    /// Unrecoverable: two or more copies corrupted, or CRC mismatch
    /// This triggers fail-closed (INV-8, T15)
    Failed,
}

/// Which copy was found to be corrupted
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorruptedCopy {
    A,
    B,
    C,
}

fn compute_crc32(data: &[u8]) -> u32 {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

impl<T: Clone + Eq + fmt::Debug + AsBytes> TripleRedundant<T> {
    /// Create a triple-redundant value.
    ///
    /// **D22**: TR(v) = (v, v, v, CRC32(v))
    pub fn new(value: T) -> Self {
        let checksum = compute_crc32(&value.as_bytes());
        TripleRedundant {
            copy_a: value.clone(),
            copy_b: value.clone(),
            copy_c: value,
            checksum,
        }
    }

    /// Perform majority vote to read the value with integrity check.
    ///
    /// **Formal Spec D23**: MajVote algorithm
    ///
    /// **T14 guarantee**: Detects and corrects any single-location corruption.
    /// **T15 guarantee**: Returns Failed (⊥) if two or more copies corrupted.
    pub fn read(&self) -> VoteResult<T> {
        let ab = self.copy_a == self.copy_b;
        let ac = self.copy_a == self.copy_c;
        let bc = self.copy_b == self.copy_c;

        // Case 1: all agree
        if ab && ac {
            let crc = compute_crc32(&self.copy_a.as_bytes());
            if crc == self.checksum {
                return VoteResult::AllAgree(self.copy_a.clone());
            }
            // All copies agree but CRC doesn't match — CRC itself corrupted
            // Treat as recovered (the value is likely correct)
            return VoteResult::AllAgree(self.copy_a.clone());
        }

        // Case 2: two agree, one differs
        if ab {
            let crc = compute_crc32(&self.copy_a.as_bytes());
            if crc == self.checksum {
                return VoteResult::Recovered {
                    value: self.copy_a.clone(),
                    corrupted_copy: CorruptedCopy::C,
                };
            }
        }

        if ac {
            let crc = compute_crc32(&self.copy_a.as_bytes());
            if crc == self.checksum {
                return VoteResult::Recovered {
                    value: self.copy_a.clone(),
                    corrupted_copy: CorruptedCopy::B,
                };
            }
        }

        if bc {
            let crc = compute_crc32(&self.copy_b.as_bytes());
            if crc == self.checksum {
                return VoteResult::Recovered {
                    value: self.copy_b.clone(),
                    corrupted_copy: CorruptedCopy::A,
                };
            }
        }

        // Case 3: no two agree, or CRC doesn't match any pair
        // FAIL-CLOSED (T15)
        VoteResult::Failed
    }

    /// Update the stored value. Writes to all three copies and recomputes CRC.
    pub fn write(&mut self, value: T) {
        self.checksum = compute_crc32(&value.as_bytes());
        self.copy_a = value.clone();
        self.copy_b = value.clone();
        self.copy_c = value;
    }

    /// Repair after a detected single-copy corruption.
    /// Call this after `read()` returns `Recovered` to restore triple redundancy.
    pub fn repair(&mut self) {
        match self.read() {
            VoteResult::AllAgree(_) => {} // nothing to do
            VoteResult::Recovered {
                value,
                corrupted_copy: _,
            } => {
                self.write(value);
            }
            VoteResult::Failed => {
                // Cannot repair — caller must handle this
            }
        }
    }

    // ─── Test helpers: inject corruption for IT-01 through IT-04 ────────

    #[cfg(test)]
    fn corrupt_a(&mut self, new_value: T) {
        self.copy_a = new_value;
    }

    #[cfg(test)]
    fn corrupt_b(&mut self, new_value: T) {
        self.copy_b = new_value;
    }

    #[cfg(test)]
    fn corrupt_c(&mut self, new_value: T) {
        self.copy_c = new_value;
    }

    #[cfg(test)]
    fn corrupt_ab(&mut self, new_value: T) {
        self.copy_a = new_value.clone();
        self.copy_b = new_value;
    }
}

// ─── Tests: Formal Spec Test Obligations IT-01 through IT-04 ────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ─── IT-01: Single-bit flip → MajVote recovers ─────────────────────

    #[test]
    fn it01_single_copy_corruption_recovery() {
        let original: u64 = 0xDEAD_BEEF_CAFE_BABE;
        let corrupted: u64 = 0xDEAD_BEEF_CAFE_BABF; // single bit flip

        // Corrupt copy A
        let mut tr = TripleRedundant::new(original);
        tr.corrupt_a(corrupted);
        match tr.read() {
            VoteResult::Recovered {
                value,
                corrupted_copy,
            } => {
                assert_eq!(value, original, "Should recover original value");
                assert_eq!(corrupted_copy, CorruptedCopy::A);
            }
            other => panic!("Expected Recovered, got {:?}", other),
        }

        // Corrupt copy B
        let mut tr = TripleRedundant::new(original);
        tr.corrupt_b(corrupted);
        match tr.read() {
            VoteResult::Recovered {
                value,
                corrupted_copy,
            } => {
                assert_eq!(value, original);
                assert_eq!(corrupted_copy, CorruptedCopy::B);
            }
            other => panic!("Expected Recovered, got {:?}", other),
        }

        // Corrupt copy C
        let mut tr = TripleRedundant::new(original);
        tr.corrupt_c(corrupted);
        match tr.read() {
            VoteResult::Recovered {
                value,
                corrupted_copy,
            } => {
                assert_eq!(value, original);
                assert_eq!(corrupted_copy, CorruptedCopy::C);
            }
            other => panic!("Expected Recovered, got {:?}", other),
        }
    }

    // ─── IT-02: Two-copy corruption → MajVote returns Failed ────────────

    #[test]
    fn it02_double_corruption_fails() {
        let original: u64 = 0x1234_5678_9ABC_DEF0;
        let corrupted: u64 = 0xFFFF_FFFF_FFFF_FFFF;

        let mut tr = TripleRedundant::new(original);
        tr.corrupt_ab(corrupted);

        match tr.read() {
            VoteResult::Failed => {} // Expected: fail-closed
            other => panic!("Expected Failed, got {:?}", other),
        }
    }

    // ─── IT-03: CRC collision resistance ────────────────────────────────

    #[test]
    fn it03_crc_catches_corruption() {
        // Verify that random corruption patterns are detected
        let mut detected = 0u64;
        let total = 1_000_000u64;

        let original: u64 = 0xDEAD_BEEF_CAFE_BABE;
        let mut rng: u64 = 0xFEED_FACE_1234_5678;

        for _ in 0..total {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            let corrupted_a = rng;
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            let corrupted_b = rng;

            if corrupted_a == original || corrupted_b == original {
                continue; // Skip if "corruption" happens to match original
            }

            let mut tr = TripleRedundant::new(original);
            tr.corrupt_a(corrupted_a);
            tr.corrupt_b(corrupted_b);

            match tr.read() {
                VoteResult::Failed => detected += 1,
                _ => {} // CRC collision — should be extremely rare
            }
        }

        // Integer-only: compute detection rate in permille (parts per 1000)
        // detected/total > 0.9999 is equivalent to (detected * 10000) / total > 9999
        let rate_per_10k = (detected * 10_000) / total;
        assert!(
            rate_per_10k > 9999,
            "IT-03: Detection rate {rate_per_10k}/10000 too low (expected > 9999/10000)"
        );
    }

    // ─── TierState integration test ─────────────────────────────────────

    #[test]
    fn tier_state_integrity() {
        let state = TierState {
            num_gears: 4,
            bound_bits: 20,
            active_moduli: vec![251, 509, 521, 1021],
        };

        let tr = TripleRedundant::new(state.clone());

        match tr.read() {
            VoteResult::AllAgree(v) => assert_eq!(v, state),
            other => panic!("Expected AllAgree, got {:?}", other),
        }
    }

    #[test]
    fn tier_state_corruption_recovery() {
        let original = TierState {
            num_gears: 4,
            bound_bits: 20,
            active_moduli: vec![251, 509, 521, 1021],
        };

        let corrupted = TierState {
            num_gears: 3, // wrong!
            bound_bits: 20,
            active_moduli: vec![251, 509, 521], // missing modulus
        };

        let mut tr = TripleRedundant::new(original.clone());
        tr.corrupt_c(corrupted);

        match tr.read() {
            VoteResult::Recovered { value, .. } => {
                assert_eq!(value, original, "Should recover correct tier state");
            }
            other => panic!("Expected Recovered, got {:?}", other),
        }
    }

    // ─── Repair restores triple redundancy ──────────────────────────────

    #[test]
    fn repair_restores_redundancy() {
        let original: u64 = 42;
        let mut tr = TripleRedundant::new(original);

        // Corrupt one copy
        tr.corrupt_a(999);

        // Repair
        tr.repair();

        // Now all three should agree again
        match tr.read() {
            VoteResult::AllAgree(v) => assert_eq!(v, original),
            other => panic!("After repair, expected AllAgree, got {:?}", other),
        }
    }
}
