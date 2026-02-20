//! # GearStack — Formal Spec composite type
//!
//! A GearStack is the primary working type in Clockwork: it holds a value's
//! RNS residues, a reference to its basis, and a bound tracker entry.
//!
//! This is the type that enforces INV-2 (representation consistency) and
//! INV-3 (bound tracker soundness) at every arithmetic operation.
//!
//! ## Design Principle
//! Every arithmetic operation on GearStack values returns a new GearStack
//! with an updated bound. The bound is NEVER computed from the actual value —
//! it is always derived from the operand bounds using the rules in D7.
//! This ensures the bound is schedule-based and value-independent (INV-7).

use crate::basis::RnsBasis;
use crate::bound_tracker::Bound;

/// A value represented in the Clockwork RNS system.
///
/// Holds:
/// - Residue vector (the RNS encoding of the value)
/// - Bound on the centered lift's magnitude (from D7)
/// - Reference to the basis being used
///
/// ## Invariants maintained by construction:
/// - `residues.len() == basis.num_gears()`
/// - `residues[i] < basis.modulus(i)` for all i
/// - `|Center_{M_k}(value)| < 2^{bound}`
/// - `basis.capacity() > 2^{bound + guard}`
#[derive(Clone, Debug)]
pub struct GearStack {
    /// RNS residues: (r_0, ..., r_k) where r_i = value mod p_i
    residues: Vec<u64>,
    /// Upper bound H such that |Center_{M_k}(value)| < 2^H
    /// This is NEVER computed from the value — always from operation rules.
    bound: Bound,
    /// The RNS basis this value lives in
    basis: RnsBasis,
}

/// Errors during GearStack operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GearError {
    /// Basis capacity too small for the result's bound + guard
    InsufficientCapacity {
        required_bits: u32,
        capacity_bits: u32,
    },
    /// Mismatched bases between operands
    BasisMismatch,
    /// Value exceeds the claimed bound (detected during verification)
    BoundViolation {
        claimed_bound: u32,
        actual_bits: u32,
    },
}

impl std::fmt::Display for GearError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GearError::InsufficientCapacity {
                required_bits,
                capacity_bits,
            } => write!(
                f,
                "Need M_k > 2^{required_bits} but capacity is only 2^{capacity_bits}"
            ),
            GearError::BasisMismatch => write!(f, "Operands use different RNS bases"),
            GearError::BoundViolation {
                claimed_bound,
                actual_bits,
            } => write!(
                f,
                "Bound claims H={claimed_bound} but actual value needs {actual_bits} bits"
            ),
        }
    }
}

/// Default guard margin (in bits) between bound and capacity.
/// This is the safety margin from formal spec A5:
///   M_k > 2^{H + guard}
pub const DEFAULT_GUARD_BITS: u32 = 8;

impl GearStack {
    /// Create a GearStack from a known unsigned value and its bit-length bound.
    ///
    /// The value is encoded into the basis, and the bound is set to the
    /// provided value (NOT computed from the actual value — caller specifies).
    ///
    /// Returns `GearError::InsufficientCapacity` if the basis can't hold
    /// 2^{bound + guard}.
    pub fn from_value(value: u128, bound_bits: u32, basis: RnsBasis) -> Result<Self, GearError> {
        let guard = DEFAULT_GUARD_BITS;
        let required = bound_bits + guard;
        let cap_bits = capacity_bits(&basis);

        if cap_bits < required {
            return Err(GearError::InsufficientCapacity {
                required_bits: required,
                capacity_bits: cap_bits,
            });
        }

        let residues = basis.encode(value);
        Ok(GearStack {
            residues,
            bound: Bound::new(bound_bits),
            basis,
        })
    }

    /// Create a GearStack from a signed (centered) value.
    pub fn from_signed(value: i128, bound_bits: u32, basis: RnsBasis) -> Result<Self, GearError> {
        let guard = DEFAULT_GUARD_BITS;
        let required = bound_bits + guard;
        let cap_bits = capacity_bits(&basis);

        if cap_bits < required {
            return Err(GearError::InsufficientCapacity {
                required_bits: required,
                capacity_bits: cap_bits,
            });
        }

        let residues = basis.encode_signed(value);
        Ok(GearStack {
            residues,
            bound: Bound::new(bound_bits),
            basis,
        })
    }

    /// Access the residue vector.
    pub fn residues(&self) -> &[u64] {
        &self.residues
    }

    /// Access the bound.
    pub fn bound(&self) -> &Bound {
        &self.bound
    }

    /// Access the basis.
    pub fn basis(&self) -> &RnsBasis {
        &self.basis
    }

    /// Decode to the unsigned representative in [0, M_k).
    pub fn decode(&self) -> u128 {
        self.basis.decode(&self.residues)
    }

    /// Decode to the centered lift in [-M_k/2, M_k/2].
    pub fn decode_centered(&self) -> i128 {
        self.basis.decode_centered(&self.residues)
    }

    // ─── Arithmetic with automatic bound tracking (D7) ──────────────────

    /// Add two GearStack values. Returns a new GearStack with updated bound.
    ///
    /// **D7 bound rule**: H(X+Y) ≤ max(H(X), H(Y)) + 1
    ///
    /// Both operands must share the same basis (INV checked at runtime).
    pub fn add(&self, other: &GearStack) -> Result<GearStack, GearError> {
        if self.basis.moduli() != other.basis.moduli() {
            return Err(GearError::BasisMismatch);
        }

        // Lane-wise addition mod each p_i (T1: ring homomorphism)
        let residues: Vec<u64> = self
            .residues
            .iter()
            .zip(other.residues.iter())
            .enumerate()
            .map(|(i, (&a, &b))| (a + b) % self.basis.modulus(i))
            .collect();

        // D7 bound update: H(X+Y) ≤ max(H(X), H(Y)) + 1
        let new_bound = Bound::add_bound(&self.bound, &other.bound);

        // Check capacity is sufficient
        let required = new_bound.bits() + DEFAULT_GUARD_BITS;
        let cap = capacity_bits(&self.basis);
        if cap < required {
            return Err(GearError::InsufficientCapacity {
                required_bits: required,
                capacity_bits: cap,
            });
        }

        Ok(GearStack {
            residues,
            bound: new_bound,
            basis: self.basis.clone(),
        })
    }

    /// Subtract two GearStack values. Same bound rule as addition.
    pub fn sub(&self, other: &GearStack) -> Result<GearStack, GearError> {
        if self.basis.moduli() != other.basis.moduli() {
            return Err(GearError::BasisMismatch);
        }

        let residues: Vec<u64> = self
            .residues
            .iter()
            .zip(other.residues.iter())
            .enumerate()
            .map(|(i, (&a, &b))| {
                let p = self.basis.modulus(i);
                (a + p - b) % p
            })
            .collect();

        // Same bound as addition: H(X-Y) ≤ max(H(X), H(Y)) + 1
        let new_bound = Bound::add_bound(&self.bound, &other.bound);

        let required = new_bound.bits() + DEFAULT_GUARD_BITS;
        let cap = capacity_bits(&self.basis);
        if cap < required {
            return Err(GearError::InsufficientCapacity {
                required_bits: required,
                capacity_bits: cap,
            });
        }

        Ok(GearStack {
            residues,
            bound: new_bound,
            basis: self.basis.clone(),
        })
    }

    /// Multiply two GearStack values.
    ///
    /// **D7 bound rule**: H(X·Y) ≤ H(X) + H(Y)
    pub fn mul(&self, other: &GearStack) -> Result<GearStack, GearError> {
        if self.basis.moduli() != other.basis.moduli() {
            return Err(GearError::BasisMismatch);
        }

        // Lane-wise multiplication mod each p_i
        let residues: Vec<u64> = self
            .residues
            .iter()
            .zip(other.residues.iter())
            .enumerate()
            .map(|(i, (&a, &b))| {
                let p = self.basis.modulus(i) as u128;
                ((a as u128 * b as u128) % p) as u64
            })
            .collect();

        // D7 bound update: H(X·Y) ≤ H(X) + H(Y)
        let new_bound = Bound::mul_bound(&self.bound, &other.bound);

        let required = new_bound.bits() + DEFAULT_GUARD_BITS;
        let cap = capacity_bits(&self.basis);
        if cap < required {
            return Err(GearError::InsufficientCapacity {
                required_bits: required,
                capacity_bits: cap,
            });
        }

        Ok(GearStack {
            residues,
            bound: new_bound,
            basis: self.basis.clone(),
        })
    }

    // ─── Verification ───────────────────────────────────────────────────

    /// Verify that the actual value satisfies the claimed bound.
    ///
    /// This is a DEBUG/TEST operation — it reconstructs the full value,
    /// which is exactly what Clockwork avoids in production. Use only
    /// for test obligation CT-03.
    ///
    /// Returns Ok(()) if |Center(value)| < 2^{bound}, Err otherwise.
    pub fn verify_bound(&self) -> Result<(), GearError> {
        let centered = self.decode_centered();
        let abs_val = centered.unsigned_abs();
        let actual_bits = if abs_val == 0 {
            0
        } else {
            128 - abs_val.leading_zeros()
        };

        if actual_bits > self.bound.bits() {
            return Err(GearError::BoundViolation {
                claimed_bound: self.bound.bits(),
                actual_bits,
            });
        }
        Ok(())
    }

    /// Check whether this GearStack needs promotion (basis extension)
    /// to safely perform an operation that would increase the bound by `delta_bits`.
    pub fn needs_promotion(&self, delta_bits: u32) -> bool {
        let required = self.bound.bits() + delta_bits + DEFAULT_GUARD_BITS;
        capacity_bits(&self.basis) < required
    }
}

/// Compute the approximate bit-length of the basis capacity.
/// Returns ⌊log₂(M_k)⌋. All integer arithmetic.
fn capacity_bits(basis: &RnsBasis) -> u32 {
    let cap = basis.capacity();
    if cap == 0 {
        return 0;
    }
    128 - cap.leading_zeros()
}

// ─── Dot product with bound tracking ─────────────────────────────────────────

/// Compute the dot product of two GearStack vectors with tracked bounds.
///
/// **D7 bound rule**: H(∑ w_j·x_j) ≤ ⌈log₂ L⌉ + max_j(H(w_j) + H(x_j))
///
/// This is the critical operation for matrix multiplication in FHE.
pub fn dot_product(weights: &[GearStack], values: &[GearStack]) -> Result<GearStack, GearError> {
    assert_eq!(weights.len(), values.len(), "Dot product length mismatch");
    assert!(!weights.is_empty(), "Empty dot product");

    let mut accumulator = weights[0].mul(&values[0])?;

    for i in 1..weights.len() {
        let term = weights[i].mul(&values[i])?;
        accumulator = accumulator.add(&term)?;
    }

    // The bound should already be correct from the chained operations,
    // but we can tighten it using the D7 dot product rule:
    // H ≤ ⌈log₂ L⌉ + max_j(H(w_j) + H(x_j))
    // The chained add/mul gives a looser bound; the tighter bound is an optimization.

    Ok(accumulator)
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_basis() -> RnsBasis {
        RnsBasis::new(vec![251, 509, 521, 1021]).unwrap()
    }

    // ─── CT-03: Bound tracker vs actual value ───────────────────────────

    #[test]
    fn ct03_bound_tracker_soundness() {
        let basis = test_basis();

        let mut rng: u64 = 0xDEAD_BEEF_1234_5678;
        for _ in 0..100_000 {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);

            // Create values with known bounds
            let x_val = (rng as u128) % 1024; // fits in 10 bits
            let gs_x = GearStack::from_value(x_val, 10, basis.clone()).unwrap();

            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            let y_val = (rng as u128) % 1024;
            let gs_y = GearStack::from_value(y_val, 10, basis.clone()).unwrap();

            // Addition: bound should be 11 (max(10,10) + 1)
            let sum = gs_x.add(&gs_y).unwrap();
            assert_eq!(sum.bound().bits(), 11, "Add bound should be 11");
            sum.verify_bound().expect("Add bound must be sound");

            // Multiplication: bound should be 20 (10 + 10)
            let prod = gs_x.mul(&gs_y).unwrap();
            assert_eq!(prod.bound().bits(), 20, "Mul bound should be 20");
            prod.verify_bound().expect("Mul bound must be sound");

            // Chain: (x + y) * x — bound should be 11 + 10 = 21
            let chained = sum.mul(&gs_x).unwrap();
            assert_eq!(chained.bound().bits(), 21, "Chain bound should be 21");
            chained.verify_bound().expect("Chain bound must be sound");
        }
    }

    #[test]
    fn ct03_bound_tracker_never_underestimates() {
        let basis = test_basis();

        // Worst case for addition: max values
        let x = GearStack::from_value(1023, 10, basis.clone()).unwrap();
        let y = GearStack::from_value(1023, 10, basis.clone()).unwrap();

        let sum = x.add(&y).unwrap();
        sum.verify_bound()
            .expect("Bound must cover worst-case addition");

        // Worst case for multiplication
        let prod = x.mul(&y).unwrap();
        prod.verify_bound()
            .expect("Bound must cover worst-case multiplication");
    }

    // ─── CT-06: Lane-wise operations match ring operations ──────────────

    #[test]
    fn ct06_lane_add_matches_ring() {
        let basis = test_basis();
        let m = basis.capacity();

        let mut rng: u64 = 0xAAAA_BBBB_CCCC_DDDD;
        for _ in 0..100_000 {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            let a_val = (rng as u128) % 256;
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            let b_val = (rng as u128) % 256;

            let gs_a = GearStack::from_value(a_val, 8, basis.clone()).unwrap();
            let gs_b = GearStack::from_value(b_val, 8, basis.clone()).unwrap();

            let gs_sum = gs_a.add(&gs_b).unwrap();
            let decoded = gs_sum.decode();

            assert_eq!(
                (a_val + b_val) % m,
                decoded,
                "Lane add mismatch: {a_val}+{b_val}"
            );
        }
    }

    #[test]
    fn ct06_lane_mul_matches_ring() {
        let basis = test_basis();
        let m = basis.capacity();

        let mut rng: u64 = 0x1111_2222_3333_4444;
        for _ in 0..100_000 {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            let a_val = (rng as u128) % 256;
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            let b_val = (rng as u128) % 256;

            let gs_a = GearStack::from_value(a_val, 8, basis.clone()).unwrap();
            let gs_b = GearStack::from_value(b_val, 8, basis.clone()).unwrap();

            let gs_prod = gs_a.mul(&gs_b).unwrap();
            let decoded = gs_prod.decode();

            assert_eq!(
                (a_val * b_val) % m,
                decoded,
                "Lane mul mismatch: {a_val}*{b_val}"
            );
        }
    }

    #[test]
    fn insufficient_capacity_detected() {
        // Tiny basis that can't hold large values
        let tiny = RnsBasis::new(vec![7, 11]).unwrap(); // M = 77, ~6.3 bits
        let result = GearStack::from_value(50, 10, tiny);
        assert!(
            result.is_err(),
            "Should reject: 10 + 8 guard > 6 bit capacity"
        );
    }
}
