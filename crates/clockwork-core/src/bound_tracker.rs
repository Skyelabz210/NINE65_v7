//! # Bound Tracker — Formal Spec §2.1 D7
//!
//! Deterministic integer bounds on the magnitude of centered-lift values.
//! This is the mechanism that replaces all floating-point `log2_height`
//! estimates with exact, auditable, schedule-based bounds.
//!
//! ## Key Property (T4: Bound Tracker Soundness)
//! If all input values satisfy |Center(X)| < 2^{H(X)}, then all computed
//! values satisfy |Center(Y)| < 2^{H(Y)} under the update rules.
//!
//! ## No Floating Point
//! This entire module uses only integer arithmetic. The "bits" field
//! is a u32 representing the exponent in the bound 2^H.

/// A deterministic upper bound on the bit-length of a centered-lift value.
///
/// **Formal Spec D7**: H such that |Center_{M_k}(X)| < 2^H.
///
/// All update rules are integer-only and always overestimate (safe).
/// This ensures T4 (soundness) by construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bound {
    /// The bound exponent: |value| < 2^bits
    bits: u32,
}

impl Bound {
    /// Create a bound for a value known to fit in `bits` bits.
    pub fn new(bits: u32) -> Self {
        Bound { bits }
    }

    /// The bound exponent.
    pub fn bits(&self) -> u32 {
        self.bits
    }

    /// Create a bound for a known constant value.
    /// Returns the minimal bound: ⌈log₂(|value| + 1)⌉.
    /// All integer arithmetic.
    pub fn from_value(value: i128) -> Self {
        let abs = value.unsigned_abs();
        if abs == 0 {
            return Bound { bits: 0 };
        }
        // ⌈log₂(abs + 1)⌉ = 128 - (abs).leading_zeros() when abs > 0
        // But we need abs < 2^H, so H = 128 - abs.leading_zeros() works
        // because 2^(128 - lz) > abs for all abs > 0.
        let bits = 128 - abs.leading_zeros();
        Bound { bits }
    }

    // ─── D7 Update Rules ────────────────────────────────────────────────

    /// Addition bound: H(X+Y) ≤ max(H(X), H(Y)) + 1
    ///
    /// Proof: |X+Y| ≤ |X| + |Y| < 2^{H(X)} + 2^{H(Y)} ≤ 2^{max+1}
    pub fn add_bound(a: &Bound, b: &Bound) -> Bound {
        Bound {
            bits: a.bits.max(b.bits) + 1,
        }
    }

    /// Subtraction bound: same as addition.
    /// H(X-Y) ≤ max(H(X), H(Y)) + 1
    pub fn sub_bound(a: &Bound, b: &Bound) -> Bound {
        Self::add_bound(a, b)
    }

    /// Multiplication bound: H(X·Y) ≤ H(X) + H(Y)
    ///
    /// Proof: |X·Y| ≤ |X|·|Y| < 2^{H(X)} · 2^{H(Y)} = 2^{H(X)+H(Y)}
    pub fn mul_bound(a: &Bound, b: &Bound) -> Bound {
        Bound {
            bits: a.bits + b.bits,
        }
    }

    /// Dot product bound: H(∑_{j=1}^{L} w_j·x_j) ≤ ⌈log₂ L⌉ + max_j(H(w_j) + H(x_j))
    ///
    /// Tighter than chaining add+mul individually.
    /// `term_bounds` is a slice of (H(w_j), H(x_j)) pairs.
    ///
    /// # Panics
    /// Panics if `term_bounds` is empty.
    pub fn dot_product_bound(term_bounds: &[(u32, u32)]) -> Bound {
        assert!(
            !term_bounds.is_empty(),
            "Dot product must have at least one term"
        );

        let l = term_bounds.len() as u32;
        // ⌈log₂ L⌉ — integer computation
        let log2_l = if l <= 1 {
            0
        } else {
            32 - (l - 1).leading_zeros()
        };

        let max_product_bound = term_bounds.iter().map(|(hw, hx)| hw + hx).max().unwrap();

        Bound {
            bits: log2_l + max_product_bound,
        }
    }

    /// Negation bound: H(-X) = H(X)
    pub fn neg_bound(a: &Bound) -> Bound {
        a.clone()
    }

    /// Scalar multiplication by a known constant c:
    /// H(c·X) ≤ H(c) + H(X)
    pub fn scalar_mul_bound(scalar_bits: u32, a: &Bound) -> Bound {
        Bound {
            bits: scalar_bits + a.bits,
        }
    }

    // ─── Promotion policy ───────────────────────────────────────────────

    /// Check if a basis with the given capacity (in bits) has sufficient
    /// headroom for this bound plus the guard margin.
    ///
    /// The promotion policy from D7: M_k > 2^{H + guard}
    pub fn needs_promotion(&self, capacity_bits: u32, guard: u32) -> bool {
        capacity_bits < self.bits + guard
    }

    /// Compute the minimum number of capacity bits needed for this bound.
    pub fn required_capacity_bits(&self, guard: u32) -> u32 {
        self.bits + guard
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bound_from_value() {
        assert_eq!(Bound::from_value(0).bits(), 0);
        assert_eq!(Bound::from_value(1).bits(), 1);
        assert_eq!(Bound::from_value(2).bits(), 2);
        assert_eq!(Bound::from_value(3).bits(), 2);
        assert_eq!(Bound::from_value(4).bits(), 3);
        assert_eq!(Bound::from_value(255).bits(), 8);
        assert_eq!(Bound::from_value(256).bits(), 9);
        assert_eq!(Bound::from_value(-1).bits(), 1);
        assert_eq!(Bound::from_value(-128).bits(), 8);
    }

    #[test]
    fn addition_bound_correct() {
        let a = Bound::new(10);
        let b = Bound::new(10);
        let sum = Bound::add_bound(&a, &b);
        assert_eq!(sum.bits(), 11); // max(10,10) + 1

        let c = Bound::new(8);
        let sum2 = Bound::add_bound(&a, &c);
        assert_eq!(sum2.bits(), 11); // max(10,8) + 1
    }

    #[test]
    fn multiplication_bound_correct() {
        let a = Bound::new(10);
        let b = Bound::new(8);
        let prod = Bound::mul_bound(&a, &b);
        assert_eq!(prod.bits(), 18); // 10 + 8
    }

    #[test]
    fn dot_product_bound_tighter_than_chain() {
        // 4-element dot product of 8-bit × 8-bit values
        let terms: Vec<(u32, u32)> = vec![(8, 8), (8, 8), (8, 8), (8, 8)];
        let dp_bound = Bound::dot_product_bound(&terms);

        // D7 says: ⌈log₂ 4⌉ + max(8+8) = 2 + 16 = 18
        assert_eq!(dp_bound.bits(), 18);

        // Chained approach would give: mul(8,8)=16, add(16,16)=17, add(17,16)=18, add(18,16)=19
        // So the dot product bound (18) is tighter than chaining (19).
        // (In this case they're close, but with more terms the gap widens.)
    }

    #[test]
    fn promotion_policy() {
        let b = Bound::new(20);
        // With guard=8, need capacity > 28 bits
        assert!(b.needs_promotion(27, 8)); // 27 < 28
        assert!(!b.needs_promotion(28, 8)); // 28 ≥ 28
        assert!(!b.needs_promotion(64, 8)); // plenty of room
    }
}
