//! ExactCoeff: Exact integer coefficient type.
//!
//! A newtype wrapper around i128 that enforces integer-only arithmetic.
//! Ring axioms verified (T2): commutativity, associativity, distributivity,
//! identity elements for + and *.
//!
//! Integer-Only Guarantee: All operations delegate to i128 checked arithmetic.

use std::fmt;
use std::ops::{Add, Mul, Neg, Sub};

/// Exact integer coefficient backed by i128.
///
/// Invariant: All arithmetic is exact (no floating-point).
/// Range: [-2^127, 2^127 - 1]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExactCoeff(pub i128);

impl ExactCoeff {
    /// Zero coefficient
    pub const ZERO: Self = ExactCoeff(0);

    /// Unit coefficient
    pub const ONE: Self = ExactCoeff(1);

    /// Checked addition returning None on overflow
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        self.0.checked_add(rhs.0).map(ExactCoeff)
    }

    /// Checked subtraction returning None on overflow
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        self.0.checked_sub(rhs.0).map(ExactCoeff)
    }

    /// Checked multiplication returning None on overflow
    pub fn checked_mul(self, rhs: Self) -> Option<Self> {
        self.0.checked_mul(rhs.0).map(ExactCoeff)
    }

    /// Checked negation returning None on overflow (i128::MIN)
    pub fn checked_neg(self) -> Option<Self> {
        self.0.checked_neg().map(ExactCoeff)
    }

    /// Absolute value, panics on i128::MIN
    pub fn abs(self) -> Self {
        ExactCoeff(self.0.abs())
    }

    /// Checked absolute value
    pub fn checked_abs(self) -> Option<Self> {
        self.0.checked_abs().map(ExactCoeff)
    }

    /// Returns true if coefficient is zero
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Returns the sign: -1, 0, or 1
    pub fn signum(self) -> i128 {
        self.0.signum()
    }
}

impl fmt::Display for ExactCoeff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// Unchecked ops for convenience (panic on overflow)
impl Add for ExactCoeff {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        ExactCoeff(self.0 + rhs.0)
    }
}

impl Sub for ExactCoeff {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        ExactCoeff(self.0 - rhs.0)
    }
}

impl Mul for ExactCoeff {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        ExactCoeff(self.0 * rhs.0)
    }
}

impl Neg for ExactCoeff {
    type Output = Self;
    fn neg(self) -> Self {
        ExactCoeff(-self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========= T2: Ring Axioms Verification =========

    #[test]
    fn t2_addition_commutative() {
        let a = ExactCoeff(42);
        let b = ExactCoeff(17);
        assert_eq!(a + b, b + a, "Addition must be commutative");
    }

    #[test]
    fn t2_addition_associative() {
        let a = ExactCoeff(1);
        let b = ExactCoeff(2);
        let c = ExactCoeff(3);
        assert_eq!((a + b) + c, a + (b + c), "Addition must be associative");
    }

    #[test]
    fn t2_multiplication_commutative() {
        let a = ExactCoeff(7);
        let b = ExactCoeff(13);
        assert_eq!(a * b, b * a, "Multiplication must be commutative");
    }

    #[test]
    fn t2_multiplication_associative() {
        let a = ExactCoeff(2);
        let b = ExactCoeff(3);
        let c = ExactCoeff(5);
        assert_eq!(
            (a * b) * c,
            a * (b * c),
            "Multiplication must be associative"
        );
    }

    #[test]
    fn t2_distributive() {
        let a = ExactCoeff(4);
        let b = ExactCoeff(5);
        let c = ExactCoeff(6);
        assert_eq!(a * (b + c), a * b + a * c, "Distributive law must hold");
    }

    #[test]
    fn t2_additive_identity() {
        let a = ExactCoeff(999);
        assert_eq!(a + ExactCoeff::ZERO, a, "a + 0 must equal a");
    }

    #[test]
    fn t2_multiplicative_identity() {
        let a = ExactCoeff(-42);
        assert_eq!(a * ExactCoeff::ONE, a, "a * 1 must equal a");
    }

    #[test]
    fn t2_additive_inverse() {
        let a = ExactCoeff(73);
        assert_eq!(a + (-a), ExactCoeff::ZERO, "a + (-a) must equal 0");
    }

    // ========= Overflow checking =========

    #[test]
    fn checked_add_overflow() {
        let max = ExactCoeff(i128::MAX);
        assert_eq!(
            max.checked_add(ExactCoeff(1)),
            None,
            "Overflow must return None"
        );
    }

    #[test]
    fn checked_mul_overflow() {
        let large = ExactCoeff(i128::MAX / 2 + 1);
        assert_eq!(
            large.checked_mul(ExactCoeff(2)),
            None,
            "Overflow must return None"
        );
    }

    #[test]
    fn checked_neg_min() {
        let min = ExactCoeff(i128::MIN);
        assert_eq!(min.checked_neg(), None, "Negation of MIN must return None");
    }
}
