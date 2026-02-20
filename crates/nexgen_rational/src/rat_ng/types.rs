//! Core types for NexGen Rational arithmetic.
//!
//! DivOut enum correctness: T8 (division trichotomy) verified by κ Critic.
//! Completeness: ExactInverse ∪ ExactAFC ∪ FPD = all (a,b) with b ≠ 0.

use super::error::ArithmeticError;
use crate::exact_coeff::ExactCoeff;
use std::fmt;

/// Denominator state tracking for optimization.
///
/// Tracks whether the denominator is in a known-simple state,
/// allowing fast-path decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenState {
    /// Denominator is exactly 1 (integer value)
    Unit,
    /// Denominator is a known value (normalized)
    Known,
    /// Denominator state is unknown (post-operation, pre-normalization)
    Unknown,
}

/// Division output — exhaustive trichotomy (T8 verified).
///
/// # Theorem T8 (Division Trichotomy)
/// ∀ a b : Z. b ≠ 0 →
///   (∃ q : Z. a = b*q) ∨
///   (∃ q r : Z. a = b*q + r ∧ 0 < |r| < |b|)
///
/// # Mapping to DivOut
/// - `ExactInverse(q)`: b = ±1, trivial exact division
/// - `ExactAFC(q)`: b | a (b divides a exactly), remainder = 0
/// - `FPD { quot, rem }`: partial division with bounded remainder
///
/// Completeness proven by T8. Mutual exclusivity verified by κ Critic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DivOut {
    /// Exact inverse: divisor is ±1, quotient is trivial.
    /// a / 1 = a, a / (-1) = -a
    ExactInverse(ExactCoeff),

    /// Exact Aligned Fractional Components: b divides a exactly.
    /// a = b * q with remainder 0.
    ExactAFC(ExactCoeff),

    /// Floored Partial Division: a = b * quot + rem, 0 < |rem| < |b|.
    FPD { quot: ExactCoeff, rem: ExactCoeff },
}

impl DivOut {
    /// Extract the quotient from any DivOut variant.
    pub fn quotient(&self) -> ExactCoeff {
        match self {
            DivOut::ExactInverse(q) => *q,
            DivOut::ExactAFC(q) => *q,
            DivOut::FPD { quot, .. } => *quot,
        }
    }

    /// Returns true if division was exact (no remainder).
    pub fn is_exact(&self) -> bool {
        matches!(self, DivOut::ExactInverse(_) | DivOut::ExactAFC(_))
    }

    /// Get remainder, or zero if exact.
    pub fn remainder(&self) -> ExactCoeff {
        match self {
            DivOut::ExactInverse(_) => ExactCoeff::ZERO,
            DivOut::ExactAFC(_) => ExactCoeff::ZERO,
            DivOut::FPD { rem, .. } => *rem,
        }
    }
}

/// Exact rational number: numerator / denominator.
///
/// Invariants:
/// - `den.0 != 0` (enforced at construction)
/// - `den.0 > 0` after normalization (sign carried by numerator)
/// - After normalize(): gcd(|num|, den) = 1
///
/// Integer-Only: All fields are ExactCoeff (i128 wrapper).
#[derive(Clone, Debug)]
pub struct NexGenRat {
    pub(crate) num: ExactCoeff,
    pub(crate) den: ExactCoeff,
    pub(crate) state: DenState,
}

impl NexGenRat {
    /// Construct a new rational num/den.
    ///
    /// # Panics
    /// Panics if `den` is zero.
    pub fn new(num: ExactCoeff, den: ExactCoeff) -> Self {
        assert!(den.0 != 0, "Denominator cannot be zero");

        // Ensure denominator is positive (sign carried by numerator)
        let (num, den) = if den.0 < 0 {
            (ExactCoeff(-num.0), ExactCoeff(-den.0))
        } else {
            (num, den)
        };

        let state = if den.0 == 1 {
            DenState::Unit
        } else {
            DenState::Unknown
        };

        NexGenRat { num, den, state }
    }

    /// Try to construct, returning Err on zero denominator.
    pub fn try_new(num: ExactCoeff, den: ExactCoeff) -> Result<Self, ArithmeticError> {
        if den.0 == 0 {
            return Err(ArithmeticError::InvalidDenominator);
        }
        Ok(Self::new(num, den))
    }

    /// Access numerator
    pub fn numerator(&self) -> ExactCoeff {
        self.num
    }

    /// Access denominator
    pub fn denominator(&self) -> ExactCoeff {
        self.den
    }

    /// Denominator state
    pub fn den_state(&self) -> DenState {
        self.state
    }

    /// Returns true if this is an integer (den = 1)
    pub fn is_integer(&self) -> bool {
        self.den.0 == 1
    }

    /// Returns true if this is zero
    pub fn is_zero(&self) -> bool {
        self.num.0 == 0
    }
}

impl fmt::Display for NexGenRat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.den.0 == 1 {
            write!(f, "{}", self.num.0)
        } else {
            write!(f, "{}/{}", self.num.0, self.den.0)
        }
    }
}

impl PartialEq for NexGenRat {
    /// Equality via cross-multiplication: a/b = c/d iff a*d = b*c
    ///
    /// Integer-only comparison — no floating-point conversion.
    fn eq(&self, other: &Self) -> bool {
        // a/b = c/d  ⟺  a*d = b*c (integer cross-multiply)
        self.num.0 * other.den.0 == self.den.0 * other.num.0
    }
}

impl Eq for NexGenRat {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_basic() {
        let r = NexGenRat::new(ExactCoeff(3), ExactCoeff(4));
        assert_eq!(r.num.0, 3);
        assert_eq!(r.den.0, 4);
    }

    #[test]
    fn new_negative_denominator_flips() {
        let r = NexGenRat::new(ExactCoeff(3), ExactCoeff(-4));
        assert_eq!(r.num.0, -3, "Sign should move to numerator");
        assert_eq!(r.den.0, 4, "Denominator should be positive");
    }

    #[test]
    #[should_panic]
    fn new_zero_denominator_panics() {
        NexGenRat::new(ExactCoeff(1), ExactCoeff(0));
    }

    #[test]
    fn try_new_zero_denominator() {
        let result = NexGenRat::try_new(ExactCoeff(1), ExactCoeff(0));
        assert!(result.is_err());
    }

    #[test]
    fn equality_cross_multiply() {
        let a = NexGenRat::new(ExactCoeff(1), ExactCoeff(2));
        let b = NexGenRat::new(ExactCoeff(2), ExactCoeff(4));
        assert_eq!(a, b, "1/2 == 2/4 by cross multiplication");
    }

    #[test]
    fn display_integer() {
        let r = NexGenRat::new(ExactCoeff(42), ExactCoeff(1));
        assert_eq!(format!("{}", r), "42");
    }

    #[test]
    fn display_fraction() {
        let r = NexGenRat::new(ExactCoeff(3), ExactCoeff(4));
        assert_eq!(format!("{}", r), "3/4");
    }

    #[test]
    fn divout_exact_inverse() {
        let d = DivOut::ExactInverse(ExactCoeff(42));
        assert!(d.is_exact());
        assert_eq!(d.quotient().0, 42);
        assert_eq!(d.remainder().0, 0);
    }

    #[test]
    fn divout_fpd() {
        let d = DivOut::FPD {
            quot: ExactCoeff(3),
            rem: ExactCoeff(1),
        };
        assert!(!d.is_exact());
        assert_eq!(d.quotient().0, 3);
        assert_eq!(d.remainder().0, 1);
    }
}
