//! Arithmetic Operations for NexGenRat — I4 Overflow Protected
//!
//! ## Operations Implemented
//! - Addition: a/b + c/d = (a*d + b*c) / (b*d) [T3 pending proof]
//! - Subtraction: a/b - c/d = (a*d - b*c) / (b*d)
//! - Multiplication: a/b * c/d = (a*c) / (b*d) [T4 pending proof]
//! - Division: a/b ÷ c/d = (a*d) / (b*c) [T5 pending proof]
//! - Negation: -(a/b) = (-a)/b
//!
//! ## I4: Overflow Protection
//! All operations use checked arithmetic (checked_mul, checked_add, checked_sub).
//! Returns ArithmeticError::Overflow with full diagnostics on overflow.
//!
//! ## Adaptive Normalization (I3)
//! Post-operation, checks should_normalize() before applying GCD reduction.
//! Only normalizes when bit usage exceeds 80% of i128 capacity.
//!
//! ## Integer-Only Guarantee
//! Zero floating-point operations. All arithmetic is i128 checked.

use super::error::ArithmeticError;
use super::normalize::{normalize, should_normalize};
use super::types::NexGenRat;
use crate::exact_coeff::ExactCoeff;

// ============================================================================
// Helper: Finalize with adaptive normalization (I3 integration)
// ============================================================================

/// Construct a NexGenRat and conditionally normalize based on I3 threshold.
///
/// This is the central exit point for all arithmetic operations.
/// I3 integration: only normalizes when `should_normalize()` returns true.
fn finalize(num: ExactCoeff, den: ExactCoeff) -> Result<NexGenRat, ArithmeticError> {
    if den.0 == 0 {
        return Err(ArithmeticError::DivideByZero);
    }

    let mut result = NexGenRat::new(num, den);

    // I3: Adaptive normalization — only when bit usage exceeds threshold
    if should_normalize(&result) {
        normalize(&mut result)?;
    }

    Ok(result)
}

// ============================================================================
// Addition: a/b + c/d = (a*d + b*c) / (b*d)
// ============================================================================

/// Add two rationals with I4 overflow protection.
///
/// # Algorithm
/// a/b + c/d = (a*d + b*c) / (b*d)
///
/// # I4: Three checked multiplications, one checked addition.
/// Any overflow returns ArithmeticError::Overflow.
///
/// # T3 (pending): value(add(a/b, c/d)) = value(a/b) + value(c/d)
pub fn add(lhs: &NexGenRat, rhs: &NexGenRat) -> Result<NexGenRat, ArithmeticError> {
    // a*d (checked)
    let ad = lhs
        .num
        .0
        .checked_mul(rhs.den.0)
        .ok_or(ArithmeticError::Overflow {
            operation: "add: a*d",
            left: lhs.num.0,
            right: rhs.den.0,
        })?;

    // b*c (checked)
    let bc = lhs
        .den
        .0
        .checked_mul(rhs.num.0)
        .ok_or(ArithmeticError::Overflow {
            operation: "add: b*c",
            left: lhs.den.0,
            right: rhs.num.0,
        })?;

    // a*d + b*c (checked)
    let num = ad.checked_add(bc).ok_or(ArithmeticError::Overflow {
        operation: "add: ad+bc",
        left: ad,
        right: bc,
    })?;

    // b*d (checked)
    let den = lhs
        .den
        .0
        .checked_mul(rhs.den.0)
        .ok_or(ArithmeticError::Overflow {
            operation: "add: b*d",
            left: lhs.den.0,
            right: rhs.den.0,
        })?;

    finalize(ExactCoeff(num), ExactCoeff(den))
}

// ============================================================================
// Subtraction: a/b - c/d = (a*d - b*c) / (b*d)
// ============================================================================

/// Subtract two rationals with I4 overflow protection.
pub fn sub(lhs: &NexGenRat, rhs: &NexGenRat) -> Result<NexGenRat, ArithmeticError> {
    let ad = lhs
        .num
        .0
        .checked_mul(rhs.den.0)
        .ok_or(ArithmeticError::Overflow {
            operation: "sub: a*d",
            left: lhs.num.0,
            right: rhs.den.0,
        })?;

    let bc = lhs
        .den
        .0
        .checked_mul(rhs.num.0)
        .ok_or(ArithmeticError::Overflow {
            operation: "sub: b*c",
            left: lhs.den.0,
            right: rhs.num.0,
        })?;

    let num = ad.checked_sub(bc).ok_or(ArithmeticError::Overflow {
        operation: "sub: ad-bc",
        left: ad,
        right: bc,
    })?;

    let den = lhs
        .den
        .0
        .checked_mul(rhs.den.0)
        .ok_or(ArithmeticError::Overflow {
            operation: "sub: b*d",
            left: lhs.den.0,
            right: rhs.den.0,
        })?;

    finalize(ExactCoeff(num), ExactCoeff(den))
}

// ============================================================================
// Multiplication: a/b * c/d = (a*c) / (b*d)
// ============================================================================

/// Multiply two rationals with I4 overflow protection.
///
/// # T4 (pending): value(mul(a/b, c/d)) = value(a/b) * value(c/d)
pub fn mul(lhs: &NexGenRat, rhs: &NexGenRat) -> Result<NexGenRat, ArithmeticError> {
    let num = lhs
        .num
        .0
        .checked_mul(rhs.num.0)
        .ok_or(ArithmeticError::Overflow {
            operation: "mul: a*c",
            left: lhs.num.0,
            right: rhs.num.0,
        })?;

    let den = lhs
        .den
        .0
        .checked_mul(rhs.den.0)
        .ok_or(ArithmeticError::Overflow {
            operation: "mul: b*d",
            left: lhs.den.0,
            right: rhs.den.0,
        })?;

    finalize(ExactCoeff(num), ExactCoeff(den))
}

// ============================================================================
// Division: a/b ÷ c/d = (a*d) / (b*c)
// ============================================================================

/// Divide two rationals with I4 overflow protection.
///
/// # T5 (pending): value(div(a/b, c/d)) = value(a/b) / value(c/d)
///
/// # Error
/// Returns DivideByZero if c = 0 (dividing by zero rational).
pub fn div(lhs: &NexGenRat, rhs: &NexGenRat) -> Result<NexGenRat, ArithmeticError> {
    if rhs.num.0 == 0 {
        return Err(ArithmeticError::DivideByZero);
    }

    let num = lhs
        .num
        .0
        .checked_mul(rhs.den.0)
        .ok_or(ArithmeticError::Overflow {
            operation: "div: a*d",
            left: lhs.num.0,
            right: rhs.den.0,
        })?;

    let den = lhs
        .den
        .0
        .checked_mul(rhs.num.0)
        .ok_or(ArithmeticError::Overflow {
            operation: "div: b*c",
            left: lhs.den.0,
            right: rhs.num.0,
        })?;

    finalize(ExactCoeff(num), ExactCoeff(den))
}

// ============================================================================
// Negation
// ============================================================================

/// Negate a rational: -(a/b) = (-a)/b
pub fn neg(rat: &NexGenRat) -> Result<NexGenRat, ArithmeticError> {
    let num = rat.num.0.checked_neg().ok_or(ArithmeticError::Overflow {
        operation: "neg",
        left: rat.num.0,
        right: 0,
    })?;

    Ok(NexGenRat {
        num: ExactCoeff(num),
        den: rat.den,
        state: rat.state,
    })
}

// ============================================================================
// Operator trait implementations
// ============================================================================

impl std::ops::Add<&NexGenRat> for &NexGenRat {
    type Output = Result<NexGenRat, ArithmeticError>;
    fn add(self, rhs: &NexGenRat) -> Self::Output {
        add(self, rhs)
    }
}

impl std::ops::Sub<&NexGenRat> for &NexGenRat {
    type Output = Result<NexGenRat, ArithmeticError>;
    fn sub(self, rhs: &NexGenRat) -> Self::Output {
        sub(self, rhs)
    }
}

impl std::ops::Mul<&NexGenRat> for &NexGenRat {
    type Output = Result<NexGenRat, ArithmeticError>;
    fn mul(self, rhs: &NexGenRat) -> Self::Output {
        mul(self, rhs)
    }
}

impl std::ops::Div<&NexGenRat> for &NexGenRat {
    type Output = Result<NexGenRat, ArithmeticError>;
    fn div(self, rhs: &NexGenRat) -> Self::Output {
        div(self, rhs)
    }
}

impl std::ops::Neg for &NexGenRat {
    type Output = Result<NexGenRat, ArithmeticError>;
    fn neg(self) -> Self::Output {
        neg(self)
    }
}

// ============================================================================
// Public normalize access on NexGenRat
// ============================================================================

impl NexGenRat {
    /// Normalize this rational in-place (GCD reduction).
    pub fn normalize(&mut self) -> Result<(), ArithmeticError> {
        normalize(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rat(n: i128, d: i128) -> NexGenRat {
        NexGenRat::new(ExactCoeff(n), ExactCoeff(d))
    }

    // ========= Addition Tests =========

    #[test]
    fn add_basic() {
        let a = rat(1, 2); // 1/2
        let b = rat(1, 3); // 1/3
        let result = (&a + &b).unwrap();
        // 1/2 + 1/3 = 5/6
        assert_eq!(result, rat(5, 6));
    }

    #[test]
    fn add_same_denominator() {
        let a = rat(1, 4);
        let b = rat(2, 4);
        let result = (&a + &b).unwrap();
        // 1/4 + 2/4 = 3/4 (or 12/16 normalized to 3/4 if threshold hit)
        assert_eq!(result, rat(3, 4));
    }

    #[test]
    fn add_negative() {
        let a = rat(1, 2);
        let b = rat(-1, 3);
        let result = (&a + &b).unwrap();
        // 1/2 + (-1/3) = 1/6
        assert_eq!(result, rat(1, 6));
    }

    #[test]
    fn add_to_zero() {
        let a = rat(1, 2);
        let b = rat(-1, 2);
        let result = (&a + &b).unwrap();
        assert!(result.is_zero(), "1/2 + (-1/2) = 0");
    }

    #[test]
    fn add_zero_identity() {
        let a = rat(3, 7);
        let zero = rat(0, 1);
        let result = (&a + &zero).unwrap();
        assert_eq!(result, a, "a + 0 = a");
    }

    // ========= Subtraction Tests =========

    #[test]
    fn sub_basic() {
        let a = rat(3, 4);
        let b = rat(1, 2);
        let result = (&a - &b).unwrap();
        // 3/4 - 1/2 = 1/4
        assert_eq!(result, rat(1, 4));
    }

    #[test]
    fn sub_self_is_zero() {
        let a = rat(42, 13);
        let result = (&a - &a).unwrap();
        assert!(result.is_zero(), "a - a = 0");
    }

    // ========= Multiplication Tests =========

    #[test]
    fn mul_basic() {
        let a = rat(3, 4);
        let b = rat(2, 5);
        let result = (&a * &b).unwrap();
        // 3/4 * 2/5 = 6/20 = 3/10
        assert_eq!(result, rat(3, 10));
    }

    #[test]
    fn mul_by_zero() {
        let a = rat(42, 13);
        let zero = rat(0, 1);
        let result = (&a * &zero).unwrap();
        assert!(result.is_zero(), "a * 0 = 0");
    }

    #[test]
    fn mul_by_one() {
        let a = rat(3, 7);
        let one = rat(1, 1);
        let result = (&a * &one).unwrap();
        assert_eq!(result, a, "a * 1 = a");
    }

    // ========= Division Tests =========

    #[test]
    fn div_basic() {
        let a = rat(3, 4);
        let b = rat(1, 2);
        let result = (&a / &b).unwrap();
        // (3/4) / (1/2) = 3/4 * 2/1 = 6/4 = 3/2
        assert_eq!(result, rat(3, 2));
    }

    #[test]
    fn div_by_zero_error() {
        let a = rat(3, 4);
        let zero = rat(0, 1);
        let result = &a / &zero;
        assert!(result.is_err(), "Division by zero rational must error");
    }

    #[test]
    fn div_self_is_one() {
        let a = rat(42, 13);
        let result = (&a / &a).unwrap();
        assert_eq!(result, rat(1, 1), "a / a = 1");
    }

    // ========= Negation Tests =========

    #[test]
    fn neg_basic() {
        let a = rat(3, 4);
        let result = (-&a).unwrap();
        assert_eq!(result, rat(-3, 4));
    }

    #[test]
    fn neg_double_is_identity() {
        let a = rat(3, 4);
        let neg1 = (-&a).unwrap();
        let neg2 = (-&neg1).unwrap();
        assert_eq!(neg2, a, "--a = a");
    }

    // ========= I4: Overflow Protection Tests =========

    #[test]
    fn i4_add_overflow_detected() {
        let large = rat(i128::MAX / 2 + 1, 1);
        let result = &large + &large;
        // The cross-multiply: (MAX/2+1)*1 + 1*(MAX/2+1) should overflow
        // Actually, the numerator cross-mul is fine, but the addition overflows
        assert!(
            result.is_err(),
            "Adding two large rationals must detect overflow"
        );
    }

    #[test]
    fn i4_mul_overflow_detected() {
        let large = rat(i128::MAX / 2, 1);
        let two = rat(3, 1);
        let result = &large * &two;
        assert!(
            result.is_err(),
            "Multiplying near-max values must detect overflow"
        );
    }

    #[test]
    fn i4_safe_large_operations() {
        // Operations within safe range should succeed
        let a = rat(1_000_000, 1);
        let b = rat(999_999, 1);
        let result = (&a + &b).unwrap();
        assert_eq!(result, rat(1_999_999, 1));
    }

    // ========= Algebraic Properties =========

    #[test]
    fn addition_commutative() {
        let a = rat(3, 7);
        let b = rat(5, 11);
        let ab = (&a + &b).unwrap();
        let ba = (&b + &a).unwrap();
        assert_eq!(ab, ba, "a + b must equal b + a");
    }

    #[test]
    fn multiplication_commutative() {
        let a = rat(3, 7);
        let b = rat(5, 11);
        let ab = (&a * &b).unwrap();
        let ba = (&b * &a).unwrap();
        assert_eq!(ab, ba, "a * b must equal b * a");
    }

    #[test]
    fn addition_associative() {
        let a = rat(1, 2);
        let b = rat(1, 3);
        let c = rat(1, 5);
        let ab_c = (&(&a + &b).unwrap() + &c).unwrap();
        let a_bc = (&a + &(&b + &c).unwrap()).unwrap();
        assert_eq!(ab_c, a_bc, "(a+b)+c must equal a+(b+c)");
    }

    #[test]
    fn multiplication_associative() {
        let a = rat(2, 3);
        let b = rat(3, 5);
        let c = rat(5, 7);
        let ab_c = (&(&a * &b).unwrap() * &c).unwrap();
        let a_bc = (&a * &(&b * &c).unwrap()).unwrap();
        assert_eq!(ab_c, a_bc, "(a*b)*c must equal a*(b*c)");
    }

    #[test]
    fn distributive_law() {
        let a = rat(2, 3);
        let b = rat(1, 4);
        let c = rat(3, 5);

        // a * (b + c)
        let bc = (&b + &c).unwrap();
        let lhs = (&a * &bc).unwrap();

        // a*b + a*c
        let ab = (&a * &b).unwrap();
        let ac = (&a * &c).unwrap();
        let rhs = (&ab + &ac).unwrap();

        assert_eq!(lhs, rhs, "a*(b+c) must equal a*b + a*c");
    }

    // ========= I3 Integration: Adaptive Normalization =========

    #[test]
    fn i3_small_operations_skip_normalization() {
        // Small operations should NOT trigger normalization
        // (bit usage stays well below 80% of 127)
        let a = rat(3, 7);
        let b = rat(5, 11);
        let result = (&a + &b).unwrap();
        // 3/7 + 5/11 = (33 + 35) / 77 = 68/77
        // Bit usage: max(7, 7) = 7 bits, well below 102-bit threshold
        // So normalization should NOT have been triggered
        assert_eq!(result.num.0, 68);
        assert_eq!(result.den.0, 77);
    }
}
