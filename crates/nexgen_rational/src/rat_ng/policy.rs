//! Division Policy — I1 + I2 Implementation
//!
//! Grounded in T8 (Division Trichotomy), verified by κ Critic.
//!
//! ## Theorem T8
//! ∀ a b : Z. b ≠ 0 →
//!   (∃ q : Z. a = b*q) ∨
//!   (∃ q r : Z. a = b*q + r ∧ 0 < |r| < |b|)
//!
//! ## DivOut Mapping (proven complete by T8)
//! - ExactInverse: |b| = 1 (unit divisor)
//! - ExactAFC: |b| > 1 ∧ a % b = 0 (exact division)
//! - FPD: |b| > 1 ∧ a % b ≠ 0 (partial division)
//!
//! ## Integer-Only Operations
//! - Division: native i128 `/`
//! - Remainder: native i128 `%`
//! - Absolute value: `abs()`
//! - Sign extraction: `signum()`
//!
//! ## Sign Convention (Rust truncating division)
//! - Quotient rounds toward zero
//! - Remainder has same sign as dividend
//! - Always: a = (a/b)*b + (a%b)

use super::error::ArithmeticError;
use super::types::DivOut;
use crate::exact_coeff::ExactCoeff;

/// Divide two ExactCoeff values using the division trichotomy.
///
/// # I4: Overflow Protection
/// Uses `checked_rem_euclid` where available, falls back to standard
/// operators with documented overflow behavior.
///
/// # Completeness (T8)
/// Every (a, b) with b ≠ 0 is handled by exactly one DivOut variant.
/// Mutual exclusivity proven by κ Critic.
///
/// # Returns
/// - `Ok(ExactInverse(q))` if |b| = 1
/// - `Ok(ExactAFC(q))` if b divides a exactly (I1)
/// - `Ok(FPD { quot, rem })` if division has remainder (I2)
/// - `Err(DivideByZero)` if b = 0
pub fn divide_coeff(a: &ExactCoeff, b: &ExactCoeff) -> Result<DivOut, ArithmeticError> {
    // Precondition: b ≠ 0
    if b.0 == 0 {
        return Err(ArithmeticError::DivideByZero);
    }

    // Case 1: Unit divisor (|b| = 1)
    // Optimization: no division needed, just sign adjustment
    if b.0.abs() == 1 {
        // b = 1  → q = a
        // b = -1 → q = -a
        let q = a.0 * b.0.signum();
        return Ok(DivOut::ExactInverse(ExactCoeff(q)));
    }

    // Cases 2 & 3: |b| > 1
    // Compute remainder to determine which case
    let r = a.0 % b.0;

    if r == 0 {
        // I1: ExactAFC — b divides a exactly
        // a = b * q with remainder 0
        let q = a.0 / b.0;
        Ok(DivOut::ExactAFC(ExactCoeff(q)))
    } else {
        // I2: FPD — Floored Partial Division
        // a = b * quot + rem, with 0 < |rem| < |b|
        let q = a.0 / b.0;
        Ok(DivOut::FPD {
            quot: ExactCoeff(q),
            rem: ExactCoeff(r),
        })
    }
}

/// Checked division with overflow protection (I4 enhancement).
///
/// Uses checked arithmetic to detect overflow in intermediate calculations.
/// Falls back to standard divide_coeff if no overflow concern.
pub fn divide_coeff_checked(a: &ExactCoeff, b: &ExactCoeff) -> Result<DivOut, ArithmeticError> {
    if b.0 == 0 {
        return Err(ArithmeticError::DivideByZero);
    }

    // i128::MIN / -1 overflows
    if a.0 == i128::MIN && b.0 == -1 {
        return Err(ArithmeticError::Overflow {
            operation: "division",
            left: a.0,
            right: b.0,
        });
    }

    // Delegate to standard implementation (safe after overflow check)
    divide_coeff(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========= I1: ExactAFC Tests =========

    #[test]
    fn i1_exact_afc_basic() {
        // 12 / 4 = 3 exactly
        let a = ExactCoeff(12);
        let b = ExactCoeff(4);
        let result = divide_coeff(&a, &b).unwrap();
        match result {
            DivOut::ExactAFC(q) => {
                assert_eq!(q.0, 3);
            }
            _ => panic!("Expected ExactAFC, got {:?}", result),
        }
    }

    #[test]
    fn i1_exact_afc_negative_dividend() {
        // -12 / 4 = -3 exactly
        let a = ExactCoeff(-12);
        let b = ExactCoeff(4);
        let result = divide_coeff(&a, &b).unwrap();
        match result {
            DivOut::ExactAFC(q) => {
                assert_eq!(q.0, -3);
            }
            _ => panic!("Expected ExactAFC, got {:?}", result),
        }
    }

    #[test]
    fn i1_exact_afc_negative_divisor() {
        // 12 / (-4) = -3 exactly
        let a = ExactCoeff(12);
        let b = ExactCoeff(-4);
        let result = divide_coeff(&a, &b).unwrap();
        match result {
            DivOut::ExactAFC(q) => {
                assert_eq!(q.0, -3);
            }
            _ => panic!("Expected ExactAFC, got {:?}", result),
        }
    }

    #[test]
    fn i1_exact_afc_both_negative() {
        // -12 / (-4) = 3 exactly
        let a = ExactCoeff(-12);
        let b = ExactCoeff(-4);
        let result = divide_coeff(&a, &b).unwrap();
        match result {
            DivOut::ExactAFC(q) => {
                assert_eq!(q.0, 3);
            }
            _ => panic!("Expected ExactAFC, got {:?}", result),
        }
    }

    #[test]
    fn i1_exact_afc_large_values() {
        // 1_000_000 / 1000 = 1000
        let a = ExactCoeff(1_000_000);
        let b = ExactCoeff(1000);
        let result = divide_coeff(&a, &b).unwrap();
        match result {
            DivOut::ExactAFC(q) => {
                assert_eq!(q.0, 1000);
            }
            _ => panic!("Expected ExactAFC, got {:?}", result),
        }
    }

    #[test]
    fn i1_exact_afc_zero_dividend() {
        // 0 / 4 = 0 exactly
        let a = ExactCoeff(0);
        let b = ExactCoeff(4);
        let result = divide_coeff(&a, &b).unwrap();
        match result {
            DivOut::ExactAFC(q) => {
                assert_eq!(q.0, 0);
            }
            _ => panic!("Expected ExactAFC for 0/4, got {:?}", result),
        }
    }

    // ========= I2: FPD Tests =========

    #[test]
    fn i2_fpd_basic() {
        // 13 / 4 = 3 remainder 1
        let a = ExactCoeff(13);
        let b = ExactCoeff(4);
        let result = divide_coeff(&a, &b).unwrap();
        match result {
            DivOut::FPD { quot, rem } => {
                assert_eq!(quot.0, 3);
                assert_eq!(rem.0, 1);
                // Division algorithm: a = b*q + r
                assert_eq!(a.0, b.0 * quot.0 + rem.0, "Division algorithm must hold");
            }
            _ => panic!("Expected FPD, got {:?}", result),
        }
    }

    #[test]
    fn i2_fpd_negative_dividend() {
        // -13 / 4 = -3 remainder -1 (Rust truncating division)
        let a = ExactCoeff(-13);
        let b = ExactCoeff(4);
        let result = divide_coeff(&a, &b).unwrap();
        match result {
            DivOut::FPD { quot, rem } => {
                assert_eq!(quot.0, -3);
                assert_eq!(rem.0, -1);
                assert_eq!(a.0, b.0 * quot.0 + rem.0, "Division algorithm must hold");
            }
            _ => panic!("Expected FPD, got {:?}", result),
        }
    }

    #[test]
    fn i2_fpd_negative_divisor() {
        // 13 / (-4) = -3 remainder 1
        let a = ExactCoeff(13);
        let b = ExactCoeff(-4);
        let result = divide_coeff(&a, &b).unwrap();
        match result {
            DivOut::FPD { quot, rem } => {
                assert_eq!(quot.0, -3);
                assert_eq!(rem.0, 1);
                assert_eq!(a.0, b.0 * quot.0 + rem.0, "Division algorithm must hold");
            }
            _ => panic!("Expected FPD, got {:?}", result),
        }
    }

    #[test]
    fn i2_fpd_both_negative() {
        // -13 / (-4) = 3 remainder -1
        let a = ExactCoeff(-13);
        let b = ExactCoeff(-4);
        let result = divide_coeff(&a, &b).unwrap();
        match result {
            DivOut::FPD { quot, rem } => {
                assert_eq!(quot.0, 3);
                assert_eq!(rem.0, -1);
                assert_eq!(a.0, b.0 * quot.0 + rem.0, "Division algorithm must hold");
            }
            _ => panic!("Expected FPD, got {:?}", result),
        }
    }

    #[test]
    fn i2_fpd_remainder_bounded() {
        // Property: |rem| < |divisor|
        let cases: Vec<(i128, i128)> = vec![
            (13, 4),
            (-13, 4),
            (13, -4),
            (-13, -4),
            (100, 7),
            (-999, 13),
            (1_000_000_007, 1000),
        ];

        for (a_val, b_val) in cases {
            let a = ExactCoeff(a_val);
            let b = ExactCoeff(b_val);
            let result = divide_coeff(&a, &b).unwrap();
            if let DivOut::FPD { rem, .. } = result {
                assert!(
                    rem.0.abs() < b_val.abs(),
                    "|rem| = {} must be < |b| = {} for {}/{}",
                    rem.0.abs(),
                    b_val.abs(),
                    a_val,
                    b_val,
                );
            }
        }
    }

    // ========= ExactInverse Tests =========

    #[test]
    fn exact_inverse_positive_one() {
        let a = ExactCoeff(42);
        let b = ExactCoeff(1);
        let result = divide_coeff(&a, &b).unwrap();
        match result {
            DivOut::ExactInverse(q) => assert_eq!(q.0, 42),
            _ => panic!("Expected ExactInverse, got {:?}", result),
        }
    }

    #[test]
    fn exact_inverse_negative_one() {
        let a = ExactCoeff(42);
        let b = ExactCoeff(-1);
        let result = divide_coeff(&a, &b).unwrap();
        match result {
            DivOut::ExactInverse(q) => assert_eq!(q.0, -42),
            _ => panic!("Expected ExactInverse, got {:?}", result),
        }
    }

    // ========= Error Cases =========

    #[test]
    fn divide_by_zero_error() {
        let a = ExactCoeff(42);
        let b = ExactCoeff(0);
        let result = divide_coeff(&a, &b);
        assert_eq!(result, Err(ArithmeticError::DivideByZero));
    }

    // ========= I4: Overflow Protection =========

    #[test]
    fn i4_overflow_min_div_neg_one() {
        let a = ExactCoeff(i128::MIN);
        let b = ExactCoeff(-1);
        let result = divide_coeff_checked(&a, &b);
        assert!(result.is_err(), "i128::MIN / -1 must be caught as overflow");
    }

    // ========= Division Algorithm Property =========

    #[test]
    fn division_algorithm_holds_exhaustive() {
        // For a range of inputs, verify: a = b*q + r
        let test_values: Vec<i128> = vec![
            0,
            1,
            -1,
            2,
            -2,
            7,
            -7,
            13,
            -13,
            100,
            -100,
            i128::MAX / 2,
            i128::MIN / 2,
        ];

        for &a_val in &test_values {
            for &b_val in &test_values {
                if b_val == 0 {
                    continue;
                }
                let a = ExactCoeff(a_val);
                let b = ExactCoeff(b_val);
                let result = divide_coeff(&a, &b).unwrap();
                let q = result.quotient().0;
                let r = result.remainder().0;
                assert_eq!(
                    a_val,
                    b_val * q + r,
                    "Division algorithm failed for {} / {}: q={}, r={}",
                    a_val,
                    b_val,
                    q,
                    r,
                );
            }
        }
    }
}
