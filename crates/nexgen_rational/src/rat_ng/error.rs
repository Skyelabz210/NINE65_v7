//! Arithmetic error types for NexGen Rational.
//!
//! I4: Enhanced error type with overflow reporting.
//! All errors are deterministic and carry diagnostic info.

use std::fmt;

/// Arithmetic error variants.
///
/// Integer-Only Design: Error reporting uses integer values only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArithmeticError {
    /// Division by zero (denominator = 0)
    DivideByZero,

    /// Integer overflow during arithmetic operation.
    ///
    /// Reports the operation name and both operands for diagnosis.
    /// I4: Checked arithmetic catches all overflow before corruption.
    Overflow {
        operation: &'static str,
        left: i128,
        right: i128,
    },

    /// Functionality not yet implemented
    Unimplemented,

    /// Denominator was zero in rational construction
    InvalidDenominator,
}

impl fmt::Display for ArithmeticError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArithmeticError::DivideByZero => {
                write!(f, "Division by zero")
            }
            ArithmeticError::Overflow {
                operation,
                left,
                right,
            } => {
                write!(
                    f,
                    "Integer overflow in {}: operands ({}, {})",
                    operation, left, right
                )
            }
            ArithmeticError::Unimplemented => {
                write!(f, "Operation not yet implemented")
            }
            ArithmeticError::InvalidDenominator => {
                write!(f, "Denominator cannot be zero")
            }
        }
    }
}

impl std::error::Error for ArithmeticError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_overflow() {
        let e = ArithmeticError::Overflow {
            operation: "checked_mul",
            left: i128::MAX,
            right: 2,
        };
        let msg = format!("{}", e);
        assert!(msg.contains("checked_mul"));
        assert!(msg.contains("overflow"));
    }

    #[test]
    fn error_display_divide_by_zero() {
        let e = ArithmeticError::DivideByZero;
        assert_eq!(format!("{}", e), "Division by zero");
    }
}
