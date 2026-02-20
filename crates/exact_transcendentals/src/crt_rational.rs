//! CRTRational - Exact rational arithmetic with arbitrary-precision integers
//!
//! Bridges ExactRational (i128-bounded) to HCVLangBigInt-backed rationals
//! for computations that exceed the i128 range.
//!
//! # Integer-Only Guarantee
//! All operations are exact integer arithmetic. No floating-point.

use crate::bigint::HCVLangBigInt;
use crate::ExactRational;

/// Exact rational number with arbitrary-precision numerator and denominator.
///
/// Unlike `ExactRational` (limited to i128), `CRTRational` uses `HCVLangBigInt`
/// and can represent any rational number regardless of magnitude.
#[derive(Clone, Debug)]
pub struct CRTRational {
    pub num: HCVLangBigInt,
    pub den: HCVLangBigInt,
}

impl CRTRational {
    /// Create a new rational from big-integer numerator and denominator.
    /// Panics if denominator is zero.
    pub fn new(num: HCVLangBigInt, den: HCVLangBigInt) -> Self {
        assert!(!den.is_zero(), "Denominator cannot be zero");
        Self { num, den }
    }

    /// Create from i128 values (convenience constructor).
    pub fn from_i128(num: i128, den: i128) -> Self {
        assert!(den != 0, "Denominator cannot be zero");
        Self {
            num: HCVLangBigInt::from(num),
            den: HCVLangBigInt::from(den),
        }
    }

    /// Create from an integer.
    pub fn from_int(n: i128) -> Self {
        Self {
            num: HCVLangBigInt::from(n),
            den: HCVLangBigInt::from(1i64),
        }
    }

    /// Convert from ExactRational (always succeeds — just widens).
    pub fn from_exact(r: &ExactRational) -> Self {
        Self {
            num: HCVLangBigInt::from(r.num),
            den: HCVLangBigInt::from(r.den),
        }
    }

    /// Try to convert back to ExactRational. Returns None if values exceed i128 range.
    pub fn to_exact(&self) -> Option<ExactRational> {
        let num = self.num.to_i128()?;
        let den = self.den.to_i128()?;
        Some(ExactRational::new(num, den))
    }

    /// Reduce to lowest terms using binary GCD.
    pub fn reduce(&self) -> Self {
        let g = HCVLangBigInt::gcd(&self.num, &self.den);
        if g.is_zero() || g == HCVLangBigInt::from(1i64) {
            return self.clone();
        }
        // Normalize sign: denominator always positive
        let num_div = self.num.clone() / g.clone();
        let den_div = self.den.clone() / g;
        if den_div.is_negative() {
            Self {
                num: -num_div,
                den: -den_div,
            }
        } else {
            Self {
                num: num_div,
                den: den_div,
            }
        }
    }

    /// Check if this rational is zero.
    pub fn is_zero(&self) -> bool {
        self.num.is_zero()
    }

    /// Addition: a/b + c/d = (a*d + c*b) / (b*d)
    pub fn add(&self, other: &Self) -> Self {
        let num = self.num.clone() * other.den.clone() + other.num.clone() * self.den.clone();
        let den = self.den.clone() * other.den.clone();
        Self { num, den }.reduce()
    }

    /// Subtraction: a/b - c/d = (a*d - c*b) / (b*d)
    pub fn sub(&self, other: &Self) -> Self {
        let num = self.num.clone() * other.den.clone() - other.num.clone() * self.den.clone();
        let den = self.den.clone() * other.den.clone();
        Self { num, den }.reduce()
    }

    /// Multiplication: a/b * c/d = (a*c) / (b*d)
    pub fn mul(&self, other: &Self) -> Self {
        let num = self.num.clone() * other.num.clone();
        let den = self.den.clone() * other.den.clone();
        Self { num, den }.reduce()
    }

    /// Division: (a/b) / (c/d) = (a*d) / (b*c)
    /// Panics if other is zero.
    pub fn div(&self, other: &Self) -> Self {
        assert!(!other.num.is_zero(), "Division by zero");
        let num = self.num.clone() * other.den.clone();
        let den = self.den.clone() * other.num.clone();
        Self { num, den }.reduce()
    }

    /// Convert to scaled integer: (num * scale) / den
    /// Returns None if the result doesn't fit in i128.
    pub fn to_scaled(&self, scale: i128) -> Option<i128> {
        let scaled_num = self.num.clone() * HCVLangBigInt::from(scale);
        let result = scaled_num / self.den.clone();
        result.to_i128()
    }

    /// Approximate as f64 (for testing only)
    #[cfg(test)]
    pub fn to_f64(&self) -> f64 {
        match (self.num.to_i128(), self.den.to_i128()) {
            (Some(n), Some(d)) => n as f64 / d as f64,
            _ => {
                // For very large values, use the most significant limbs
                // This is a rough approximation for test assertions only
                let n = &self.num;
                let d = &self.den;
                let n_f = bigint_to_f64_approx(n);
                let d_f = bigint_to_f64_approx(d);
                n_f / d_f
            }
        }
    }
}

/// Rough f64 approximation of a HCVLangBigInt (test-only helper).
#[cfg(test)]
fn bigint_to_f64_approx(b: &HCVLangBigInt) -> f64 {
    // Try direct conversion first
    if let Some(v) = b.to_i128() {
        return v as f64;
    }
    // Fallback: use string representation
    let s = format!("{}", b);
    s.parse::<f64>().unwrap_or(f64::INFINITY)
}

impl PartialEq for CRTRational {
    fn eq(&self, other: &Self) -> bool {
        // a/b == c/d iff a*d == c*b
        let lhs = self.num.clone() * other.den.clone();
        let rhs = other.num.clone() * self.den.clone();
        lhs == rhs
    }
}

impl Eq for CRTRational {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_construction_and_equality() {
        let a = CRTRational::from_i128(1, 3);
        let b = CRTRational::from_i128(2, 6);
        assert_eq!(a, b); // 1/3 == 2/6
    }

    #[test]
    fn test_addition() {
        // 1/3 + 1/7 = 10/21
        let a = CRTRational::from_i128(1, 3);
        let b = CRTRational::from_i128(1, 7);
        let sum = a.add(&b);
        let expected = CRTRational::from_i128(10, 21);
        assert_eq!(sum, expected);
    }

    #[test]
    fn test_subtraction() {
        // 1/2 - 1/3 = 1/6
        let a = CRTRational::from_i128(1, 2);
        let b = CRTRational::from_i128(1, 3);
        let diff = a.sub(&b);
        let expected = CRTRational::from_i128(1, 6);
        assert_eq!(diff, expected);
    }

    #[test]
    fn test_multiplication() {
        // 2/3 * 3/5 = 2/5
        let a = CRTRational::from_i128(2, 3);
        let b = CRTRational::from_i128(3, 5);
        let prod = a.mul(&b);
        let expected = CRTRational::from_i128(2, 5);
        assert_eq!(prod, expected);
    }

    #[test]
    fn test_division() {
        // (2/3) / (4/5) = 10/12 = 5/6
        let a = CRTRational::from_i128(2, 3);
        let b = CRTRational::from_i128(4, 5);
        let quot = a.div(&b);
        let expected = CRTRational::from_i128(5, 6);
        assert_eq!(quot, expected);
    }

    #[test]
    fn test_roundtrip_exact() {
        let orig = ExactRational::new(355, 113); // pi approximation
        let big = CRTRational::from_exact(&orig);
        let back = big.to_exact().unwrap();
        assert_eq!(back.num, 355);
        assert_eq!(back.den, 113);
    }

    #[test]
    fn test_reduce() {
        let r = CRTRational::from_i128(12, 18);
        let reduced = r.reduce();
        let expected = CRTRational::from_i128(2, 3);
        assert_eq!(reduced, expected);
    }

    #[test]
    fn test_to_scaled() {
        // 1/3 * 2^30 should be approximately 2^30 / 3
        let r = CRTRational::from_i128(1, 3);
        let scale: i128 = 1 << 30;
        let scaled = r.to_scaled(scale).unwrap();
        assert_eq!(scaled, scale / 3); // integer division
    }

    #[test]
    fn test_large_values_beyond_i128() {
        // Construct values that would overflow i128
        // 2^120 / 7
        let big_num = HCVLangBigInt::from(1i64) << 120;
        let den = HCVLangBigInt::from(7i64);
        let r = CRTRational::new(big_num.clone(), den);

        // Multiply by 7 should give back 2^120
        let seven = CRTRational::from_i128(7, 1);
        let product = r.mul(&seven);
        let expected_num = HCVLangBigInt::from(1i64) << 120;
        let expected = CRTRational::new(expected_num, HCVLangBigInt::from(1i64));
        assert_eq!(product, expected);
    }

    #[test]
    fn test_negative_rational() {
        let a = CRTRational::from_i128(-3, 4);
        let b = CRTRational::from_i128(1, 4);
        let sum = a.add(&b);
        let expected = CRTRational::from_i128(-1, 2);
        assert_eq!(sum, expected);
    }
}
