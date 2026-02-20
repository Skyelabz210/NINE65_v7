//! CRTBigInt - Chinese Remainder Theorem based integers
//!
//! High-performance bounded integers using CRT representation for
//! parallel computation with safe reconstruction.
//!
//! # Integer-Only Guarantee
//! All operations use exact integer arithmetic. No floating-point.

#[cfg(not(feature = "std"))]
use alloc::vec;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

use core::cmp::Ordering;
use core::fmt;
use core::ops::{Add, Div, Mul, Neg, Rem, Sub};

use crate::bigint::HCVLangBigInt;

/// Default moduli - Fibonacci numbers at prime indices (pairwise coprime).
pub const DEFAULT_MODULI: &[u64] = &[2, 5, 13, 89, 233, 1597, 4181, 28657, 514229, 1346269];

/// Product of DEFAULT_MODULI (fits in u128).
pub const DEFAULT_MODULI_PRODUCT: u128 = 357102999447516172932830542690u128;

/// CRT-based bounded integers with safe reconstruction.
#[derive(Clone, Debug)]
pub struct CRTBigInt {
    pub residues: Vec<u64>,
    pub moduli: Vec<u64>,
    pub value: Option<u128>,
    pub sign: i8,
}

impl CRTBigInt {
    pub fn new(value: i128) -> Self {
        Self::with_moduli(value, DEFAULT_MODULI.to_vec())
    }

    fn gcd_u64(mut a: u64, mut b: u64) -> u64 {
        while b != 0 {
            let t = a % b;
            a = b;
            b = t;
        }
        a
    }

    fn validate_moduli(moduli: &[u64]) -> u128 {
        assert!(!moduli.is_empty(), "CRTBigInt: moduli must be non-empty");
        let mut product: u128 = 1;
        for (i, &m) in moduli.iter().enumerate() {
            assert!(m >= 2, "CRTBigInt: invalid modulus at index {}", i);
            product = product
                .checked_mul(m as u128)
                .expect("CRTBigInt: modulus product overflows u128");
            for &prev in &moduli[..i] {
                assert!(
                    Self::gcd_u64(m, prev) == 1,
                    "CRTBigInt: moduli must be pairwise coprime"
                );
            }
        }
        product
    }

    fn capacity_for_moduli(moduli: &[u64]) -> u128 {
        if moduli == DEFAULT_MODULI {
            DEFAULT_MODULI_PRODUCT
        } else {
            moduli
                .iter()
                .try_fold(1u128, |acc, &m| acc.checked_mul(m as u128))
                .expect("CRTBigInt: modulus product overflows u128")
        }
    }

    pub fn with_moduli(value: i128, moduli: Vec<u64>) -> Self {
        if value == 0 {
            return Self::zero_with_moduli(moduli);
        }
        let capacity = Self::validate_moduli(&moduli);
        let sign = value.signum() as i8;
        let abs_value = value.unsigned_abs();
        assert!(
            abs_value < capacity,
            "CRTBigInt: value exceeds CRT representable range (promotion required)"
        );
        let residues: Vec<u64> = moduli
            .iter()
            .map(|&m| (abs_value % m as u128) as u64)
            .collect();
        Self {
            residues,
            moduli,
            value: Some(abs_value),
            sign,
        }
    }

    pub fn from_i64(value: i64) -> Self {
        Self::new(value as i128)
    }
    pub fn from_u64(value: u64) -> Self {
        Self::new(value as i128)
    }
    pub fn from_i128(value: i128) -> Self {
        Self::new(value)
    }

    pub fn to_i64(&self) -> Option<i64> {
        self.to_i128().and_then(|v| {
            if v >= i64::MIN as i128 && v <= i64::MAX as i128 {
                Some(v as i64)
            } else {
                None
            }
        })
    }

    pub fn to_i128(&self) -> Option<i128> {
        self.value.and_then(|val| {
            if val > i128::MAX as u128 {
                None
            } else {
                Some((val as i128) * (self.sign as i128))
            }
        })
    }

    pub fn from_bigint(bigint: &HCVLangBigInt) -> Self {
        if bigint.is_zero() {
            return Self::zero();
        }
        if let Some(val) = bigint.to_i128() {
            if val.unsigned_abs() >= DEFAULT_MODULI_PRODUCT {
                return Self::zero();
            }
            return Self::new(val);
        }
        Self::zero()
    }

    pub fn to_bigint(&self) -> HCVLangBigInt {
        if self.is_zero() {
            return HCVLangBigInt::zero();
        }
        let result = HCVLangBigInt::from_u128(self.reconstruct());
        if self.sign < 0 {
            -result
        } else {
            result
        }
    }

    pub fn zero() -> Self {
        Self::zero_with_moduli(DEFAULT_MODULI.to_vec())
    }

    fn zero_with_moduli(moduli: Vec<u64>) -> Self {
        let _ = Self::validate_moduli(&moduli);
        Self {
            residues: vec![0; moduli.len()],
            moduli,
            value: Some(0),
            sign: 0,
        }
    }

    pub fn one() -> Self {
        Self::new(1)
    }
    pub fn is_zero(&self) -> bool {
        self.sign == 0
    }
    pub fn is_one(&self) -> bool {
        self.sign == 1
            && self
                .residues
                .iter()
                .enumerate()
                .all(|(i, &r)| r == (1 % self.moduli[i]))
    }
    pub fn is_negative(&self) -> bool {
        self.sign < 0
    }
    pub fn is_positive(&self) -> bool {
        self.sign > 0
    }

    pub fn abs(&self) -> Self {
        if self.sign < 0 {
            let mut r = self.clone();
            r.sign = -r.sign;
            r
        } else {
            self.clone()
        }
    }

    pub fn bit_length(&self) -> u32 {
        if self.is_zero() {
            0
        } else {
            let v = self.value.unwrap_or_else(|| self.reconstruct());
            if v == 0 {
                0
            } else {
                128 - v.leading_zeros()
            }
        }
    }

    pub fn reconstruct(&self) -> u128 {
        if let Some(val) = self.value {
            return val;
        }
        let mut result = self.residues[0] as u128;
        let mut prod = self.moduli[0] as u128;
        for i in 1..self.residues.len() {
            let modulus = self.moduli[i] as u128;
            let residue = self.residues[i] as u128;
            let temp = (residue + modulus - (result % modulus)) % modulus;
            if let Some(inv) = Self::moduli_inverse(prod, modulus) {
                let coefficient = (temp * inv) % modulus;
                result += prod * coefficient;
                prod = prod
                    .checked_mul(modulus)
                    .expect("CRTBigInt: product overflow in reconstruct");
            } else {
                panic!("CRTBigInt: moduli are not coprime");
            }
        }
        result
    }

    fn moduli_inverse(a: u128, m: u128) -> Option<u128> {
        if a == 0 || m == 0 {
            return None;
        }
        let (gcd, x, _) = Self::extended_gcd(a as i128, m as i128);
        if gcd != 1 {
            return None;
        }
        Some(((x % m as i128) + m as i128) as u128 % m)
    }

    fn extended_gcd(a: i128, b: i128) -> (i128, i128, i128) {
        if a == 0 {
            return (b, 0, 1);
        }
        let (gcd, x1, y1) = Self::extended_gcd(b % a, a);
        (gcd, y1 - (b / a) * x1, x1)
    }

    pub fn gcd(a: &Self, b: &Self) -> Self {
        if b.is_zero() {
            a.clone()
        } else {
            let r = a.clone() % b.clone();
            Self::gcd(b, &r)
        }
    }

    pub fn mod_inverse_with_modulus(&self, modulus: &Self) -> Option<Self> {
        if self.is_zero() || modulus.is_zero() {
            return None;
        }
        let a_val = self.to_i128()?;
        let mod_val = modulus.to_i128()?;
        let (gcd, x, _) = Self::extended_gcd(a_val, mod_val);
        if gcd != 1 {
            return None;
        }
        Some(Self::from_i128(((x % mod_val) + mod_val) % mod_val))
    }
}

// Arithmetic operators

impl Add for CRTBigInt {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        if self.is_zero() {
            return other;
        }
        if other.is_zero() {
            return self;
        }
        assert!(self.moduli == other.moduli, "CRTBigInt: mismatched moduli");
        let capacity = Self::capacity_for_moduli(&self.moduli);
        let mag1 = self.reconstruct();
        let mag2 = other.reconstruct();
        if self.sign == other.sign {
            let new_mag = mag1
                .checked_add(mag2)
                .expect("CRTBigInt: addition overflow");
            assert!(
                new_mag < capacity,
                "CRTBigInt: addition overflow (promotion required)"
            );
            let residues: Vec<u64> = self
                .residues
                .iter()
                .zip(other.residues.iter())
                .zip(self.moduli.iter())
                .map(|((a, b), m)| ((*a as u128 + *b as u128) % *m as u128) as u64)
                .collect();
            Self {
                residues,
                moduli: self.moduli,
                value: Some(new_mag),
                sign: if new_mag == 0 { 0 } else { self.sign },
            }
        } else if mag1 >= mag2 {
            let new_mag = mag1 - mag2;
            let residues: Vec<u64> = self
                .residues
                .iter()
                .zip(other.residues.iter())
                .zip(self.moduli.iter())
                .map(|((a, b), m)| if *a >= *b { a - b } else { m - (b - a) })
                .collect();
            Self {
                residues,
                moduli: self.moduli,
                value: Some(new_mag),
                sign: if new_mag == 0 { 0 } else { self.sign },
            }
        } else {
            let new_mag = mag2 - mag1;
            let residues: Vec<u64> = other
                .residues
                .iter()
                .zip(self.residues.iter())
                .zip(self.moduli.iter())
                .map(|((b, a), m)| if *b >= *a { b - a } else { m - (a - b) })
                .collect();
            Self {
                residues,
                moduli: self.moduli,
                value: Some(new_mag),
                sign: if new_mag == 0 { 0 } else { other.sign },
            }
        }
    }
}

impl Sub for CRTBigInt {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        if other.is_zero() {
            return self;
        }
        if self.is_zero() {
            let mut r = other;
            r.sign = -r.sign;
            return r;
        }
        self + (-other)
    }
}

impl Mul for CRTBigInt {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }
        assert!(self.moduli == other.moduli, "CRTBigInt: mismatched moduli");
        let capacity = Self::capacity_for_moduli(&self.moduli);
        let mag1 = self.reconstruct();
        let mag2 = other.reconstruct();
        assert!(
            mag2 <= (capacity - 1) / mag1,
            "CRTBigInt: multiplication overflow (promotion required)"
        );
        let new_mag = mag1 * mag2;
        let residues: Vec<u64> = self
            .residues
            .iter()
            .zip(other.residues.iter())
            .zip(self.moduli.iter())
            .map(|((a, b), m)| ((*a as u128 * *b as u128) % *m as u128) as u64)
            .collect();
        Self {
            residues,
            moduli: self.moduli,
            value: Some(new_mag),
            sign: if new_mag == 0 {
                0
            } else {
                self.sign * other.sign
            },
        }
    }
}

impl Div for CRTBigInt {
    type Output = Self;
    fn div(self, other: Self) -> Self {
        assert!(!other.is_zero(), "CRTBigInt: division by zero");
        if self.is_zero() {
            return Self::zero_with_moduli(self.moduli);
        }
        let a_mag = self.reconstruct();
        let b_mag = other.reconstruct();
        let q_mag = a_mag / b_mag;
        let residues: Vec<u64> = self
            .moduli
            .iter()
            .map(|&m| (q_mag % m as u128) as u64)
            .collect();
        Self {
            residues,
            moduli: self.moduli,
            value: Some(q_mag),
            sign: if q_mag == 0 {
                0
            } else {
                self.sign * other.sign
            },
        }
    }
}

impl Rem for CRTBigInt {
    type Output = Self;
    fn rem(self, other: Self) -> Self {
        assert!(!other.is_zero(), "CRTBigInt: division by zero");
        if self.is_zero() {
            return Self::zero_with_moduli(self.moduli);
        }
        let a_mag = self.reconstruct();
        let b_mag = other.reconstruct();
        let r_mag = a_mag % b_mag;
        let residues: Vec<u64> = self
            .moduli
            .iter()
            .map(|&m| (r_mag % m as u128) as u64)
            .collect();
        Self {
            residues,
            moduli: self.moduli,
            value: Some(r_mag),
            sign: if r_mag == 0 { 0 } else { 1 },
        }
    }
}

impl Neg for CRTBigInt {
    type Output = Self;
    fn neg(mut self) -> Self {
        if !self.is_zero() {
            self.sign = -self.sign;
        }
        self
    }
}

impl PartialEq for CRTBigInt {
    fn eq(&self, other: &Self) -> bool {
        self.sign == other.sign && self.reconstruct() == other.reconstruct()
    }
}
impl Eq for CRTBigInt {}

impl PartialOrd for CRTBigInt {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for CRTBigInt {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.sign.cmp(&other.sign) {
            Ordering::Equal => {
                let o = self.reconstruct().cmp(&other.reconstruct());
                if self.sign < 0 {
                    o.reverse()
                } else {
                    o
                }
            }
            ord => ord,
        }
    }
}

impl fmt::Display for CRTBigInt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_zero() {
            write!(f, "0")
        } else if self.sign < 0 {
            write!(f, "-{}", self.reconstruct())
        } else {
            write!(f, "{}", self.reconstruct())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coprime_moduli() {
        for i in 0..DEFAULT_MODULI.len() {
            for j in (i + 1)..DEFAULT_MODULI.len() {
                assert_eq!(CRTBigInt::gcd_u64(DEFAULT_MODULI[i], DEFAULT_MODULI[j]), 1);
            }
        }
    }

    #[test]
    fn test_creation_and_reconstruct() {
        let a = CRTBigInt::new(12345);
        assert_eq!(a.reconstruct(), 12345);
        assert_eq!(a.sign, 1);
    }

    #[test]
    fn test_addition() {
        let c = CRTBigInt::new(100) + CRTBigInt::new(200);
        assert_eq!(c.reconstruct(), 300);
    }

    #[test]
    fn test_subtraction() {
        let c = CRTBigInt::new(200) - CRTBigInt::new(100);
        assert_eq!(c.to_i128(), Some(100));
    }

    #[test]
    fn test_multiplication() {
        let c = CRTBigInt::new(12) * CRTBigInt::new(34);
        assert_eq!(c.reconstruct(), 408);
    }

    #[test]
    fn test_division() {
        let c = CRTBigInt::new(100) / CRTBigInt::new(7);
        assert_eq!(c.to_i128(), Some(14)); // integer division
    }

    #[test]
    fn test_negative() {
        let neg = CRTBigInt::new(-42);
        assert_eq!(neg.to_i128(), Some(-42));
        assert!(neg.is_negative());
    }

    #[test]
    fn test_gcd() {
        let g = CRTBigInt::gcd(&CRTBigInt::new(35), &CRTBigInt::new(15));
        assert_eq!(g.to_i128(), Some(5));
    }

    #[test]
    fn test_bigint_roundtrip() {
        let original = CRTBigInt::new(999999);
        let bigint = original.to_bigint();
        let back = CRTBigInt::from_bigint(&bigint);
        assert_eq!(original.to_i128(), back.to_i128());
    }

    #[test]
    fn test_zero_cancellation() {
        let c = CRTBigInt::new(5) + CRTBigInt::new(-5);
        assert!(c.is_zero());
    }

    #[test]
    #[should_panic(expected = "promotion required")]
    fn test_overflow_panics() {
        let max = CRTBigInt::new((DEFAULT_MODULI_PRODUCT - 1) as i128);
        let _ = max + CRTBigInt::new(1);
    }
}
