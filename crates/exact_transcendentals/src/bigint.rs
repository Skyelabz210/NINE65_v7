//! HCVLangBigInt - Arbitrary precision signed integers
//!
//! Extracted from qmnf-primitives for use in exact_transcendentals.
//! Base: 2^64 limbs, little-endian. Signed via `neg` bit.
//!
//! # Integer-Only Guarantee
//! All operations are exact integer arithmetic. No floating-point.

#![allow(missing_docs)]
#![allow(clippy::needless_return)]

#[cfg(not(feature = "std"))]
use alloc::vec;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

use core::cmp::Ordering;
use core::fmt;
use core::hash::{Hash, Hasher};
use core::ops::{
    Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Rem, RemAssign, Shl, ShlAssign, Shr,
    ShrAssign, Sub, SubAssign,
};

/// Arbitrary precision signed integer.
///
/// Internally represented as a vector of 64-bit limbs (little-endian)
/// with a sign bit. Zero is canonically represented as empty limbs
/// with neg=false.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HCVLangBigInt {
    /// Little-endian 64-bit limbs (least significant first)
    pub limbs: Vec<u64>,
    /// Sign flag: false = non-negative, true = negative
    pub neg: bool,
}

impl Hash for HCVLangBigInt {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.limbs.hash(state);
        self.neg.hash(state);
    }
}

impl HCVLangBigInt {
    pub fn new(value: i64) -> Self {
        if value == 0 {
            return Self::zero();
        }
        let neg = value < 0;
        let v = value.unsigned_abs();
        Self {
            limbs: if v == 0 { Vec::new() } else { vec![v] },
            neg,
        }
        .normalize()
    }

    pub fn from_u64(value: u64) -> Self {
        if value == 0 {
            Self::zero()
        } else {
            Self {
                limbs: vec![value],
                neg: false,
            }
        }
    }

    pub fn from_u128(value: u128) -> Self {
        if value == 0 {
            return Self::zero();
        }
        let lo = (value & 0xFFFF_FFFF_FFFF_FFFF) as u64;
        let hi = (value >> 64) as u64;
        let limbs = if hi == 0 { vec![lo] } else { vec![lo, hi] };
        Self { limbs, neg: false }
    }

    pub fn from_i128(value: i128) -> Self {
        if value == 0 {
            return Self::zero();
        }
        let neg = value < 0;
        let mut x = value.unsigned_abs();
        let mut limbs = Vec::with_capacity(2);
        limbs.push((x & 0xFFFF_FFFF_FFFF_FFFF) as u64);
        x >>= 64;
        if x != 0 {
            limbs.push((x & 0xFFFF_FFFF_FFFF_FFFF) as u64);
        }
        Self { limbs, neg }.normalize()
    }

    #[inline]
    pub fn zero() -> Self {
        Self {
            limbs: Vec::new(),
            neg: false,
        }
    }

    #[inline]
    pub fn one() -> Self {
        Self {
            limbs: vec![1],
            neg: false,
        }
    }

    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        self.limbs.is_empty()
    }

    #[inline(always)]
    pub fn is_negative(&self) -> bool {
        self.neg && !self.is_zero()
    }

    #[inline]
    pub fn is_one(&self) -> bool {
        self.limbs.len() == 1 && self.limbs[0] == 1 && !self.neg
    }

    #[inline(always)]
    pub fn is_even(&self) -> bool {
        self.is_zero() || (self.limbs[0] & 1) == 0
    }

    #[inline(always)]
    pub fn abs(&self) -> Self {
        let mut t = self.clone();
        t.neg = false;
        t
    }

    #[inline(always)]
    fn normalize(mut self) -> Self {
        while let Some(&last) = self.limbs.last() {
            if last == 0 {
                self.limbs.pop();
            } else {
                break;
            }
        }
        if self.limbs.is_empty() {
            self.neg = false;
        }
        self
    }

    pub fn cmp_abs(&self, other: &Self) -> Ordering {
        let la = self.limbs.len();
        let lb = other.limbs.len();
        if la != lb {
            return la.cmp(&lb);
        }
        for i in (0..la).rev() {
            if self.limbs[i] != other.limbs[i] {
                return self.limbs[i].cmp(&other.limbs[i]);
            }
        }
        Ordering::Equal
    }

    #[inline(always)]
    fn add_abs_assign(&mut self, rhs: &Self) {
        if rhs.is_zero() {
            return;
        }
        if self.limbs.len() < rhs.limbs.len() {
            self.limbs.resize(rhs.limbs.len(), 0);
        }
        let mut carry = 0u128;
        let n = rhs.limbs.len();
        for i in 0..n {
            let sum = self.limbs[i] as u128 + rhs.limbs[i] as u128 + carry;
            self.limbs[i] = sum as u64;
            carry = sum >> 64;
        }
        let m = self.limbs.len();
        let mut i = n;
        while carry != 0 && i < m {
            let sum = self.limbs[i] as u128 + carry;
            self.limbs[i] = sum as u64;
            carry = sum >> 64;
            i += 1;
        }
        if carry != 0 {
            self.limbs.push(carry as u64);
        }
    }

    #[inline(always)]
    fn sub_abs_assign(&mut self, rhs: &Self) {
        debug_assert!(self.cmp_abs(rhs) != Ordering::Less);
        if rhs.is_zero() {
            return;
        }
        let mut borrow = 0u128;
        let n = rhs.limbs.len();
        for i in 0..n {
            let a = self.limbs[i] as u128;
            let b = rhs.limbs[i] as u128 + borrow;
            let (res, did_borrow) = a.overflowing_sub(b);
            self.limbs[i] = res as u64;
            borrow = if did_borrow { 1 } else { 0 };
        }
        let m = self.limbs.len();
        let mut i = n;
        while borrow != 0 && i < m {
            let a = self.limbs[i] as u128;
            let (res, did_borrow) = a.overflowing_sub(1);
            self.limbs[i] = res as u64;
            borrow = if did_borrow { 1 } else { 0 };
            i += 1;
        }
        *self = self.clone().normalize();
    }

    #[inline(always)]
    pub fn mul_u64_assign(&mut self, rhs: u64) {
        if self.is_zero() || rhs == 0 {
            *self = Self::zero();
            return;
        }
        if rhs == 1 {
            return;
        }
        let mut carry = 0u128;
        for limb in &mut self.limbs {
            let t = (*limb as u128) * (rhs as u128) + carry;
            *limb = t as u64;
            carry = t >> 64;
        }
        if carry != 0 {
            self.limbs.push(carry as u64);
        }
    }

    pub fn div_rem_u64(&self, divisor: u64) -> (Self, u64) {
        assert!(divisor != 0, "division by zero");
        if self.is_zero() {
            return (Self::zero(), 0);
        }
        let mut quotient_limbs = vec![0u64; self.limbs.len()];
        let mut remainder: u128 = 0;
        for (idx, limb) in self.limbs.iter().enumerate().rev() {
            let cur = (remainder << 64) | (*limb as u128);
            quotient_limbs[idx] = (cur / divisor as u128) as u64;
            remainder = cur % divisor as u128;
        }
        (
            Self {
                limbs: quotient_limbs,
                neg: self.neg,
            }
            .normalize(),
            remainder as u64,
        )
    }

    pub fn low_u128(&self) -> u128 {
        let lo = *self.limbs.first().unwrap_or(&0) as u128;
        let hi = *self.limbs.get(1).unwrap_or(&0) as u128;
        (hi << 64) | lo
    }

    pub fn rem_u64(&self, m: u64) -> u64 {
        if m == 0 {
            return 0;
        }
        let mut rem: u128 = 0;
        for &w in self.limbs.iter().rev() {
            rem = ((rem << 64) | (w as u128)) % (m as u128);
        }
        rem as u64
    }

    #[inline(always)]
    pub fn trailing_zeros(&self) -> u32 {
        if self.is_zero() {
            return 0;
        }
        let mut count = 0;
        for &limb in self.limbs.iter() {
            if limb == 0 {
                count += 64;
            } else {
                count += limb.trailing_zeros();
                break;
            }
        }
        count
    }

    pub fn shr_in_place(&mut self, bits: u32) {
        self.shr_assign(bits);
    }

    #[inline(always)]
    pub fn gcd(a: &Self, b: &Self) -> Self {
        if a.is_zero() {
            return b.abs();
        }
        if b.is_zero() {
            return a.abs();
        }
        let mut u = a.abs();
        let mut v = b.abs();
        let u_zeros = u.trailing_zeros();
        let v_zeros = v.trailing_zeros();
        let common_twos = u_zeros.min(v_zeros);
        u.shr_in_place(u_zeros);
        v.shr_in_place(v_zeros);
        while u != v {
            if u > v {
                core::mem::swap(&mut u, &mut v);
            }
            v -= &u;
            v >>= 1;
            let vz = v.trailing_zeros();
            if vz > 0 {
                v.shr_in_place(vz);
            }
        }
        u << common_twos
    }

    pub fn to_i64(&self) -> Option<i64> {
        if self.limbs.len() > 1 {
            return None;
        }
        let v = *self.limbs.first().unwrap_or(&0) as i128;
        let s = if self.is_negative() { -v } else { v };
        s.try_into().ok()
    }

    pub fn to_i128(&self) -> Option<i128> {
        if self.is_zero() {
            return Some(0);
        }
        if self.limbs.len() > 2 {
            return None;
        }
        let magnitude = self.low_u128();
        if self.is_negative() {
            if magnitude > (1u128 << 127) {
                return None;
            }
            if magnitude == (1u128 << 127) {
                return Some(i128::MIN);
            }
            Some(-(magnitude as i128))
        } else {
            if magnitude > i128::MAX as u128 {
                return None;
            }
            Some(magnitude as i128)
        }
    }
}

// Operator implementations

impl AddAssign<&HCVLangBigInt> for HCVLangBigInt {
    fn add_assign(&mut self, rhs: &HCVLangBigInt) {
        match (self.neg, rhs.neg) {
            (false, false) => self.add_abs_assign(rhs),
            (true, true) => {
                self.neg = false;
                self.add_abs_assign(rhs);
                self.neg = !self.is_zero();
            }
            (false, true) => match self.cmp_abs(rhs) {
                Ordering::Greater | Ordering::Equal => self.sub_abs_assign(rhs),
                Ordering::Less => {
                    let mut tmp = rhs.clone();
                    tmp.neg = false;
                    tmp.sub_abs_assign(self);
                    *self = tmp;
                    self.neg = !self.is_zero();
                }
            },
            (true, false) => {
                let mut lhs_abs = self.clone();
                lhs_abs.neg = false;
                match lhs_abs.cmp_abs(rhs) {
                    Ordering::Greater | Ordering::Equal => {
                        lhs_abs.sub_abs_assign(rhs);
                        *self = lhs_abs;
                        self.neg = !self.is_zero();
                    }
                    Ordering::Less => {
                        let mut t = rhs.clone();
                        t.sub_abs_assign(&lhs_abs);
                        *self = t;
                        self.neg = false;
                    }
                }
            }
        }
        *self = self.clone().normalize();
    }
}

impl SubAssign<&HCVLangBigInt> for HCVLangBigInt {
    fn sub_assign(&mut self, rhs: &HCVLangBigInt) {
        let mut t = rhs.clone();
        t.neg = !t.neg;
        *self += &t;
    }
}

impl MulAssign<&HCVLangBigInt> for HCVLangBigInt {
    fn mul_assign(&mut self, rhs: &HCVLangBigInt) {
        if self.is_zero() || rhs.is_zero() {
            *self = Self::zero();
            return;
        }
        let n = self.limbs.len();
        let m = rhs.limbs.len();
        let mut out = vec![0u64; n + m];
        for i in 0..n {
            let a = self.limbs[i] as u128;
            let mut carry = 0u128;
            for j in 0..m {
                let t = a * (rhs.limbs[j] as u128) + (out[i + j] as u128) + carry;
                out[i + j] = t as u64;
                carry = t >> 64;
            }
            if carry != 0 {
                out[i + m] = (out[i + m] as u128 + carry) as u64;
            }
        }
        let neg = self.neg ^ rhs.neg;
        *self = HCVLangBigInt { limbs: out, neg }.normalize();
    }
}

impl DivAssign<&HCVLangBigInt> for HCVLangBigInt {
    fn div_assign(&mut self, rhs: &HCVLangBigInt) {
        if rhs.is_zero() {
            panic!("division by zero");
        }
        if self.is_zero() {
            return;
        }
        if self.cmp_abs(rhs) == Ordering::Less {
            *self = Self::zero();
            return;
        }
        let a = self.abs();
        let b = rhs.abs();
        let mut q = Self::zero();
        let mut current = Self::zero();
        for i in (0..a.limbs.len() * 64).rev() {
            current <<= 1;
            if (a.limbs[i / 64] >> (i % 64)) & 1 == 1 {
                if current.limbs.is_empty() {
                    current.limbs.push(0);
                }
                current.limbs[0] |= 1;
            }
            current = current.normalize();
            if current.cmp_abs(&b) != Ordering::Less {
                current -= &b;
                if q.limbs.is_empty() {
                    q.limbs.resize(a.limbs.len(), 0);
                }
                q.limbs[i / 64] |= 1 << (i % 64);
            }
        }
        q = q.normalize();
        q.neg = self.neg ^ rhs.neg;
        *self = q.normalize();
    }
}

impl RemAssign<&HCVLangBigInt> for HCVLangBigInt {
    fn rem_assign(&mut self, rhs: &HCVLangBigInt) {
        if rhs.is_zero() {
            panic!("division by zero");
        }
        if self.is_zero() {
            return;
        }
        let a = self.abs();
        let b = rhs.abs();
        if a.cmp_abs(&b) == Ordering::Less {
            return;
        }
        let mut current = Self::zero();
        for i in (0..a.limbs.len() * 64).rev() {
            current <<= 1;
            if (a.limbs[i / 64] >> (i % 64)) & 1 == 1 {
                if current.limbs.is_empty() {
                    current.limbs.push(0);
                }
                current.limbs[0] |= 1;
            }
            current = current.normalize();
            if current.cmp_abs(&b) != Ordering::Less {
                current -= &b;
            }
        }
        *self = current.normalize();
        self.neg = a.neg;
    }
}

// Value operators
impl Add for HCVLangBigInt {
    type Output = Self;
    fn add(mut self, rhs: Self) -> Self {
        self += &rhs;
        self
    }
}
impl Add<&HCVLangBigInt> for HCVLangBigInt {
    type Output = Self;
    fn add(mut self, rhs: &Self) -> Self {
        self += rhs;
        self
    }
}
impl Sub for HCVLangBigInt {
    type Output = Self;
    fn sub(mut self, rhs: Self) -> Self {
        self -= &rhs;
        self
    }
}
impl Sub<&HCVLangBigInt> for HCVLangBigInt {
    type Output = Self;
    fn sub(mut self, rhs: &Self) -> Self {
        self -= rhs;
        self
    }
}
impl Mul for HCVLangBigInt {
    type Output = Self;
    fn mul(mut self, rhs: Self) -> Self {
        self *= &rhs;
        self
    }
}
impl Mul<&HCVLangBigInt> for HCVLangBigInt {
    type Output = Self;
    fn mul(mut self, rhs: &Self) -> Self {
        self *= rhs;
        self
    }
}
impl Div for HCVLangBigInt {
    type Output = Self;
    fn div(mut self, rhs: Self) -> Self {
        self /= &rhs;
        self
    }
}
impl Div<&HCVLangBigInt> for HCVLangBigInt {
    type Output = Self;
    fn div(mut self, rhs: &Self) -> Self {
        self /= rhs;
        self
    }
}
impl Rem for HCVLangBigInt {
    type Output = Self;
    fn rem(mut self, rhs: Self) -> Self {
        self %= &rhs;
        self
    }
}
impl Rem<&HCVLangBigInt> for HCVLangBigInt {
    type Output = Self;
    fn rem(mut self, rhs: &Self) -> Self {
        self %= rhs;
        self
    }
}
impl Neg for HCVLangBigInt {
    type Output = Self;
    fn neg(mut self) -> Self {
        if !self.is_zero() {
            self.neg = !self.neg;
        }
        self
    }
}

// Shifts
impl ShlAssign<u32> for HCVLangBigInt {
    fn shl_assign(&mut self, rhs: u32) {
        if self.is_zero() || rhs == 0 {
            return;
        }
        let word_shift = (rhs / 64) as usize;
        let bit_shift = rhs % 64;
        if word_shift > 0 {
            let mut v = vec![0u64; word_shift];
            v.extend_from_slice(&self.limbs);
            self.limbs = v;
        }
        if bit_shift == 0 {
            return;
        }
        let mut carry = 0u64;
        for w in &mut self.limbs {
            let new_carry = (*w >> (64 - bit_shift)) & ((1u64 << bit_shift) - 1);
            let t = ((*w as u128) << bit_shift) | (carry as u128);
            *w = t as u64;
            carry = new_carry;
        }
        if carry != 0 {
            self.limbs.push(carry);
        }
    }
}
impl Shl<u32> for HCVLangBigInt {
    type Output = Self;
    fn shl(mut self, rhs: u32) -> Self {
        self <<= rhs;
        self
    }
}

impl ShrAssign<u32> for HCVLangBigInt {
    fn shr_assign(&mut self, rhs: u32) {
        if self.is_zero() || rhs == 0 {
            return;
        }
        let word_shift = (rhs / 64) as usize;
        let bit_shift = rhs % 64;
        if word_shift >= self.limbs.len() {
            *self = Self::zero();
            return;
        }
        if word_shift > 0 {
            self.limbs.drain(0..word_shift);
        }
        if bit_shift == 0 {
            *self = self.clone().normalize();
            return;
        }
        let mut carry = 0u64;
        for i in (0..self.limbs.len()).rev() {
            let limb = self.limbs[i];
            self.limbs[i] = (limb >> bit_shift) | (carry << (64 - bit_shift));
            carry = limb & ((1u64 << bit_shift) - 1);
        }
        *self = self.clone().normalize();
    }
}
impl Shr<u32> for HCVLangBigInt {
    type Output = Self;
    fn shr(mut self, rhs: u32) -> Self {
        self >>= rhs;
        self
    }
}

// Ordering
impl PartialOrd for HCVLangBigInt {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for HCVLangBigInt {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.neg, other.neg) {
            (false, false) => self.cmp_abs(other),
            (true, true) => other.cmp_abs(self),
            (false, true) => Ordering::Greater,
            (true, false) => Ordering::Less,
        }
    }
}

// Display
impl fmt::Display for HCVLangBigInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_zero() {
            return write!(f, "0");
        }
        const BASE: u32 = 1_000_000_000;
        let mut tmp = self.abs();
        let mut parts: Vec<u32> = Vec::new();
        while !tmp.is_zero() {
            let mut rem: u128 = 0;
            for w in tmp.limbs.iter_mut().rev() {
                let cur = (rem << 64) | (*w as u128);
                *w = (cur / (BASE as u128)) as u64;
                rem = cur % (BASE as u128);
            }
            tmp = tmp.normalize();
            parts.push(rem as u32);
        }
        if self.is_negative() {
            write!(f, "-")?;
        }
        if let Some(last) = parts.pop() {
            write!(f, "{}", last)?;
            while let Some(p) = parts.pop() {
                write!(f, "{:09}", p)?;
            }
        }
        Ok(())
    }
}

// From impls
impl From<i64> for HCVLangBigInt {
    fn from(v: i64) -> Self {
        Self::new(v)
    }
}
impl From<i128> for HCVLangBigInt {
    fn from(v: i128) -> Self {
        Self::from_i128(v)
    }
}
impl From<u64> for HCVLangBigInt {
    fn from(v: u64) -> Self {
        Self::from_u64(v)
    }
}
impl From<u128> for HCVLangBigInt {
    fn from(v: u128) -> Self {
        Self::from_u128(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_construction() {
        let a = HCVLangBigInt::new(42);
        assert_eq!(a.to_i64(), Some(42));
        let b = HCVLangBigInt::new(-42);
        assert_eq!(b.to_i64(), Some(-42));
        assert!(HCVLangBigInt::zero().is_zero());
    }

    #[test]
    fn test_arithmetic() {
        let a = HCVLangBigInt::new(100);
        let b = HCVLangBigInt::new(50);
        assert_eq!((a.clone() + b.clone()).to_i64(), Some(150));
        assert_eq!((a.clone() - b.clone()).to_i64(), Some(50));
        assert_eq!((a.clone() * b.clone()).to_i64(), Some(5000));
        assert_eq!((a / b).to_i64(), Some(2));
    }

    #[test]
    fn test_gcd() {
        let a = HCVLangBigInt::new(48);
        let b = HCVLangBigInt::new(18);
        assert_eq!(HCVLangBigInt::gcd(&a, &b).to_i64(), Some(6));
    }

    #[test]
    fn test_i128_limits() {
        let max = HCVLangBigInt::from_i128(i128::MAX);
        assert_eq!(max.to_i128(), Some(i128::MAX));
        let min = HCVLangBigInt::from_i128(i128::MIN);
        assert_eq!(min.to_i128(), Some(i128::MIN));
    }

    #[test]
    fn test_shifts() {
        let a = HCVLangBigInt::new(8);
        assert_eq!((a.clone() << 2).to_i64(), Some(32));
        assert_eq!((a >> 1).to_i64(), Some(4));
    }

    #[test]
    fn test_large_multiply() {
        let a = HCVLangBigInt::from_i128(1_000_000_000_000i128);
        let b = HCVLangBigInt::from_i128(1_000_000_000_000i128);
        let c = a * b;
        assert_eq!(c.to_i128(), Some(1_000_000_000_000_000_000_000_000i128));
    }
}
