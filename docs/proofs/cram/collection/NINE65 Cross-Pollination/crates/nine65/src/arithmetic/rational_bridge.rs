//! Bridge between NexGen exact rationals and NINE65's RNS infrastructure.
//!
//! Provides conversions between NexGenRat (i128 exact fractions) and
//! NINE65's modular residue types for exact parameter computation.

use nexgen_rational::exact_coeff::ExactCoeff as NGExactCoeff;
use nexgen_rational::rat_ng::error::ArithmeticError as NGError;
use nexgen_rational::rat_ng::ops;
use nexgen_rational::rat_ng::policy;
use nexgen_rational::rat_ng::types::{DivOut, NexGenRat};

/// Bridge between exact rationals and RNS residue representation.
///
/// Holds a NexGenRat value and provides conversions to/from
/// the modular arithmetic used by NINE65's FHE pipeline.
#[derive(Clone, Debug)]
pub struct RationalBridge {
    inner: NexGenRat,
}

/// Errors from rational bridge operations.
#[derive(Debug)]
pub enum BridgeError {
    /// Denominator was zero
    ZeroDenominator,
    /// Arithmetic overflow in i128
    Overflow(String),
    /// Modular inverse does not exist (gcd(den, p) != 1)
    NoInverse { den: u64, modulus: u64 },
    /// NexGen arithmetic error
    Arithmetic(NGError),
}

impl From<NGError> for BridgeError {
    fn from(e: NGError) -> Self {
        BridgeError::Arithmetic(e)
    }
}

impl RationalBridge {
    /// Create a rational bridge from numerator/denominator.
    pub fn new(num: i128, den: i128) -> Result<Self, BridgeError> {
        if den == 0 {
            return Err(BridgeError::ZeroDenominator);
        }
        let rat = NexGenRat::new(NGExactCoeff(num), NGExactCoeff(den));
        Ok(Self { inner: rat })
    }

    /// Create from an integer value (den = 1).
    pub fn from_integer(val: i128) -> Self {
        Self {
            inner: NexGenRat::new(NGExactCoeff(val), NGExactCoeff(1)),
        }
    }

    /// Access numerator as i128.
    pub fn numerator(&self) -> i128 {
        self.inner.numerator().0
    }

    /// Access denominator as i128.
    pub fn denominator(&self) -> i128 {
        self.inner.denominator().0
    }

    /// Returns true if this is an integer (den = 1).
    pub fn is_integer(&self) -> bool {
        self.inner.is_integer()
    }

    /// Convert rational to a residue mod p.
    ///
    /// Computes (num * den^(-1)) mod p using extended Euclidean algorithm.
    /// Returns the residue in [0, p).
    ///
    /// # Panics
    /// If gcd(den, p) != 1 (inverse doesn't exist).
    pub fn to_residue(&self, p: u64) -> u64 {
        let num = self.inner.numerator().0.rem_euclid(p as i128) as u64;
        let den = self.inner.denominator().0.rem_euclid(p as i128) as u64;
        let den_inv = mod_inverse_u64(den, p).expect("denominator must be invertible mod p");
        ((num as u128 * den_inv as u128) % p as u128) as u64
    }

    /// Convert rational to residues for multiple moduli.
    pub fn to_residues(&self, moduli: &[u64]) -> Vec<u64> {
        moduli.iter().map(|&p| self.to_residue(p)).collect()
    }

    /// Perform exact integer division using NexGen's trichotomy.
    ///
    /// Returns DivOut (ExactInverse, ExactAFC, or FPD).
    pub fn exact_divide(a: i128, b: i128) -> Result<DivOut, BridgeError> {
        let a_coeff = NGExactCoeff(a);
        let b_coeff = NGExactCoeff(b);
        Ok(policy::divide_coeff(&a_coeff, &b_coeff)?)
    }

    /// Add two rational bridges.
    pub fn add(&self, other: &Self) -> Result<Self, BridgeError> {
        let result = ops::add(&self.inner, &other.inner)?;
        Ok(Self { inner: result })
    }

    /// Subtract two rational bridges.
    pub fn sub(&self, other: &Self) -> Result<Self, BridgeError> {
        let result = ops::sub(&self.inner, &other.inner)?;
        Ok(Self { inner: result })
    }

    /// Multiply two rational bridges.
    pub fn mul(&self, other: &Self) -> Result<Self, BridgeError> {
        let result = ops::mul(&self.inner, &other.inner)?;
        Ok(Self { inner: result })
    }

    /// Divide two rational bridges.
    pub fn div(&self, other: &Self) -> Result<Self, BridgeError> {
        let result = ops::div(&self.inner, &other.inner)?;
        Ok(Self { inner: result })
    }
}

/// Extended Euclidean algorithm for modular inverse.
/// Returns a^(-1) mod m, or None if gcd(a, m) != 1.
fn mod_inverse_u64(a: u64, m: u64) -> Option<u64> {
    if m == 0 {
        return None;
    }
    if m == 1 {
        return Some(0);
    }
    let (mut old_r, mut r) = (m as i128, a as i128);
    let (mut old_s, mut s) = (0i128, 1i128);

    while r != 0 {
        let q = old_r / r;
        let tmp_r = r;
        r = old_r - q * r;
        old_r = tmp_r;
        let tmp_s = s;
        s = old_s - q * s;
        old_s = tmp_s;
    }

    if old_r != 1 {
        return None; // gcd != 1, no inverse
    }

    Some(old_s.rem_euclid(m as i128) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_rational_to_residues() {
        // 3/4 should produce correct residues mod small primes
        let rat = RationalBridge::new(3, 4).unwrap();
        let p = 17u64;
        // 3/4 mod 17 = 3 * 4^(-1) mod 17 = 3 * 13 mod 17 = 39 mod 17 = 5
        let residue = rat.to_residue(p);
        assert_eq!(residue, 5);
    }

    #[test]
    fn bridge_exact_division_trichotomy() {
        // 12/4 = 3 exactly -> ExactAFC
        let result = RationalBridge::exact_divide(12, 4).unwrap();
        assert!(result.is_exact());
        assert_eq!(result.quotient().0, 3);
    }

    #[test]
    fn bridge_from_kelim_reconstruction() {
        // Reconstruct from K-Elimination output
        let rat = RationalBridge::from_integer(42);
        assert_eq!(rat.numerator(), 42);
        assert_eq!(rat.denominator(), 1);
        assert!(rat.is_integer());
    }

    #[test]
    fn bridge_zero_denominator_rejected() {
        let result = RationalBridge::new(1, 0);
        assert!(matches!(result, Err(BridgeError::ZeroDenominator)));
    }

    #[test]
    fn bridge_arithmetic_ops() {
        let a = RationalBridge::new(1, 3).unwrap(); // 1/3
        let b = RationalBridge::new(1, 7).unwrap(); // 1/7
        let sum = a.add(&b).unwrap(); // 10/21
        assert_eq!(sum.to_residue(17), {
            // 10/21 mod 17 = 10 * 21^(-1) mod 17 = 10 * 13 mod 17
            // (since 21 = 4 mod 17, 4^-1 = 13) = 130 mod 17 = 11
            let num = 10i128.rem_euclid(17) as u64;
            let den = 21i128.rem_euclid(17) as u64; // = 4
            let den_inv = mod_inverse_u64(den, 17).unwrap(); // 4^-1 mod 17 = 13
            ((num as u128 * den_inv as u128) % 17) as u64
        });
    }

    #[test]
    fn bridge_to_residues_multiple_primes() {
        let rat = RationalBridge::from_integer(42);
        let residues = rat.to_residues(&[7, 11, 13]);
        assert_eq!(residues, vec![0, 9, 3]);
    }

    #[test]
    fn mod_inverse_basic() {
        // 4^(-1) mod 17 = 13 (since 4*13 = 52 = 3*17 + 1)
        assert_eq!(mod_inverse_u64(4, 17), Some(13));
    }

    #[test]
    fn mod_inverse_no_inverse() {
        // gcd(6, 12) = 6 != 1, no inverse
        assert_eq!(mod_inverse_u64(6, 12), None);
    }
}
