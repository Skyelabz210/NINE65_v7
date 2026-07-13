//! Persistent Montgomery representation.
//!
//! Values remain in Montgomery coordinates across operation chains and convert
//! only at explicit boundaries. The modulus must be odd so that `R = 2^64` is
//! invertible. Primality is not required: this layer is CLASS-R unless a caller
//! requests a field-only operation such as Fermat inversion.

use crate::params::is_prime;

/// Persistent Montgomery context for one odd modulus below `2^63`.
#[derive(Clone, Debug)]
pub struct PersistentMontgomery {
    pub m: u64,
    pub r_squared: u64,
    pub m_prime: u64,
    pub r_log: u32,
}

impl PersistentMontgomery {
    /// Create a persistent Montgomery context.
    ///
    /// The `< 2^63` bound makes one-subtraction branchless reduction exact for
    /// sums of two canonical residues and bounds REDC intermediates below `2^64`.
    pub fn new(m: u64) -> Self {
        assert!(m > 1, "Montgomery modulus must be greater than one");
        assert!(m & 1 == 1, "Montgomery modulus must be odd");
        assert!(m < (1_u64 << 63), "Montgomery modulus must be below 2^63");

        Self {
            m,
            r_squared: Self::compute_r_squared(m),
            m_prime: Self::compute_m_prime(m),
            r_log: 64,
        }
    }

    fn compute_m_prime(m: u64) -> u64 {
        let mut inverse = 1_u64;
        for _ in 0..6 {
            inverse = inverse.wrapping_mul(2_u64.wrapping_sub(m.wrapping_mul(inverse)));
        }
        inverse.wrapping_neg()
    }

    fn compute_r_squared(m: u64) -> u64 {
        let r_mod_m = (1_u128 << 64) % m as u128;
        ((r_mod_m * r_mod_m) % m as u128) as u64
    }

    /// Montgomery REDC with branchless final canonicalization.
    #[inline(always)]
    pub fn redc(&self, t_lo: u64, t_hi: u64) -> u64 {
        let correction_word = t_lo.wrapping_mul(self.m_prime);
        let correction = correction_word as u128 * self.m as u128;
        let input = t_lo as u128 | (t_hi as u128) << 64;
        let reduced = (input + correction) >> 64;
        let candidate = reduced as u64;

        let difference = candidate.wrapping_sub(self.m);
        let underflow = difference >> 63;
        difference.wrapping_add(self.m & 0_u64.wrapping_sub(underflow))
    }

    /// Persistent multiplication. Inputs and output remain in Montgomery form.
    #[inline(always)]
    pub fn mul(&self, left: u64, right: u64) -> u64 {
        let product = left as u128 * right as u128;
        self.redc(product as u64, (product >> 64) as u64)
    }

    /// Persistent branchless addition.
    #[inline(always)]
    pub fn add(&self, left: u64, right: u64) -> u64 {
        let sum = left + right;
        let difference = sum.wrapping_sub(self.m);
        let underflow = difference >> 63;
        difference.wrapping_add(self.m & 0_u64.wrapping_sub(underflow))
    }

    /// Persistent branchless subtraction.
    #[inline(always)]
    pub fn sub(&self, left: u64, right: u64) -> u64 {
        let difference = left.wrapping_sub(right);
        let underflow = difference >> 63;
        difference.wrapping_add(self.m & 0_u64.wrapping_sub(underflow))
    }

    /// Persistent branchless negation.
    #[inline(always)]
    pub fn neg(&self, value: u64) -> u64 {
        let candidate = self.m.wrapping_sub(value);
        let nonzero = (value | value.wrapping_neg()) >> 63;
        candidate & 0_u64.wrapping_sub(nonzero)
    }

    #[inline(always)]
    pub fn square(&self, value: u64) -> u64 {
        self.mul(value, value)
    }

    /// Fixed-iteration Montgomery ladder.
    pub fn pow(&self, base: u64, exponent: u64) -> u64 {
        let mut lower = self.one();
        let mut upper = base;

        for bit_index in (0..64).rev() {
            let bit = (exponent >> bit_index) & 1;
            let mask = 0_u64.wrapping_sub(bit);
            let swap = (lower ^ upper) & mask;
            lower ^= swap;
            upper ^= swap;

            upper = self.mul(lower, upper);
            lower = self.square(lower);

            let swap_back = (lower ^ upper) & mask;
            lower ^= swap_back;
            upper ^= swap_back;
        }

        lower
    }

    /// Field-only Fermat inversion.
    ///
    /// Composite CLASS-R moduli are valid for persistent ring arithmetic but
    /// are rejected here because `x^(m-2)` is a field identity, not a general
    /// ring inverse algorithm. The validity branch is an explicit public API
    /// boundary and this method is not part of a secret-oblivious hot path.
    pub fn inverse(&self, value: u64) -> Option<u64> {
        if value == 0 || !is_prime(self.m) {
            None
        } else {
            Some(self.pow(value, self.m - 2))
        }
    }

    /// Enter Montgomery form at an explicit system boundary.
    #[inline]
    pub fn enter(&self, value: u64) -> u64 {
        let product = value as u128 * self.r_squared as u128;
        self.redc(product as u64, (product >> 64) as u64)
    }

    /// Leave Montgomery form at an explicit system boundary.
    #[inline]
    pub fn exit(&self, value: u64) -> u64 {
        self.redc(value, 0)
    }

    #[inline]
    pub fn from_raw_montgomery(value: u64) -> u64 {
        value
    }

    #[inline]
    pub fn zero() -> u64 {
        0
    }

    #[inline]
    pub fn one(&self) -> u64 {
        self.redc(self.r_squared, 0)
    }
}

/// Polynomial whose coefficients remain in persistent Montgomery form.
#[derive(Clone, Debug)]
pub struct PersistentPolynomial {
    pub coeffs: Vec<u64>,
    pub ctx: PersistentMontgomery,
}

impl PersistentPolynomial {
    pub fn from_montgomery(coeffs: Vec<u64>, ctx: PersistentMontgomery) -> Self {
        Self { coeffs, ctx }
    }

    pub fn zero(n: usize, ctx: PersistentMontgomery) -> Self {
        Self {
            coeffs: vec![0; n],
            ctx,
        }
    }

    pub fn add(&self, other: &Self) -> Self {
        assert_eq!(self.coeffs.len(), other.coeffs.len());
        assert_eq!(self.ctx.m, other.ctx.m);
        let coeffs = self
            .coeffs
            .iter()
            .zip(&other.coeffs)
            .map(|(left, right)| self.ctx.add(*left, *right))
            .collect();
        Self {
            coeffs,
            ctx: self.ctx.clone(),
        }
    }

    pub fn sub(&self, other: &Self) -> Self {
        assert_eq!(self.coeffs.len(), other.coeffs.len());
        assert_eq!(self.ctx.m, other.ctx.m);
        let coeffs = self
            .coeffs
            .iter()
            .zip(&other.coeffs)
            .map(|(left, right)| self.ctx.sub(*left, *right))
            .collect();
        Self {
            coeffs,
            ctx: self.ctx.clone(),
        }
    }

    pub fn scalar_mul(&self, scalar: u64) -> Self {
        let coeffs = self
            .coeffs
            .iter()
            .map(|coefficient| self.ctx.mul(*coefficient, scalar))
            .collect();
        Self {
            coeffs,
            ctx: self.ctx.clone(),
        }
    }

    pub fn pointwise_mul(&self, other: &Self) -> Self {
        assert_eq!(self.coeffs.len(), other.coeffs.len());
        assert_eq!(self.ctx.m, other.ctx.m);
        let coeffs = self
            .coeffs
            .iter()
            .zip(&other.coeffs)
            .map(|(left, right)| self.ctx.mul(*left, *right))
            .collect();
        Self {
            coeffs,
            ctx: self.ctx.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PRIME: u64 = 998_244_353;

    #[test]
    fn montgomery_roundtrip() {
        let context = PersistentMontgomery::new(TEST_PRIME);
        for value in [0, 1, 2, 12_345, 999_999, TEST_PRIME - 1] {
            assert_eq!(context.exit(context.enter(value)), value % TEST_PRIME);
        }
    }

    #[test]
    fn montgomery_multiplication() {
        let context = PersistentMontgomery::new(TEST_PRIME);
        let left = 12_345_u64;
        let right = 67_890_u64;
        let expected = (left as u128 * right as u128 % TEST_PRIME as u128) as u64;
        let actual = context.exit(context.mul(context.enter(left), context.enter(right)));
        assert_eq!(actual, expected);
    }

    #[test]
    fn persistent_chain_has_single_entry_and_exit() {
        let context = PersistentMontgomery::new(TEST_PRIME);
        let value = context.enter(100);
        let squared = context.square(value);
        let cubed = context.mul(squared, value);
        let fourth = context.mul(cubed, value);
        assert_eq!(context.exit(fourth), 100_u64.pow(4) % TEST_PRIME);
    }

    #[test]
    fn branchless_ring_ops_match_integer_reference() {
        let context = PersistentMontgomery::new(TEST_PRIME);
        let samples = [0, 1, 2, TEST_PRIME / 2, TEST_PRIME - 2, TEST_PRIME - 1];
        for &left in &samples {
            for &right in &samples {
                assert_eq!(context.add(left, right), (left + right) % TEST_PRIME);
                assert_eq!(
                    context.sub(left, right),
                    (left + TEST_PRIME - right) % TEST_PRIME
                );
            }
            let expected = if left == 0 { 0 } else { TEST_PRIME - left };
            assert_eq!(context.neg(left), expected);
        }
    }

    #[test]
    fn fixed_iteration_pow_matches_reference() {
        let context = PersistentMontgomery::new(TEST_PRIME);
        let base = 7_u64;
        for exponent in [0, 1, 2, 3, 31, 64, 255] {
            let mut expected = 1_u64;
            for _ in 0..exponent {
                expected =
                    (expected as u128 * base as u128 % TEST_PRIME as u128) as u64;
            }
            assert_eq!(context.exit(context.pow(context.enter(base), exponent)), expected);
        }
    }

    #[test]
    fn field_inverse_accepts_prime_modulus() {
        let context = PersistentMontgomery::new(TEST_PRIME);
        let value = context.enter(7);
        let inverse = context.inverse(value).expect("prime-field inverse");
        assert_eq!(context.exit(context.mul(value, inverse)), 1);
    }

    #[test]
    fn odd_composite_class_r_modulus_is_supported() {
        let modulus = 15_u64;
        let context = PersistentMontgomery::new(modulus);
        for left in 0..modulus {
            for right in 0..modulus {
                let product = context.exit(context.mul(context.enter(left), context.enter(right)));
                assert_eq!(product, left * right % modulus);
                assert_eq!(context.add(left, right), (left + right) % modulus);
                assert_eq!(context.sub(left, right), (left + modulus - right) % modulus);
            }
        }
        assert_eq!(context.inverse(context.enter(2)), None);
    }

    #[test]
    #[should_panic(expected = "Montgomery modulus must be odd")]
    fn even_modulus_is_rejected() {
        let _ = PersistentMontgomery::new(16);
    }
}
