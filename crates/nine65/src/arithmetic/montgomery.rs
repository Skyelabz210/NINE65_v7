//! Montgomery arithmetic for exact division-free modular multiplication.
//!
//! The core operations use fixed-width integer arithmetic and branchless
//! canonicalization. Modulus setup is public. The modulus must be odd so that
//! `R = 2^64` is invertible; primality is imposed only by CLASS-F callers.

/// Montgomery context for one odd modulus below `2^63`.
#[derive(Clone, Debug)]
pub struct MontgomeryContext {
    pub q: u64,
    pub r: u128,
    pub r2: u64,
    pub q_inv_neg: u64,
}

impl MontgomeryContext {
    pub fn new(q: u64) -> Self {
        assert!(q > 1, "Montgomery modulus must be greater than one");
        assert!(q & 1 == 1, "Montgomery modulus must be odd");
        assert!(q < (1_u64 << 63), "Montgomery modulus must be below 2^63");

        let r = 1_u128 << 64;
        Self {
            q,
            r,
            r2: Self::compute_r2(q),
            q_inv_neg: Self::compute_q_inv_neg(q),
        }
    }

    fn compute_r2(q: u64) -> u64 {
        let r_mod_q = ((1_u128 << 64) % q as u128) as u64;
        (r_mod_q as u128 * r_mod_q as u128 % q as u128) as u64
    }

    fn compute_q_inv_neg(q: u64) -> u64 {
        let mut inverse = 1_u64;
        for _ in 0..6 {
            inverse = inverse.wrapping_mul(2_u64.wrapping_sub(q.wrapping_mul(inverse)));
        }
        inverse.wrapping_neg()
    }

    #[inline(always)]
    pub fn to_montgomery(&self, value: u64) -> u64 {
        self.montgomery_mul(value, self.r2)
    }

    #[inline(always)]
    pub fn from_montgomery(&self, value: u64) -> u64 {
        self.montgomery_reduce(value as u128)
    }

    #[inline(always)]
    pub fn montgomery_mul(&self, left: u64, right: u64) -> u64 {
        self.montgomery_reduce(left as u128 * right as u128)
    }

    /// REDC with branchless final subtraction.
    #[inline(always)]
    pub fn montgomery_reduce(&self, input: u128) -> u64 {
        let low = input as u64;
        let multiplier = low.wrapping_mul(self.q_inv_neg);
        let correction = multiplier as u128 * self.q as u128;
        let reduced = (input + correction) >> 64;
        let candidate = reduced as u64;

        let difference = candidate.wrapping_sub(self.q);
        let underflow = difference >> 63;
        difference.wrapping_add(self.q & 0_u64.wrapping_sub(underflow))
    }

    #[inline(always)]
    pub fn montgomery_square(&self, value: u64) -> u64 {
        self.montgomery_mul(value, value)
    }

    /// Fixed 64-iteration Montgomery ladder.
    pub fn montgomery_pow(&self, base: u64, exponent: u64) -> u64 {
        let mut lower = self.to_montgomery(1);
        let mut upper = base;

        for bit_index in (0..64).rev() {
            let bit = (exponent >> bit_index) & 1;
            let mask = 0_u64.wrapping_sub(bit);
            let swap = (lower ^ upper) & mask;
            lower ^= swap;
            upper ^= swap;

            upper = self.montgomery_mul(lower, upper);
            lower = self.montgomery_square(lower);

            let swap_back = (lower ^ upper) & mask;
            lower ^= swap_back;
            upper ^= swap_back;
        }

        lower
    }

    /// Variable-time exponentiation for public setup values only.
    #[inline]
    pub fn montgomery_pow_vartime(&self, base: u64, exponent: u64) -> u64 {
        let mut result = self.to_montgomery(1);
        let mut base = base;
        let mut exponent = exponent;
        while exponent > 0 {
            if exponent & 1 == 1 {
                result = self.montgomery_mul(result, base);
            }
            base = self.montgomery_square(base);
            exponent >>= 1;
        }
        result
    }

    #[inline(always)]
    pub fn montgomery_add(&self, left: u64, right: u64) -> u64 {
        let sum = left + right;
        let difference = sum.wrapping_sub(self.q);
        let underflow = difference >> 63;
        difference.wrapping_add(self.q & 0_u64.wrapping_sub(underflow))
    }

    #[inline(always)]
    pub fn montgomery_sub(&self, left: u64, right: u64) -> u64 {
        let difference = left.wrapping_sub(right);
        let underflow = difference >> 63;
        difference.wrapping_add(self.q & 0_u64.wrapping_sub(underflow))
    }

    #[inline(always)]
    pub fn montgomery_neg(&self, value: u64) -> u64 {
        let candidate = self.q.wrapping_sub(value);
        let nonzero = (value | value.wrapping_neg()) >> 63;
        candidate & 0_u64.wrapping_sub(nonzero)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PRIME: u64 = 998_244_353;

    #[test]
    fn montgomery_roundtrip() {
        let context = MontgomeryContext::new(TEST_PRIME);
        for value in [0, 1, 2, 100, 12_345, TEST_PRIME - 1] {
            assert_eq!(context.from_montgomery(context.to_montgomery(value)), value);
        }
    }

    #[test]
    fn montgomery_multiplication() {
        let context = MontgomeryContext::new(TEST_PRIME);
        let left = 12_345_u64;
        let right = 67_890_u64;
        let expected = (left as u128 * right as u128 % TEST_PRIME as u128) as u64;
        let actual = context.from_montgomery(context.montgomery_mul(
            context.to_montgomery(left),
            context.to_montgomery(right),
        ));
        assert_eq!(actual, expected);
    }

    #[test]
    fn fixed_iteration_power_matches_reference() {
        let context = MontgomeryContext::new(TEST_PRIME);
        let base = 3_u64;
        for exponent in [0, 1, 2, 3, 100, 255] {
            let mut expected = 1_u64;
            for _ in 0..exponent {
                expected =
                    (expected as u128 * base as u128 % TEST_PRIME as u128) as u64;
            }
            let actual = context.from_montgomery(
                context.montgomery_pow(context.to_montgomery(base), exponent),
            );
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn coefficient_ops_match_integer_reference() {
        let context = MontgomeryContext::new(TEST_PRIME);
        let samples = [0, 1, 2, TEST_PRIME / 2, TEST_PRIME - 2, TEST_PRIME - 1];
        for &left in &samples {
            for &right in &samples {
                assert_eq!(context.montgomery_add(left, right), (left + right) % TEST_PRIME);
                assert_eq!(
                    context.montgomery_sub(left, right),
                    (left + TEST_PRIME - right) % TEST_PRIME
                );
            }
            let expected = if left == 0 { 0 } else { TEST_PRIME - left };
            assert_eq!(context.montgomery_neg(left), expected);
        }
    }

    #[test]
    fn odd_composite_class_r_modulus_is_supported() {
        let modulus = 15_u64;
        let context = MontgomeryContext::new(modulus);
        for left in 0..modulus {
            for right in 0..modulus {
                let actual = context.from_montgomery(context.montgomery_mul(
                    context.to_montgomery(left),
                    context.to_montgomery(right),
                ));
                assert_eq!(actual, left * right % modulus);
            }
        }
    }

    #[test]
    #[should_panic(expected = "Montgomery modulus must be odd")]
    fn even_modulus_is_rejected() {
        let _ = MontgomeryContext::new(16);
    }
}
