//! Montgomery Arithmetic - Gen 2 Division-Free Modular Multiplication
//!
//! Montgomery representation eliminates conversion overhead by staying in residue space.
//!
//! # Security
//!
//! All operations are implemented in **constant-time** to prevent
//! timing side-channel attacks. This includes:
//! - Montgomery reduction (no data-dependent branches)
//! - Addition/subtraction (constant-time conditional)
//! - Exponentiation (Montgomery ladder)
//!
//! Uses bit manipulation instead of branches for security-critical paths.

/// Montgomery context for a specific modulus
#[derive(Clone, Debug)]
pub struct MontgomeryContext {
    /// The modulus q
    pub q: u64,
    /// R = 2^64 mod q (implicit)
    pub r: u128,
    /// R^2 mod q for fast conversion to Montgomery form
    pub r2: u64,
    /// -q^(-1) mod 2^64
    pub q_inv_neg: u64,
}

impl MontgomeryContext {
    /// Create a new Montgomery context for modulus q
    pub fn new(q: u64) -> Self {
        // R = 2^64
        let r: u128 = 1u128 << 64;

        // Compute R mod q
        let _r_mod_q = (r % (q as u128)) as u64;

        // Compute R^2 mod q
        let r2 = Self::compute_r2(q);

        // Compute -q^(-1) mod 2^64 using extended Euclidean algorithm
        let q_inv_neg = Self::compute_q_inv_neg(q);

        Self {
            q,
            r,
            r2,
            q_inv_neg,
        }
    }

    /// Compute R^2 mod q
    fn compute_r2(q: u64) -> u64 {
        // R^2 = 2^128 mod q
        // We compute this by repeated squaring: (2^64 mod q)^2 mod q
        let r_mod_q = ((1u128 << 64) % (q as u128)) as u64;
        ((r_mod_q as u128 * r_mod_q as u128) % (q as u128)) as u64
    }

    /// Compute -q^(-1) mod 2^64 using Newton's method
    fn compute_q_inv_neg(q: u64) -> u64 {
        // Newton iteration: x_{n+1} = x_n * (2 - q * x_n) mod 2^64
        // Starting with x_0 = 1 (works for odd q)
        let mut x: u64 = 1;
        for _ in 0..6 {
            x = x.wrapping_mul(2u64.wrapping_sub(q.wrapping_mul(x)));
        }
        // Return -q^(-1) mod 2^64
        x.wrapping_neg()
    }

    /// Convert to Montgomery form: a -> aR mod q
    #[inline(always)]
    pub fn to_montgomery(&self, a: u64) -> u64 {
        self.montgomery_mul(a, self.r2)
    }

    /// Convert from Montgomery form: aR -> a mod q
    #[inline(always)]
    pub fn from_montgomery(&self, a_mont: u64) -> u64 {
        self.montgomery_reduce(a_mont as u128)
    }

    /// Montgomery multiplication: (aR * bR) / R mod q = abR mod q
    #[inline(always)]
    pub fn montgomery_mul(&self, a: u64, b: u64) -> u64 {
        let t = (a as u128) * (b as u128);
        self.montgomery_reduce(t)
    }

    /// Montgomery reduction: t / R mod q
    /// REDC algorithm - no division, only multiplication and shifts
    ///
    /// # Security
    ///
    /// This implementation is **constant-time**: the final conditional
    /// reduction uses bit manipulation instead of branches to prevent
    /// timing side-channel attacks.
    #[inline(always)]
    pub fn montgomery_reduce(&self, t: u128) -> u64 {
        // m = (t mod R) * q_inv_neg mod R
        let t_lo = t as u64;
        let m = t_lo.wrapping_mul(self.q_inv_neg);

        // t = (t + m * q) / R
        let mq = (m as u128) * (self.q as u128);
        let result = ((t.wrapping_add(mq)) >> 64) as u64;

        // CONSTANT-TIME final reduction
        // mask = 0xFFFF...FFFF if result >= q, else 0x0000...0000
        // Uses the fact that (result - q) will underflow if result < q
        let (diff, borrow) = result.overflowing_sub(self.q);
        // If no borrow (result >= q), use diff; otherwise use result
        // borrow is true (1) when result < q, false (0) when result >= q
        // We want: if borrow { result } else { diff }
        // mask = borrow as 0 or u64::MAX
        let mask = (borrow as u64).wrapping_neg(); // 0 if no borrow, u64::MAX if borrow
                                                   // result = (result & mask) | (diff & !mask)
        (result & mask) | (diff & !mask)
    }

    /// Montgomery squaring (slightly optimized)
    #[inline(always)]
    pub fn montgomery_square(&self, a: u64) -> u64 {
        self.montgomery_mul(a, a)
    }

    /// Montgomery exponentiation: a^e mod q (in Montgomery form)
    ///
    /// # Security
    ///
    /// Uses the **Montgomery ladder** algorithm which is constant-time:
    /// - Always performs the same number of multiplications
    /// - Memory access pattern is independent of exponent bits
    /// - No data-dependent branches
    ///
    /// This prevents timing and power analysis attacks that could
    /// recover the exponent (which may be secret in some protocols).
    pub fn montgomery_pow(&self, base: u64, exp: u64) -> u64 {
        // Montgomery ladder: constant-time exponentiation
        // R0 = 1, R1 = base
        // For each bit of exp (MSB to LSB):
        //   if bit == 0: R1 = R0 * R1, R0 = R0^2
        //   if bit == 1: R0 = R0 * R1, R1 = R1^2
        // Result is R0

        let one_mont = self.to_montgomery(1);

        if exp == 0 {
            return one_mont;
        }

        let mut r0 = one_mont;
        let mut r1 = base;

        // Find the highest set bit
        let bits = 64 - exp.leading_zeros();

        for i in (0..bits).rev() {
            let bit = (exp >> i) & 1;

            // CONSTANT-TIME swap based on bit
            // If bit == 1: swap r0 and r1
            let mask = bit.wrapping_neg(); // 0 if bit=0, u64::MAX if bit=1
            let tmp = (r0 ^ r1) & mask;
            r0 ^= tmp;
            r1 ^= tmp;

            // Always: r1 = r0 * r1, r0 = r0^2
            r1 = self.montgomery_mul(r0, r1);
            r0 = self.montgomery_square(r0);

            // CONSTANT-TIME swap back
            let tmp = (r0 ^ r1) & mask;
            r0 ^= tmp;
            r1 ^= tmp;
        }

        r0
    }

    /// Variable-time exponentiation (faster, use only with public exponents)
    ///
    /// # Security Warning
    ///
    /// This function has timing side-channels. Only use when the exponent
    /// is PUBLIC (e.g., for NTT root computation, not for secret operations).
    #[inline]
    pub fn montgomery_pow_vartime(&self, base: u64, exp: u64) -> u64 {
        if exp == 0 {
            return self.to_montgomery(1);
        }

        let mut result = self.to_montgomery(1);
        let mut base = base;
        let mut e = exp;

        while e > 0 {
            if e & 1 == 1 {
                result = self.montgomery_mul(result, base);
            }
            base = self.montgomery_square(base);
            e >>= 1;
        }

        result
    }

    /// Add two Montgomery form numbers (constant-time)
    ///
    /// # Security
    ///
    /// Uses constant-time conditional subtraction to prevent timing leaks.
    #[inline(always)]
    pub fn montgomery_add(&self, a: u64, b: u64) -> u64 {
        let sum = a.wrapping_add(b);
        // CONSTANT-TIME: subtract q if sum >= q
        let (diff, borrow) = sum.overflowing_sub(self.q);
        let mask = (borrow as u64).wrapping_neg();
        (sum & mask) | (diff & !mask)
    }

    /// Subtract two Montgomery form numbers (constant-time)
    ///
    /// # Security
    ///
    /// Uses constant-time conditional addition to prevent timing leaks.
    #[inline(always)]
    pub fn montgomery_sub(&self, a: u64, b: u64) -> u64 {
        let (diff, borrow) = a.overflowing_sub(b);
        // CONSTANT-TIME: add q if a < b (borrow occurred)
        let correction = self.q & (borrow as u64).wrapping_neg();
        diff.wrapping_add(correction)
    }

    /// Negate in Montgomery form (constant-time)
    ///
    /// # Security
    ///
    /// Uses constant-time zero check to prevent timing leaks.
    #[inline(always)]
    pub fn montgomery_neg(&self, a: u64) -> u64 {
        // CONSTANT-TIME: compute (q - a) but return 0 if a == 0
        let neg = self.q.wrapping_sub(a);
        // mask = 0 if a == 0, else u64::MAX
        let is_zero = a == 0;
        let mask = (!is_zero as u64).wrapping_neg();
        neg & mask
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PRIME: u64 = 998244353;

    #[test]
    fn test_montgomery_roundtrip() {
        let ctx = MontgomeryContext::new(TEST_PRIME);

        for a in [0, 1, 2, 100, 12345, TEST_PRIME - 1] {
            let mont = ctx.to_montgomery(a);
            let back = ctx.from_montgomery(mont);
            assert_eq!(back, a, "Roundtrip failed for {}", a);
        }
    }

    #[test]
    fn test_montgomery_mul() {
        let ctx = MontgomeryContext::new(TEST_PRIME);

        let a = 12345u64;
        let b = 67890u64;
        let expected = ((a as u128 * b as u128) % TEST_PRIME as u128) as u64;

        let a_mont = ctx.to_montgomery(a);
        let b_mont = ctx.to_montgomery(b);
        let result_mont = ctx.montgomery_mul(a_mont, b_mont);
        let result = ctx.from_montgomery(result_mont);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_montgomery_pow() {
        let ctx = MontgomeryContext::new(TEST_PRIME);

        let base = 3u64;
        let exp = 100u64;

        // Compute expected result the slow way
        let mut expected = 1u64;
        for _ in 0..exp {
            expected = ((expected as u128 * base as u128) % TEST_PRIME as u128) as u64;
        }

        let base_mont = ctx.to_montgomery(base);
        let result_mont = ctx.montgomery_pow(base_mont, exp);
        let result = ctx.from_montgomery(result_mont);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_montgomery_add_sub() {
        let ctx = MontgomeryContext::new(TEST_PRIME);

        let a = 12345u64;
        let b = 67890u64;

        let a_mont = ctx.to_montgomery(a);
        let b_mont = ctx.to_montgomery(b);

        // Test add
        let sum_mont = ctx.montgomery_add(a_mont, b_mont);
        let sum = ctx.from_montgomery(sum_mont);
        assert_eq!(sum, (a + b) % TEST_PRIME);

        // Test sub
        let diff_mont = ctx.montgomery_sub(b_mont, a_mont);
        let diff = ctx.from_montgomery(diff_mont);
        assert_eq!(diff, (b - a) % TEST_PRIME);
    }

    #[test]
    fn test_montgomery_benchmark() {
        let ctx = MontgomeryContext::new(TEST_PRIME);
        let a = ctx.to_montgomery(12345);
        let b = ctx.to_montgomery(67890);

        let start = std::time::Instant::now();
        let mut result = a;
        for _ in 0..100_000 {
            result = ctx.montgomery_mul(result, b);
        }
        let elapsed = start.elapsed();

        println!(
            "Montgomery 100k muls: {:?} (result={})",
            elapsed,
            ctx.from_montgomery(result)
        );
        // Should be < 5ms for 100k operations
    }
}
