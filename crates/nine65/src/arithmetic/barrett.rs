//! Barrett Reduction - One-Cycle Modular Reduction
//!
//! Complements Montgomery for isolated reductions where conversion
//! overhead isn't amortized across multiple operations.

/// Barrett reduction context
#[derive(Clone, Debug)]
pub struct BarrettContext {
    /// The modulus q
    pub q: u64,
    /// Precomputed: floor(2^128 / q)
    pub mu: u128,
    /// Bit shift amount
    pub k: u32,
}

impl BarrettContext {
    /// Create a new Barrett context for modulus q
    pub fn new(q: u64) -> Self {
        // k = 2 * bits(q)
        let k = 128u32;

        // mu = floor(2^k / q)
        // For k=128, we compute this carefully to avoid overflow
        let mu = Self::compute_mu(q);

        Self { q, mu, k }
    }

    /// Compute mu = floor(2^128 / q)
    fn compute_mu(q: u64) -> u128 {
        // 2^128 / q = (2^64 / q) * 2^64 + remainder handling
        // We use the division algorithm carefully
        let q128 = q as u128;

        // Compute 2^128 / q by long division
        // 2^128 = q * quotient + remainder
        // quotient = 2^128 / q

        // Split: 2^128 = 2^64 * 2^64
        // First divide 2^64 by q, get quotient q1 and remainder r1
        // Then 2^128 / q = (2^64 * 2^64) / q

        // For exact computation, we use the fact that
        // 2^128 = (2^127 + 2^127)
        let half = 1u128 << 127;
        let q1 = half / q128;
        let r1 = half % q128;

        // 2^128 / q = 2 * (2^127 / q) + (2 * r1) / q
        let extra = (2 * r1) / q128;

        2 * q1 + extra
    }

    /// Barrett reduction: a mod q for a < q^2
    #[inline(always)]
    pub fn reduce(&self, a: u128) -> u64 {
        if a < self.q as u128 {
            return a as u64;
        }

        // q_hat = floor(a * mu / 2^128)
        // We approximate floor(a / q) using this
        let q_hat = self.mul_high(a, self.mu);

        // r = a - q_hat * q
        let r = a.wrapping_sub(q_hat.wrapping_mul(self.q as u128));

        // Final correction (at most 2 subtractions needed)
        let mut result = r as u64;
        if result >= self.q {
            result -= self.q;
        }
        if result >= self.q {
            result -= self.q;
        }

        result
    }

    /// Compute high 128 bits of a * b where both are 128-bit
    #[inline(always)]
    fn mul_high(&self, a: u128, b: u128) -> u128 {
        // Split into 64-bit parts
        let a_lo = a as u64 as u128;
        let a_hi = (a >> 64) as u64 as u128;
        let b_lo = b as u64 as u128;
        let b_hi = (b >> 64) as u64 as u128;

        // Compute partial products
        let p0 = a_lo * b_lo;
        let p1 = a_lo * b_hi;
        let p2 = a_hi * b_lo;
        let p3 = a_hi * b_hi;

        // Combine for high bits
        // result_high = p3 + high(p1) + high(p2) + carry from (low(p1) + low(p2) + high(p0))
        let mid = (p0 >> 64) + (p1 as u64 as u128) + (p2 as u64 as u128);
        let carry = mid >> 64;

        p3 + (p1 >> 64) + (p2 >> 64) + carry
    }

    /// Modular multiplication using Barrett
    #[inline(always)]
    pub fn mul(&self, a: u64, b: u64) -> u64 {
        let product = (a as u128) * (b as u128);
        self.reduce(product)
    }

    /// Modular multiplication using Barrett (constant-time)
    #[inline(always)]
    pub fn mul_ct(&self, a: u64, b: u64) -> u64 {
        let product = (a as u128) * (b as u128);
        self.reduce_ct(product)
    }

    /// Constant-time Barrett reduction: a mod q for a < q^2
    ///
    /// Uses bit manipulation instead of branches to prevent timing side-channels.
    /// This is critical when reducing values derived from secret data.
    #[inline(always)]
    pub fn reduce_ct(&self, a: u128) -> u64 {
        // q_hat = floor(a * mu / 2^128)
        let q_hat = self.mul_high(a, self.mu);

        // r = a - q_hat * q
        let r = a.wrapping_sub(q_hat.wrapping_mul(self.q as u128));

        // At most 2 corrections needed. Use constant-time conditional subtraction.
        let mut result = r as u64;

        // First correction: result = result - q if result >= q
        let mask1 = ((result >= self.q) as u64).wrapping_neg(); // 0 or u64::MAX
        result = result.wrapping_sub(self.q & mask1);

        // Second correction (rare but possible)
        let mask2 = ((result >= self.q) as u64).wrapping_neg();
        result = result.wrapping_sub(self.q & mask2);

        result
    }

    /// Modular addition
    #[inline(always)]
    pub fn add(&self, a: u64, b: u64) -> u64 {
        let sum = a as u128 + b as u128;
        if sum >= self.q as u128 {
            (sum - self.q as u128) as u64
        } else {
            sum as u64
        }
    }

    /// Constant-time modular addition
    #[inline(always)]
    pub fn add_ct(&self, a: u64, b: u64) -> u64 {
        let sum = a.wrapping_add(b);
        // If sum >= q or sum < a (overflow), subtract q
        let overflow = (sum < a) as u64;
        let geq = (sum >= self.q) as u64;
        let mask = (overflow | geq).wrapping_neg();
        sum.wrapping_sub(self.q & mask)
    }

    /// Modular subtraction
    #[inline(always)]
    pub fn sub(&self, a: u64, b: u64) -> u64 {
        if a >= b {
            a - b
        } else {
            self.q - b + a
        }
    }

    /// Constant-time modular subtraction
    #[inline(always)]
    pub fn sub_ct(&self, a: u64, b: u64) -> u64 {
        let diff = a.wrapping_sub(b);
        // If a < b (borrow occurred), add q
        let borrow = (a < b) as u64;
        let mask = borrow.wrapping_neg();
        diff.wrapping_add(self.q & mask)
    }

    /// Modular exponentiation
    pub fn pow(&self, base: u64, exp: u64) -> u64 {
        if exp == 0 {
            return 1;
        }

        let mut result = 1u64;
        let mut base = base;
        let mut e = exp;

        while e > 0 {
            if e & 1 == 1 {
                result = self.mul(result, base);
            }
            base = self.mul(base, base);
            e >>= 1;
        }

        result
    }
}

/// Hybrid context that uses both Montgomery and Barrett optimally
#[derive(Clone, Debug)]
pub struct HybridModContext {
    pub mont: super::montgomery::MontgomeryContext,
    pub barrett: BarrettContext,
}

impl HybridModContext {
    pub fn new(q: u64) -> Self {
        Self {
            mont: super::montgomery::MontgomeryContext::new(q),
            barrett: BarrettContext::new(q),
        }
    }

    /// Use Barrett for isolated reductions
    #[inline(always)]
    pub fn reduce(&self, a: u128) -> u64 {
        self.barrett.reduce(a)
    }

    /// Use Montgomery for repeated multiplications
    #[inline(always)]
    pub fn persistent_mul(&self, a_mont: u64, b_mont: u64) -> u64 {
        self.mont.montgomery_mul(a_mont, b_mont)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PRIME: u64 = 998244353;

    #[test]
    fn test_barrett_reduce() {
        let ctx = BarrettContext::new(TEST_PRIME);

        // Test various values
        for a in [
            0u128,
            1,
            100,
            12345,
            TEST_PRIME as u128 - 1,
            TEST_PRIME as u128,
            TEST_PRIME as u128 + 1,
        ] {
            let result = ctx.reduce(a);
            let expected = (a % TEST_PRIME as u128) as u64;
            assert_eq!(result, expected, "Barrett reduce failed for {}", a);
        }
    }

    #[test]
    fn test_barrett_reduce_large() {
        let ctx = BarrettContext::new(TEST_PRIME);

        // Test large values near q^2
        let large = (TEST_PRIME as u128 - 1) * (TEST_PRIME as u128 - 1);
        let result = ctx.reduce(large);
        let expected = (large % TEST_PRIME as u128) as u64;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_barrett_mul() {
        let ctx = BarrettContext::new(TEST_PRIME);

        let a = 12345u64;
        let b = 67890u64;
        let expected = ((a as u128 * b as u128) % TEST_PRIME as u128) as u64;

        let result = ctx.mul(a, b);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_barrett_pow() {
        let ctx = BarrettContext::new(TEST_PRIME);

        let base = 7u64;
        let exp = 11u64;

        // Expected: 7^11 mod q
        let mut expected = 1u64;
        for _ in 0..exp {
            expected = ((expected as u128 * base as u128) % TEST_PRIME as u128) as u64;
        }

        let result = ctx.pow(base, exp);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_barrett_vs_naive() {
        let ctx = BarrettContext::new(TEST_PRIME);

        for i in 0..1000 {
            let a = (i * 12345) % TEST_PRIME;
            let b = (i * 67890) % TEST_PRIME;

            let naive = ((a as u128 * b as u128) % TEST_PRIME as u128) as u64;
            let barrett = ctx.mul(a, b);

            assert_eq!(barrett, naive, "Mismatch at i={}", i);
        }
    }

    #[test]
    fn test_hybrid_context() {
        let ctx = HybridModContext::new(TEST_PRIME);

        let a = 12345u64;
        let b = 67890u64;

        // Test Barrett path
        let product = (a as u128) * (b as u128);
        let result = ctx.reduce(product);
        let expected = ((a as u128 * b as u128) % TEST_PRIME as u128) as u64;
        assert_eq!(result, expected);

        // Test Montgomery path
        let a_mont = ctx.mont.to_montgomery(a);
        let b_mont = ctx.mont.to_montgomery(b);
        let result_mont = ctx.persistent_mul(a_mont, b_mont);
        let result2 = ctx.mont.from_montgomery(result_mont);
        assert_eq!(result2, expected);
    }

    #[test]
    fn test_barrett_benchmark() {
        let ctx = BarrettContext::new(TEST_PRIME);

        let start = std::time::Instant::now();
        let mut sum = 0u64;
        for i in 0..100_000u64 {
            sum = ctx.reduce((sum as u128 + i as u128) * 12345);
        }
        let elapsed = start.elapsed();

        println!("Barrett 100k reductions: {:?} (sum={})", elapsed, sum);
    }

    #[test]
    fn test_barrett_reduce_ct() {
        let ctx = BarrettContext::new(TEST_PRIME);

        // Test various values - CT variant should match regular reduce
        for a in [
            0u128,
            1,
            100,
            12345,
            TEST_PRIME as u128 - 1,
            TEST_PRIME as u128,
            TEST_PRIME as u128 + 1,
        ] {
            let result_ct = ctx.reduce_ct(a);
            let result_vt = ctx.reduce(a);
            assert_eq!(result_ct, result_vt, "CT reduce mismatch for {}", a);
        }

        // Test large values near q^2
        let large = (TEST_PRIME as u128 - 1) * (TEST_PRIME as u128 - 1);
        let result_ct = ctx.reduce_ct(large);
        let expected = (large % TEST_PRIME as u128) as u64;
        assert_eq!(result_ct, expected);
    }

    #[test]
    fn test_barrett_add_ct() {
        let ctx = BarrettContext::new(TEST_PRIME);

        // Test normal additions
        for (a, b) in [
            (0, 0),
            (1, 1),
            (100, 200),
            (TEST_PRIME - 1, 1),
            (TEST_PRIME - 1, TEST_PRIME - 1),
        ] {
            let result_ct = ctx.add_ct(a, b);
            let result_vt = ctx.add(a, b);
            assert_eq!(result_ct, result_vt, "CT add mismatch for {} + {}", a, b);
        }
    }

    #[test]
    fn test_barrett_sub_ct() {
        let ctx = BarrettContext::new(TEST_PRIME);

        // Test normal subtractions
        for (a, b) in [
            (0, 0),
            (100, 50),
            (50, 100),
            (TEST_PRIME - 1, 0),
            (0, TEST_PRIME - 1),
        ] {
            let result_ct = ctx.sub_ct(a, b);
            let result_vt = ctx.sub(a, b);
            assert_eq!(result_ct, result_vt, "CT sub mismatch for {} - {}", a, b);
        }
    }

    #[test]
    fn test_barrett_mul_ct() {
        let ctx = BarrettContext::new(TEST_PRIME);

        for i in 0..1000 {
            let a = (i * 12345) % TEST_PRIME;
            let b = (i * 67890) % TEST_PRIME;

            let result_ct = ctx.mul_ct(a, b);
            let result_vt = ctx.mul(a, b);

            assert_eq!(result_ct, result_vt, "CT mul mismatch at i={}", i);
        }
    }

    // Timing regression tests moved to criterion benches (benches/timing.rs)
}
