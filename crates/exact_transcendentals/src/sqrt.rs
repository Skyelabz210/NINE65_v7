//! Integer Square Root - Exact Arithmetic
//!
//! Square root computed using ONLY integer operations.
//! No floating point anywhere - critical for QMNF's "truth cannot be approximated" philosophy.
//!
//! ## Algorithms:
//! 1. **Newton-Raphson** - Quadratic convergence, requires division
//! 2. **Digit-by-digit** - Linear but no division needed (good for hardware)
//! 3. **Binary search** - Simple, guaranteed correct, no division
//!
//! ## Key Insight:
//! For integer sqrt, we want floor(√n). Newton-Raphson with integers
//! naturally converges to this - no truncation needed!
//!
//! ## QMNF Integration:
//! - K-Elimination can make Newton division exact
//! - Rational sqrt returns (√n) as rational approximation
//! - CRTBigInt enables arbitrary precision sqrt

use crate::ExactRational;

/// Compute floor(sqrt(n)) using Newton-Raphson
/// Quadratic convergence: doubles correct digits each iteration
///
/// # Algorithm
/// x_{k+1} = (x_k + n/x_k) / 2
///
/// For integers, this converges to floor(sqrt(n)) from above
#[inline]
pub fn isqrt_newton(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    if n == 1 {
        return 1;
    }

    // Initial guess: start high to ensure convergence from above
    // Use n/2 + 1 as initial guess for small n, or bit-based for large n
    let mut x = if n < 4 {
        n
    } else {
        // sqrt(n) ≈ 2^(ceil(log2(n)/2))
        let log2 = 63 - n.leading_zeros();
        let shift = log2.div_ceil(2);
        // Start slightly high
        (1u64 << shift).max(n >> shift)
    };

    // Newton-Raphson iterations - always converges from above
    loop {
        let x_next = (x + n / x) / 2;
        if x_next >= x {
            // Converged
            break;
        }
        x = x_next;
    }

    // Final adjustment - ensure we have floor(sqrt(n))
    while x * x > n {
        x -= 1;
    }
    x
}

/// Compute floor(sqrt(n)) for 128-bit integers
#[inline]
pub fn isqrt_newton_128(n: u128) -> u128 {
    if n == 0 {
        return 0;
    }
    if n == 1 {
        return 1;
    }

    // Initial guess - start high
    let mut x = if n < 4 {
        n
    } else {
        let log2 = 127 - n.leading_zeros();
        let shift = log2.div_ceil(2);
        (1u128 << shift).max(n >> shift)
    };

    loop {
        let x_next = (x + n / x) / 2;
        if x_next >= x {
            break;
        }
        x = x_next;
    }

    while x * x > n {
        x -= 1;
    }
    x
}

/// Compute integer square root using digit-by-digit method
/// No division needed - only addition, subtraction, and shifts!
/// Linear convergence: 1 bit per iteration
#[inline]
pub fn isqrt_digit_by_digit(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }

    let mut result = 0u64;
    let mut remainder = 0u64;

    // Process 2 bits at a time, from high to low
    // 64 bits = 32 pairs
    for i in (0..32).rev() {
        // Bring down next pair of bits
        remainder = (remainder << 2) | ((n >> (i * 2)) & 3);

        // Trial subtraction
        let trial = (result << 2) | 1;

        if remainder >= trial {
            remainder -= trial;
            result = (result << 1) | 1;
        } else {
            result <<= 1;
        }
    }

    result
}

/// Binary search for integer square root
/// Simple and robust, guaranteed correct
#[inline]
pub fn isqrt_binary(n: u64) -> u64 {
    if n < 2 {
        return n;
    }

    let mut low = 1u64;
    let mut high = n.min(1u64 << 32); // sqrt(u64::MAX) < 2^32

    while low < high {
        let mid = low + (high - low).div_ceil(2);
        if mid <= n / mid {
            low = mid;
        } else {
            high = mid - 1;
        }
    }

    low
}

/// Compute sqrt as a rational approximation with specified precision
/// Returns (numerator, denominator) such that num/den ≈ sqrt(n)
/// with error < 2^(-precision_bits)
pub fn sqrt_rational(n: u64, precision_bits: u32) -> ExactRational {
    if n == 0 {
        return ExactRational::new(0, 1);
    }

    // Use continued fraction expansion of sqrt(n)
    // For sqrt(n) where n is not a perfect square:
    // sqrt(n) = a_0 + 1/(a_1 + 1/(a_2 + ...))

    // First check if n is a perfect square
    let s = isqrt_newton(n);
    if s * s == n {
        return ExactRational::new(s as i128, 1);
    }

    // Generate continued fraction convergents
    let a0 = s;
    let mut m = 0u64;
    let mut d = 1u64;
    let mut a = a0;

    // h_{-1} = 1, h_0 = a_0
    // k_{-1} = 0, k_0 = 1
    let mut h_prev = 1i128;
    let mut h_curr = a0 as i128;
    let mut k_prev = 0i128;
    let mut k_curr = 1i128;

    // Generate convergents until we have enough precision
    for _ in 0..precision_bits {
        // Compute next continued fraction coefficient
        m = d * a - m;
        d = (n - m * m) / d;
        a = (a0 + m) / d;

        // Update convergents
        let h_next = a as i128 * h_curr + h_prev;
        let k_next = a as i128 * k_curr + k_prev;

        h_prev = h_curr;
        h_curr = h_next;
        k_prev = k_curr;
        k_curr = k_next;

        // Check for overflow
        if k_curr > (1i128 << 60) {
            break;
        }
    }

    ExactRational::new(h_curr, k_curr)
}

/// High-precision sqrt using scaled integers
/// Returns sqrt(n) × 2^scale_bits
pub fn sqrt_scaled(n: u64, scale_bits: u32) -> u128 {
    if n == 0 {
        return 0;
    }

    // Compute sqrt(n × 2^(2×scale_bits)) = sqrt(n) × 2^scale_bits
    let scaled_n = (n as u128) << (2 * scale_bits);
    isqrt_newton_128(scaled_n)
}

/// Compute 1/sqrt(n) × 2^scale_bits (inverse square root)
/// Useful for normalization without division
pub fn inv_sqrt_scaled(n: u64, scale_bits: u32) -> u128 {
    if n == 0 {
        return u128::MAX;
    }

    // 1/sqrt(n) × 2^scale = 2^scale / sqrt(n)
    // = 2^(2×scale) / (sqrt(n) × 2^scale)
    let sqrt_val = sqrt_scaled(n, scale_bits);
    if sqrt_val == 0 {
        return u128::MAX;
    }

    let two_scale = 1u128 << (2 * scale_bits);
    two_scale / sqrt_val
}

/// Fast inverse sqrt (Quake-style, but with integer refinement)
/// Returns 1/sqrt(n) × 2^30
pub fn fast_inv_sqrt(n: u64) -> u64 {
    if n == 0 {
        return u64::MAX;
    }
    if n == 1 {
        return 1 << 30;
    } // 1/sqrt(1) = 1

    // Initial guess using bit manipulation
    // Based on log2(1/sqrt(n)) = -0.5 * log2(n)
    let log2 = 63 - n.leading_zeros();
    let mut y = 1u64 << (30 - log2 / 2);

    // Newton-Raphson for 1/sqrt: y_{k+1} = y_k * (3 - n*y_k²) / 2
    // With y in units of 2^30:
    //   y represents y_actual = y / 2^30
    //   y² / 2^30 represents y_actual² × 2^30
    //   n × (y² / 2^30) represents n × y_actual² × 2^30 (NO further division!)
    let scale: u128 = 1 << 30;
    let three_scale = 3u128 << 30;

    for _ in 0..8 {
        // y² scaled = y_actual² × 2^30
        let y2_scaled = (y as u128 * y as u128) / scale;
        // n × y² scaled = n × y_actual² × 2^30 (don't divide by scale again!)
        let ny2_scaled = n as u128 * y2_scaled;

        if ny2_scaled >= three_scale {
            // y is too large, reduce
            y /= 2;
            continue;
        }

        // factor = (3 - n*y²) / 2, scaled by 2^30
        // factor represents (3 - n*y_actual²) / 2 × 2^30
        let factor = (three_scale - ny2_scaled) / 2;
        let y_next = ((y as u128 * factor) / scale) as u64;

        if y_next == y || y_next == 0 {
            break;
        }
        y = y_next;
    }

    y
}

/// Check if n is a perfect square
#[inline]
pub fn is_perfect_square(n: u64) -> bool {
    let s = isqrt_newton(n);
    s * s == n
}

/// Integer cube root (bonus!)
pub fn icbrt(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    if n == 1 {
        return 1;
    }
    if n < 8 {
        return 1;
    }

    // Initial guess - start high enough
    let log2 = 63 - n.leading_zeros();
    let mut x = 1u64 << ((log2 / 3) + 1);
    x = x.max(2);

    // Newton-Raphson for cube root: x_{k+1} = (2*x_k + n/x_k²) / 3
    loop {
        let x2 = x.saturating_mul(x);
        if x2 == 0 {
            break;
        }
        let x_next = (2u64.saturating_mul(x).saturating_add(n / x2)) / 3;
        if x_next >= x {
            break;
        }
        x = x_next;
    }

    // Ensure floor - check both x and x-1
    while x > 0 && x.saturating_mul(x).saturating_mul(x) > n {
        x -= 1;
    }
    x
}

/// Arbitrary-precision integer sqrt using HCVLangBigInt.
///
/// Uses Newton-Raphson iteration with exact integer arithmetic.
#[cfg(feature = "arbitrary-precision")]
pub fn big_isqrt(n: &crate::bigint::HCVLangBigInt) -> crate::bigint::HCVLangBigInt {
    use crate::bigint::HCVLangBigInt;

    if n.is_zero() || n.is_negative() {
        return HCVLangBigInt::from(0i64);
    }

    // Initial guess: n >> (bit_length / 2)
    // For simplicity, start with n itself and converge down
    let one = HCVLangBigInt::from(1i64);
    let two = HCVLangBigInt::from(2i64);
    let mut x = n.clone();

    loop {
        // x_next = (x + n/x) / 2
        let x_next = (x.clone() + n.clone() / x.clone()) / two.clone();
        if x_next >= x {
            break;
        }
        x = x_next;
    }

    // Final correction: ensure x*x <= n < (x+1)*(x+1)
    while x.clone() * x.clone() > *n {
        x = x - one.clone();
    }

    x
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_isqrt_newton() {
        assert_eq!(isqrt_newton(0), 0);
        assert_eq!(isqrt_newton(1), 1);
        assert_eq!(isqrt_newton(4), 2);
        assert_eq!(isqrt_newton(9), 3);
        assert_eq!(isqrt_newton(10), 3);
        assert_eq!(isqrt_newton(15), 3);
        assert_eq!(isqrt_newton(16), 4);
        assert_eq!(isqrt_newton(100), 10);
        assert_eq!(isqrt_newton(u64::MAX), 4294967295); // 2^32 - 1
    }

    #[test]
    fn test_isqrt_digit_by_digit() {
        for n in [0, 1, 4, 9, 10, 15, 16, 100, 1000000] {
            assert_eq!(isqrt_digit_by_digit(n), isqrt_newton(n));
        }
    }

    #[test]
    fn test_isqrt_binary() {
        for n in [0, 1, 4, 9, 10, 15, 16, 100, 1000000] {
            assert_eq!(isqrt_binary(n), isqrt_newton(n));
        }
    }

    #[test]
    fn test_sqrt_rational() {
        // sqrt(2) ≈ 1.414...
        let rat = sqrt_rational(2, 20);
        let approx = rat.num as f64 / rat.den as f64;
        let expected = std::f64::consts::SQRT_2;
        assert!((approx - expected).abs() < 1e-6);
    }

    #[test]
    fn test_sqrt_scaled() {
        // sqrt(2) × 2^30 ≈ 1518500249
        let result = sqrt_scaled(2, 30);
        let expected = (std::f64::consts::SQRT_2 * (1u64 << 30) as f64) as u128;
        assert!((result as i128 - expected as i128).abs() < 10);
    }

    #[test]
    fn test_is_perfect_square() {
        assert!(is_perfect_square(0));
        assert!(is_perfect_square(1));
        assert!(is_perfect_square(4));
        assert!(is_perfect_square(9));
        assert!(is_perfect_square(16));
        assert!(!is_perfect_square(2));
        assert!(!is_perfect_square(3));
        assert!(!is_perfect_square(5));
    }

    #[test]
    fn test_icbrt() {
        assert_eq!(icbrt(0), 0);
        assert_eq!(icbrt(1), 1);
        assert_eq!(icbrt(8), 2);
        assert_eq!(icbrt(27), 3);
        assert_eq!(icbrt(26), 2);
        assert_eq!(icbrt(1000), 10);
    }

    #[test]
    fn test_fast_inv_sqrt() {
        // 1/sqrt(4) = 0.5
        let result = fast_inv_sqrt(4);
        let scale: u64 = 1 << 30;
        let expected = scale / 2;
        assert!((result as i64 - expected as i64).abs() < (scale / 100) as i64);
    }

    #[test]
    fn test_inv_sqrt_scaled() {
        // 1/sqrt(4) = 0.5, scaled by 2^30
        let result = inv_sqrt_scaled(4, 30);
        let expected = 1u128 << 29; // 0.5 * 2^30
        assert!((result as i128 - expected as i128).abs() < 100);
    }

    #[test]
    fn test_isqrt_newton_small_nonsquares() {
        assert_eq!(isqrt_newton(2), 1);
        assert_eq!(isqrt_newton(3), 1);
        assert_eq!(isqrt_newton(5), 2);
        assert_eq!(isqrt_newton(8), 2);
    }

    #[cfg(feature = "arbitrary-precision")]
    #[test]
    fn test_big_isqrt() {
        use super::big_isqrt;
        use crate::bigint::HCVLangBigInt;

        // sqrt(0) = 0
        let zero = HCVLangBigInt::from(0i64);
        assert!(big_isqrt(&zero).is_zero());

        // sqrt(1) = 1
        let one = HCVLangBigInt::from(1i64);
        assert_eq!(big_isqrt(&one), one);

        // sqrt(4) = 2
        let four = HCVLangBigInt::from(4i64);
        let two = HCVLangBigInt::from(2i64);
        assert_eq!(big_isqrt(&four), two);

        // sqrt(100) = 10
        let hundred = HCVLangBigInt::from(100i64);
        let ten = HCVLangBigInt::from(10i64);
        assert_eq!(big_isqrt(&hundred), ten);

        // sqrt(2^64) = 2^32
        let big = HCVLangBigInt::from(1i64) << 64;
        let expected = HCVLangBigInt::from(1i64) << 32;
        assert_eq!(big_isqrt(&big), expected);
    }
}
