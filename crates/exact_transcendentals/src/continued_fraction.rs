//! Continued Fraction Expansions
//!
//! Every irrational number has a unique continued fraction expansion.
//! The convergents p_n/q_n give the BEST rational approximation for any
//! denominator ≤ q_n. This is mathematically optimal approximation!
//!
//! ## Key Properties:
//! - Convergents alternate above/below the true value
//! - |x - p_n/q_n| < 1/(q_n × q_{n+1}) - guaranteed error bound!
//! - For quadratic irrationals (like √2), the CF is eventually periodic
//!
//! ## Applications:
//! - √n: Periodic CF, efficient computation
//! - e: [2; 1, 2, 1, 1, 4, 1, 1, 6, ...] (beautiful pattern!)
//! - π: [3; 7, 15, 1, 292, ...] (irregular, but good approximations)
//! - Golden ratio: [1; 1, 1, 1, ...] (simplest irrational!)
//!
//! ## QMNF Integration:
//! - All operations exact integer arithmetic
//! - Convergents are ExactRational values
//! - Provable error bounds

use crate::sqrt::isqrt_newton;
use crate::ExactRational;

#[cfg(not(feature = "std"))]
use alloc::vec;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Continued fraction representation [a_0; a_1, a_2, ...]
#[derive(Clone, Debug)]
pub struct ContinuedFraction {
    /// Integer part
    pub a0: i64,
    /// Continued fraction coefficients
    pub coeffs: Vec<i64>,
    /// Whether the CF is eventually periodic (for quadratic surds)
    pub periodic_start: Option<usize>,
}

impl ContinuedFraction {
    /// Create from coefficients
    pub fn new(a0: i64, coeffs: Vec<i64>) -> Self {
        Self {
            a0,
            coeffs,
            periodic_start: None,
        }
    }

    /// Create periodic CF (for √n and other quadratic surds)
    pub fn periodic(a0: i64, period: Vec<i64>) -> Self {
        Self {
            a0,
            coeffs: period.clone(),
            periodic_start: Some(0),
        }
    }

    /// Get nth coefficient (handles periodicity)
    pub fn coeff(&self, n: usize) -> i64 {
        if n == 0 {
            return self.a0;
        }

        let idx = n - 1;
        if idx < self.coeffs.len() {
            self.coeffs[idx]
        } else if let Some(start) = self.periodic_start {
            // Periodic continuation
            let period_len = self.coeffs.len() - start;
            if period_len > 0 {
                let period_idx = (idx - start) % period_len + start;
                self.coeffs[period_idx]
            } else {
                1 // Fallback
            }
        } else {
            1 // Non-periodic, unknown beyond stored coefficients
        }
    }

    /// Compute nth convergent p_n/q_n
    pub fn convergent(&self, n: usize) -> ExactRational {
        // Recurrence: p_n = a_n × p_{n-1} + p_{n-2}
        //             q_n = a_n × q_{n-1} + q_{n-2}
        // Initial: p_{-1} = 1, p_0 = a_0
        //          q_{-1} = 0, q_0 = 1

        let mut p_prev = 1i128;
        let mut p_curr = self.a0 as i128;
        let mut q_prev = 0i128;
        let mut q_curr = 1i128;

        for i in 1..=n {
            let a = self.coeff(i) as i128;

            let p_next = a * p_curr + p_prev;
            let q_next = a * q_curr + q_prev;

            p_prev = p_curr;
            p_curr = p_next;
            q_prev = q_curr;
            q_curr = q_next;

            // Check overflow
            if p_curr.abs() > (1i128 << 100) || q_curr > (1i128 << 100) {
                break;
            }
        }

        ExactRational::new(p_curr, q_curr)
    }

    /// Get all convergents up to n
    pub fn all_convergents(&self, n: usize) -> Vec<ExactRational> {
        let mut result = Vec::with_capacity(n + 1);

        let mut p_prev = 1i128;
        let mut p_curr = self.a0 as i128;
        let mut q_prev = 0i128;
        let mut q_curr = 1i128;

        result.push(ExactRational::new(p_curr, q_curr));

        for i in 1..=n {
            let a = self.coeff(i) as i128;

            let p_next = a * p_curr + p_prev;
            let q_next = a * q_curr + q_prev;

            result.push(ExactRational::new(p_next, q_next));

            p_prev = p_curr;
            p_curr = p_next;
            q_prev = q_curr;
            q_curr = q_next;

            if p_curr.abs() > (1i128 << 100) {
                break;
            }
        }

        result
    }

    /// Error bound for nth convergent
    /// |x - p_n/q_n| < 1/(q_n × q_{n+1})
    ///
    /// Uses single-pass computation to get q_n and q_{n+1} simultaneously,
    /// avoiding the O(n) redundant recomputation of calling convergent() twice.
    pub fn error_bound(&self, n: usize) -> ExactRational {
        // Single-pass recurrence to get both q_n and q_{n+1}
        let mut p_prev = 1i128;
        let mut p_curr = self.a0 as i128;
        let mut q_prev = 0i128;
        let mut q_curr = 1i128;

        for i in 1..=n + 1 {
            let a = self.coeff(i) as i128;
            let p_next = a * p_curr + p_prev;
            let q_next = a * q_curr + q_prev;

            p_prev = p_curr;
            p_curr = p_next;
            q_prev = q_curr;
            q_curr = q_next;

            if p_curr.abs() > (1i128 << 100) || q_curr > (1i128 << 100) {
                break;
            }
        }

        // q_prev = q_n, q_curr = q_{n+1} after the loop completes
        ExactRational::new(1, q_prev * q_curr)
    }
}

/// Continued fraction for √n (quadratic surd)
/// Always eventually periodic: √n = [a_0; a_1, ..., a_k, 2a_0, a_1, ...]
pub fn sqrt_cf(n: u64) -> ContinuedFraction {
    // Check if perfect square using integer sqrt
    let a0 = isqrt_newton(n) as i64;
    if (a0 as u64) * (a0 as u64) == n {
        return ContinuedFraction::new(a0, Vec::new());
    }

    // Generate periodic part using standard algorithm
    let mut coeffs = Vec::new();
    let mut m = 0i64;
    let mut d = 1i64;
    let mut a = a0;

    // The period ends when we see 2×a0
    loop {
        m = d * a - m;
        d = ((n as i64) - m * m) / d;
        if d == 0 {
            break;
        }
        a = (a0 + m) / d;

        coeffs.push(a);

        // Period ends at 2×a0
        if a == 2 * a0 {
            break;
        }

        // Safety limit
        if coeffs.len() > 1000 {
            break;
        }
    }

    ContinuedFraction {
        a0,
        coeffs,
        periodic_start: Some(0),
    }
}

/// Continued fraction for e = [2; 1, 2, 1, 1, 4, 1, 1, 6, ...]
/// Pattern: [2; 1, 2k, 1] repeating
pub fn e_cf() -> ContinuedFraction {
    // Generate first 50 coefficients
    let mut coeffs = Vec::with_capacity(50);

    for k in 1..=17 {
        coeffs.push(1); // 1
        coeffs.push(2 * k as i64); // 2k
        coeffs.push(1); // 1
    }

    ContinuedFraction::new(2, coeffs)
}

/// Continued fraction for π
/// [3; 7, 15, 1, 292, 1, 1, 1, 2, 1, 3, 1, 14, ...]
/// (Irregular, but known to many terms)
pub fn pi_cf() -> ContinuedFraction {
    // First 20 coefficients of π's CF
    ContinuedFraction::new(
        3,
        vec![
            7, 15, 1, 292, 1, 1, 1, 2, 1, 3, 1, 14, 2, 1, 1, 2, 2, 2, 2, 1,
        ],
    )
}

/// Continued fraction for golden ratio φ = (1+√5)/2
/// φ = [1; 1, 1, 1, ...] (all ones!)
pub fn golden_ratio_cf() -> ContinuedFraction {
    ContinuedFraction::periodic(1, vec![1])
}

/// Continued fraction for ln(2)
/// [0; 1, 2, 3, 1, 6, 3, 1, 1, 2, ...]
pub fn ln2_cf() -> ContinuedFraction {
    ContinuedFraction::new(
        0,
        vec![1, 2, 3, 1, 6, 3, 1, 1, 2, 1, 1, 1, 1, 3, 10, 1, 1, 1, 2, 1],
    )
}

/// Generalized continued fraction for tan(x)
/// tan(x) = x / (1 - x²/(3 - x²/(5 - ...)))
pub fn tan_gcf(x_num: i128, x_den: i128, terms: usize) -> ExactRational {
    // Evaluate from the bottom up
    let x_squared = ExactRational::new(x_num * x_num, x_den * x_den);

    // Start with the deepest term
    let mut result = ExactRational::from_int(2 * terms as i128 + 1);

    // Work backwards
    for k in (1..terms).rev() {
        let odd = 2 * k as i128 + 1;

        // result = odd - x²/result
        let x2_over_result = x_squared.div(&result);
        result = ExactRational::from_int(odd).sub(&x2_over_result);
    }

    // Final: x / (1 - x²/result)
    let denom = ExactRational::from_int(1).sub(&x_squared.div(&result));
    ExactRational::new(x_num, x_den).div(&denom)
}

/// Best rational approximation to √2 with denominator ≤ max_denom
pub fn best_sqrt2_approx(max_denom: i128) -> ExactRational {
    let cf = sqrt_cf(2);

    let mut best = cf.convergent(0);
    for n in 1..100 {
        let conv = cf.convergent(n);
        if conv.den > max_denom {
            break;
        }
        best = conv;
    }

    best
}

/// Pell equation solver: find smallest x, y where x² - n×y² = 1
/// Uses continued fraction of √n
pub fn pell_fundamental(n: u64) -> Option<(i128, i128)> {
    // Check if n is a perfect square (no solution)
    let sqrt_n = isqrt_newton(n);
    if sqrt_n * sqrt_n == n {
        return None;
    }

    let cf = sqrt_cf(n);

    // The fundamental solution comes from the convergent at the end of the period
    let period_len = cf.coeffs.len();
    if period_len == 0 {
        return None;
    }

    // For Pell equation, solution is at convergent p_{r-1}/q_{r-1}
    // where r is the period length
    // If r is odd, use p_{2r-1}/q_{2r-1}
    let conv_idx = if period_len.is_multiple_of(2) {
        period_len - 1
    } else {
        2 * period_len - 1
    };

    let conv = cf.convergent(conv_idx);

    // Verify: x² - n×y² should equal 1
    let x = conv.num;
    let y = conv.den;
    let check = x * x - (n as i128) * y * y;

    if check == 1 {
        Some((x, y))
    } else if check == -1 {
        // Need to double the solution
        let x2 = x * x + (n as i128) * y * y;
        let y2 = 2 * x * y;
        Some((x2, y2))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqrt2_cf() {
        let cf = sqrt_cf(2);
        assert_eq!(cf.a0, 1);
        assert_eq!(cf.coeffs[0], 2);

        // First convergents of √2: 1, 3/2, 7/5, 17/12, 41/29, ...
        let c0 = cf.convergent(0);
        assert_eq!(c0.num, 1);
        assert_eq!(c0.den, 1);

        let c1 = cf.convergent(1);
        assert_eq!(c1.num, 3);
        assert_eq!(c1.den, 2);

        let c2 = cf.convergent(2);
        assert_eq!(c2.num, 7);
        assert_eq!(c2.den, 5);

        let c3 = cf.convergent(3);
        assert_eq!(c3.num, 17);
        assert_eq!(c3.den, 12);
    }

    #[test]
    fn test_golden_ratio() {
        let cf = golden_ratio_cf();

        // Convergents are Fibonacci ratios: 1/1, 2/1, 3/2, 5/3, 8/5, ...
        let c0 = cf.convergent(0);
        assert_eq!(c0.num, 1);
        assert_eq!(c0.den, 1);

        let c1 = cf.convergent(1);
        assert_eq!(c1.num, 2);
        assert_eq!(c1.den, 1);

        let c2 = cf.convergent(2);
        assert_eq!(c2.num, 3);
        assert_eq!(c2.den, 2);

        let c5 = cf.convergent(5);
        assert_eq!(c5.num, 13);
        assert_eq!(c5.den, 8);
    }

    #[test]
    fn test_e_cf_convergence() {
        let cf = e_cf();

        // e ≈ 2.718281828...
        // Check convergents approach e
        for n in [5, 10, 15] {
            let conv = cf.convergent(n);
            let approx = conv.num as f64 / conv.den as f64;
            println!("e convergent {}: {}/{} ≈ {}", n, conv.num, conv.den, approx);
            assert!((approx - std::f64::consts::E).abs() < 0.1 / (n as f64));
        }
    }

    #[test]
    fn test_pi_cf() {
        let cf = pi_cf();

        // Famous approximation: 22/7
        let c1 = cf.convergent(1);
        assert_eq!(c1.num, 22);
        assert_eq!(c1.den, 7);

        // Better: 333/106
        let c2 = cf.convergent(2);
        assert_eq!(c2.num, 333);
        assert_eq!(c2.den, 106);

        // Even better: 355/113 (祖冲之, Zu Chongzhi's approximation)
        let c3 = cf.convergent(3);
        assert_eq!(c3.num, 355);
        assert_eq!(c3.den, 113);
    }

    #[test]
    fn test_pell_equation() {
        // x² - 2y² = 1: fundamental solution is (3, 2)
        let sol = pell_fundamental(2);
        assert!(sol.is_some());
        let (x, y) = sol.unwrap();
        assert_eq!(x * x - 2 * y * y, 1);

        // x² - 5y² = 1: fundamental solution is (9, 4)
        let sol = pell_fundamental(5);
        assert!(sol.is_some());
        let (x, y) = sol.unwrap();
        assert_eq!(x * x - 5 * y * y, 1);
    }

    #[test]
    fn test_best_sqrt2() {
        let approx = best_sqrt2_approx(1000);

        // Best approximation with denom ≤ 1000 should be 1393/985
        // Actually 577/408 with error ~8e-7
        println!("Best √2 ≈ {}/{}", approx.num, approx.den);

        let value = approx.num as f64 / approx.den as f64;
        assert!((value - std::f64::consts::SQRT_2).abs() < 1e-5);
    }

    // ================================================================
    // GAP-02: error_bound() correctness after EX-08 single-pass rewrite
    // ================================================================

    /// Verify error_bound gives same result as manual two-convergent computation.
    /// This confirms the single-pass rewrite (EX-08) didn't break semantics.
    #[test]
    fn test_error_bound_consistency() {
        let cf = sqrt_cf(2);

        for n in 0..5 {
            let bound = cf.error_bound(n);

            // Manual computation: 1 / (q_n × q_{n+1})
            let c_n = cf.convergent(n);
            let c_n1 = cf.convergent(n + 1);
            let expected_den = c_n.den * c_n1.den;

            assert_eq!(
                bound.num, 1,
                "error_bound numerator should be 1 for convergent {}",
                n
            );
            assert_eq!(
                bound.den, expected_den,
                "error_bound denominator mismatch at convergent {}: got {}, expected {}",
                n, bound.den, expected_den
            );
        }
    }

    /// Verify error bounds decrease monotonically (better approximation → tighter bound).
    #[test]
    fn test_error_bound_monotone_decrease() {
        let cf = sqrt_cf(3);

        let mut prev_den = 0i128;
        for n in 0..6 {
            let bound = cf.error_bound(n);
            // Larger denominator = smaller error bound
            assert!(
                bound.den > prev_den,
                "error_bound should decrease: bound({}).den={} ≤ prev={}",
                n,
                bound.den,
                prev_den
            );
            prev_den = bound.den;
        }
    }

    /// Verify actual approximation error is within the theoretical bound.
    #[test]
    fn test_error_bound_is_valid() {
        let cf = sqrt_cf(2);
        let sqrt2 = std::f64::consts::SQRT_2;

        for n in 0..5 {
            let conv = cf.convergent(n);
            let bound = cf.error_bound(n);

            let approx = conv.num as f64 / conv.den as f64;
            let actual_error = (approx - sqrt2).abs();
            let bound_value = 1.0 / bound.den as f64;

            assert!(
                actual_error < bound_value,
                "Actual error {:.2e} exceeds theoretical bound {:.2e} at convergent {}",
                actual_error,
                bound_value,
                n
            );
        }
    }
}
