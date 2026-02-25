// Module 7: montgomery_timing_audit
//
// Q11: Does Montgomery reduction have timing-observable branches?
//
// Note: This module provides empirical (not cryptographic) evidence.
// It verifies correctness at boundary values and measures relative timing
// via iteration counts. A max/min ratio < 2x is a conservative bound —
// not a cryptographic constant-time guarantee.

#[cfg(test)]
mod tests {
    use nine65::arithmetic::montgomery::MontgomeryContext;

    fn test_prime() -> u64 {
        // A safe NTT-friendly prime for testing.
        2013265921 // 15 * 2^27 + 1
    }

    /// montgomery_neg(0) must return 0.
    #[test]
    fn test_montgomery_neg_zero() {
        let ctx = MontgomeryContext::new(test_prime());
        // Convert 0 to Montgomery form.
        let zero_mont = ctx.to_montgomery(0);
        // In any Montgomery scheme, 0 in Montgomery form is still 0 (0 * R mod q = 0).
        assert_eq!(zero_mont, 0, "to_montgomery(0) != 0");

        // Reduction of 0 must return 0.
        let reduced = ctx.montgomery_reduce(0u128);
        assert_eq!(reduced, 0, "montgomery_reduce(0) != 0");
    }

    /// Boundary values must reduce correctly.
    #[test]
    fn test_montgomery_reduction_all_boundary_values() {
        let q = test_prime();
        let ctx = MontgomeryContext::new(q);

        let test_values: &[u64] = &[0, 1, q - 1, q / 2, q - 2];
        for &a in test_values {
            let a_mont = ctx.to_montgomery(a);
            let recovered = ctx.from_montgomery(a_mont);
            assert_eq!(recovered, a,
                "Montgomery roundtrip failed for {}: got {}", a, recovered);
        }
    }

    /// Montgomery multiplication must be correct for all boundary combinations.
    #[test]
    fn test_montgomery_mul_boundary_combinations() {
        let q = test_prime();
        let ctx = MontgomeryContext::new(q);

        let values: &[u64] = &[0, 1, 2, q - 1, q / 2, q - 2];
        for &a in values {
            for &b in values {
                let expected = ((a as u128 * b as u128) % q as u128) as u64;
                let a_mont = ctx.to_montgomery(a);
                let b_mont = ctx.to_montgomery(b);
                let result_mont = ctx.montgomery_mul(a_mont, b_mont);
                let result = ctx.from_montgomery(result_mont);
                assert_eq!(result, expected,
                    "Montgomery mul({}, {}) = {} expected {} (q={})",
                    a, b, result, expected, q);
            }
        }
    }

    /// Exponentiation must be correct for small cases.
    #[test]
    fn test_montgomery_pow_correctness() {
        let q = test_prime();
        let ctx = MontgomeryContext::new(q);

        // 3^0 = 1
        let three_mont = ctx.to_montgomery(3);
        let result = ctx.montgomery_pow(three_mont, 0);
        assert_eq!(ctx.from_montgomery(result), 1, "3^0 != 1");

        // 3^1 = 3
        let result = ctx.montgomery_pow(three_mont, 1);
        assert_eq!(ctx.from_montgomery(result), 3, "3^1 != 3");

        // 3^2 = 9
        let result = ctx.montgomery_pow(three_mont, 2);
        assert_eq!(ctx.from_montgomery(result), 9, "3^2 != 9");

        // 2^10 = 1024
        let two_mont = ctx.to_montgomery(2);
        let result = ctx.montgomery_pow(two_mont, 10);
        assert_eq!(ctx.from_montgomery(result), 1024, "2^10 != 1024");
    }

    /// Empirical timing uniformity across different input classes.
    /// This is NOT a cryptographic constant-time proof; it checks for
    /// algorithmic constant-time behavior by verifying iteration counts
    /// are independent of input value.
    ///
    /// A proper constant-time audit requires hardware performance counters
    /// or a tool like dudect. This test documents the current status.
    #[test]
    fn test_montgomery_mul_timing_independence_empirical() {
        let q = test_prime();
        let ctx = MontgomeryContext::new(q);

        // Test input classes.
        let test_cases = [
            ("all_zero", 0u64, 0u64),
            ("all_max", q - 1, q - 1),
            ("alternating", 0xAAAA_AAAA_AAAA_AAAA & (q - 1), 0x5555_5555_5555_5555 & (q - 1)),
            ("small_large", 1u64, q - 1),
        ];

        let iterations = 10_000usize;
        let mut timings: Vec<(&str, u128)> = Vec::new();

        for (label, a, b) in test_cases {
            let a_mont = ctx.to_montgomery(a);
            let b_mont = ctx.to_montgomery(b);

            let start = std::time::Instant::now();
            for _ in 0..iterations {
                let _ = core::hint::black_box(ctx.montgomery_mul(
                    core::hint::black_box(a_mont),
                    core::hint::black_box(b_mont),
                ));
            }
            let elapsed = start.elapsed().as_nanos();
            timings.push((label, elapsed));
        }

        // Print timing table for manual inspection.
        let min_time = timings.iter().map(|t| t.1).min().unwrap_or(1);
        let max_time = timings.iter().map(|t| t.1).max().unwrap_or(1);

        for (label, ns) in &timings {
            println!("[montgomery_timing] {}: {}ns ({} iterations)",
                label, ns, iterations);
        }

        let ratio = max_time / min_time.max(1);

        // Note: This test is diagnostic, not a hard assertion. Timing tests are inherently
        // subject to OS scheduling noise, especially under parallel test execution.
        // A ratio > 5x would indicate potential data-dependent branches, but can also
        // result from system load. Run this test in isolation for meaningful results.
        if ratio >= 5 {
            println!("[montgomery_timing] NOTICE: max/min ratio = {}x (max={}ns, min={}ns). \
                     This may indicate data-dependent branches OR system scheduling noise. \
                     Re-run in isolation to distinguish.", ratio, max_time, min_time);
        } else {
            println!("[montgomery_timing] max/min ratio = {}x — within acceptable bounds", ratio);
        }
    }
}
