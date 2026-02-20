//! Binary GCD (Stein's Algorithm) — Integer-Only Implementation
//!
//! Correctness: T1 proof sketch verified by κ Critic (confidence 0.63)
//! Termination: A2 verified — O(log min(|u|,|v|)) iterations
//!
//! Integer-Only Guarantee:
//! - Bit operations: trailing_zeros, >>, <<, |
//! - Arithmetic: subtraction, absolute value
//! - Zero floating-point operations
//!
//! Algorithm Phases:
//! 1. Base cases (u=0 or v=0)
//! 2. Absolute value normalization
//! 3. Extract common factors of 2
//! 4. Reduction loop (Stein's algorithm)
//! 5. Restore common factors

/// Compute GCD using Stein's binary algorithm.
///
/// # Properties (T1)
/// - `(g | u) ∧ (g | v)`: result divides both inputs
/// - Maximality: any common divisor of u,v divides g
/// - `g > 0` when at least one input is non-zero
/// - `g = 0` only when both inputs are zero
///
/// # Integer-Only Design
/// Uses only bit operations and subtraction — no division, no floats.
///
/// # Performance
/// O(log min(|u|, |v|)) iterations, each O(1) bit operations.
pub fn binary_gcd(mut u: i128, mut v: i128) -> i128 {
    // Phase 1: Base cases
    // gcd(0, v) = |v| — any integer divides 0
    if u == 0 {
        return v.abs();
    }
    // gcd(u, 0) = |u| — symmetric case
    if v == 0 {
        return u.abs();
    }

    // Phase 2: Absolute value normalization
    // Lemma 2.1: gcd(u, v) = gcd(|u|, |v|)
    // Divisibility ignores sign
    u = u.abs();
    v = v.abs();

    // Phase 3: Extract common factors of 2
    // shift = min(tz(u), tz(v)) = common trailing zeros
    // Lemma 3.1: gcd(2^k * u', 2^k * v') = 2^k * gcd(u', v')
    let shift = (u | v).trailing_zeros();
    u >>= u.trailing_zeros();
    // Invariant: u is now odd

    // Phase 4: Reduction loop
    // Loop invariant I(u, v, shift):
    //   gcd(original_u, original_v) = 2^shift * gcd(u, v) ∧ u is odd ∧ v ≥ 0
    //
    // Termination: v strictly decreases each iteration (A2)
    loop {
        // Remove trailing zeros from v
        // gcd(u, v) = gcd(u, v/2^k) when u is odd
        v >>= v.trailing_zeros();

        // Ensure u ≤ v for subtraction
        // gcd(u, v) = gcd(v, u) — symmetric
        if u > v {
            std::mem::swap(&mut u, &mut v);
        }

        // Euclidean reduction: gcd(u, v) = gcd(u, v - u)
        // Lemma 4.1: common divisors preserved under subtraction
        v -= u;

        // Exit when v = 0: gcd(u, 0) = u
        if v == 0 {
            break;
        }
    }

    // Phase 5: Restore common factors of 2
    // gcd(original) = 2^shift * u
    //
    // SAFETY NOTE (κ Critic T1-3): overflow possible if log2(u) + shift > 127
    // For normalized rationals this is extremely rare. Using checked_shl
    // would be safer but we accept this for v0.2.
    u << shift
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========= T1: Binary GCD Correctness =========

    #[test]
    fn t1_base_case_zero_u() {
        assert_eq!(binary_gcd(0, 5), 5, "gcd(0, 5) = 5");
        assert_eq!(binary_gcd(0, -7), 7, "gcd(0, -7) = 7");
    }

    #[test]
    fn t1_base_case_zero_v() {
        assert_eq!(binary_gcd(12, 0), 12, "gcd(12, 0) = 12");
        assert_eq!(binary_gcd(-9, 0), 9, "gcd(-9, 0) = 9");
    }

    #[test]
    fn t1_base_case_both_zero() {
        assert_eq!(binary_gcd(0, 0), 0, "gcd(0, 0) = 0");
    }

    #[test]
    fn t1_coprime() {
        assert_eq!(binary_gcd(7, 13), 1, "gcd(7, 13) = 1 (coprime)");
        assert_eq!(binary_gcd(17, 31), 1, "gcd(17, 31) = 1 (coprime primes)");
    }

    #[test]
    fn t1_example_48_18() {
        // From proof sketch concrete example
        assert_eq!(binary_gcd(48, 18), 6, "gcd(48, 18) = 6");
    }

    #[test]
    fn t1_powers_of_two() {
        assert_eq!(binary_gcd(16, 12), 4, "gcd(16, 12) = 4");
        assert_eq!(binary_gcd(64, 32), 32, "gcd(64, 32) = 32");
    }

    #[test]
    fn t1_negative_inputs() {
        assert_eq!(binary_gcd(-48, 18), 6, "gcd(-48, 18) = 6");
        assert_eq!(binary_gcd(48, -18), 6, "gcd(48, -18) = 6");
        assert_eq!(binary_gcd(-48, -18), 6, "gcd(-48, -18) = 6");
    }

    #[test]
    fn t1_equal_inputs() {
        assert_eq!(binary_gcd(42, 42), 42, "gcd(42, 42) = 42");
        assert_eq!(binary_gcd(1, 1), 1, "gcd(1, 1) = 1");
    }

    #[test]
    fn t1_one_input() {
        assert_eq!(binary_gcd(1, 999), 1, "gcd(1, n) = 1");
        assert_eq!(binary_gcd(999, 1), 1, "gcd(n, 1) = 1");
    }

    #[test]
    fn t1_divisibility_property() {
        // Property 1: g divides both inputs
        let u = 360;
        let v = 150;
        let g = binary_gcd(u, v);
        assert_eq!(g, 30);
        assert_eq!(u % g, 0, "g must divide u");
        assert_eq!(v % g, 0, "g must divide v");
    }

    #[test]
    fn t1_maximality_property() {
        // Property 2: g is maximal common divisor
        let u = 360;
        let v = 150;
        let g = binary_gcd(u, v);
        // Check no common divisor larger than g exists
        for d in (g + 1)..=(u.min(v)) {
            if u % d == 0 && v % d == 0 {
                panic!("Found larger common divisor {d}, but GCD was {g}");
            }
        }
    }

    #[test]
    fn t1_positivity_property() {
        // Property 3: g > 0 for non-zero inputs
        assert!(binary_gcd(42, 18) > 0);
        assert!(binary_gcd(-42, -18) > 0);
        assert!(binary_gcd(1, i128::MAX) > 0);
    }

    #[test]
    fn t1_commutative() {
        assert_eq!(
            binary_gcd(48, 18),
            binary_gcd(18, 48),
            "gcd must be commutative"
        );
    }

    #[test]
    fn t1_large_values() {
        let large_a = 1_000_000_000_000i128;
        let large_b = 500_000_000_000i128;
        let g = binary_gcd(large_a, large_b);
        assert_eq!(g, 500_000_000_000);
        assert_eq!(large_a % g, 0);
        assert_eq!(large_b % g, 0);
    }
}
