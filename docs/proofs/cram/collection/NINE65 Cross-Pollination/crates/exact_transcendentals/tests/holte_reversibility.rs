//! Exact finite regressions for Holte's carry chain under uniform i.i.d.
//! driving digits. The carry states themselves need not be independent.
//!
//! These checks cover the stated finite grids. They do not replace a proof of
//! the reversibility dichotomy for every summand count and every base, and
//! they establish no FHE bootstrap or cryptographic security property.

use exact_transcendentals::cram_carry::{
    carry_matrix, detailed_balance_defect, eulerian, eulerian_stationary, Frac,
};

fn factorial(n: usize) -> i128 {
    (1..=n as i128).product()
}

/// Integer binomial coefficient, including the combinatorial zero cases.
fn choose(top: i128, bottom: usize) -> i128 {
    if top < bottom as i128 || top < 0 {
        return 0;
    }
    let mut value = 1;
    for j in 1..=bottom {
        value = value * (top - j as i128 + 1) / j as i128;
    }
    value
}

/// Bounded-composition inclusion-exclusion, independent of the production
/// implementation's repeated digit convolution.
fn prefix_count(n: usize, base: i128, upper: i128) -> i128 {
    (0..=n)
        .map(|excluded| {
            let term = choose(n as i128, excluded)
                * choose(upper - excluded as i128 * base + n as i128, n);
            if excluded % 2 == 0 {
                term
            } else {
                -term
            }
        })
        .sum()
}

fn transition_count(n: usize, base: i128, from: usize, to: usize) -> i128 {
    prefix_count(n, base, (to as i128 + 1) * base - 1 - from as i128)
        - prefix_count(n, base, to as i128 * base - 1 - from as i128)
}

fn matrix_count(probability: Frac, total: i128) -> i128 {
    assert_eq!(total % probability.den, 0);
    probability.num * (total / probability.den)
}

fn corner_gap(n: usize, base: i128) -> i128 {
    let weight = (1i128 << n) - n as i128 - 1;
    transition_count(n, base, 0, 1) - weight * transition_count(n, base, 1, 0)
}

/// User-supplied factored corner differences T01-A(n,1)*T10.
fn factored_corner_gap(n: usize, base: i128) -> i128 {
    let m = base;
    let common = m * (m - 1) * (m + 1);
    match n {
        4 => -common / 6,
        5 => -common * (m + 2) / 4,
        6 => -common * (m + 2) * (23 * m + 64) / 120,
        7 => -common * (m + 2) * (m + 3) * (3 * m + 10) / 30,
        8 => -common * (m + 2) * (m + 3) * (67 * m * m + 512 * m + 990) / 1680,
        _ => panic!("factored regression table covers n=4 through n=8"),
    }
}

#[test]
fn uniform_digit_transition_counts_match_independent_inclusion_exclusion() {
    for n in 1..=8 {
        for base in 2i128..=64 {
            let matrix = carry_matrix(n, base);
            let total = base.pow(n as u32);
            for (from, row) in matrix.iter().enumerate() {
                let mut row_total = 0;
                for (to, &probability) in row.iter().enumerate() {
                    let count = transition_count(n, base, from, to);
                    assert!(count >= 0, "n={n}, base={base}, {from}->{to}");
                    assert_eq!(
                        probability,
                        Frac::new(count, total),
                        "n={n}, base={base}, {from}->{to}"
                    );
                    row_total += count;
                }
                assert_eq!(row_total, total, "n={n}, base={base}, row={from}");
            }
        }
    }
}

#[test]
fn tiny_uniform_digit_words_are_counted_exhaustively() {
    for n in 1..=6 {
        for base in 2i128..=4 {
            let total = base.pow(n as u32);
            let mut counts = vec![vec![0i128; n]; n];
            // Each word is one equally likely tuple of independent digits.
            for word in 0..total {
                let mut remaining = word;
                let mut digit_sum = 0;
                for _ in 0..n {
                    digit_sum += remaining % base;
                    remaining /= base;
                }
                for (from, row) in counts.iter_mut().enumerate() {
                    let to = ((from as i128 + digit_sum) / base) as usize;
                    row[to] += 1;
                }
            }
            let matrix = carry_matrix(n, base);
            for (from, row) in counts.iter().enumerate() {
                for (to, &count) in row.iter().enumerate() {
                    assert_eq!(matrix[from][to], Frac::new(count, total));
                }
            }
        }
    }
}

#[test]
fn eulerian_weights_and_stationarity_hold_on_the_checked_grid() {
    for n in 1..=8 {
        let weights = eulerian(n);
        let stationary = eulerian_stationary(n);
        assert_eq!(weights.iter().sum::<i128>(), factorial(n));
        for (j, &weight) in weights.iter().enumerate() {
            // Independent finite-difference formula for Eulerian numbers.
            let expected: i128 = (0..=j + 1)
                .map(|k| {
                    let term = choose(n as i128 + 1, k) * (j as i128 + 1 - k as i128).pow(n as u32);
                    if k % 2 == 0 {
                        term
                    } else {
                        -term
                    }
                })
                .sum();
            assert_eq!(weight, expected);
            assert_eq!(stationary[j], Frac::new(weight, factorial(n)));
        }
        for base in 2i128..=64 {
            let matrix = carry_matrix(n, base);
            let total = base.pow(n as u32);
            for to in 0..n {
                let inbound: i128 = weights
                    .iter()
                    .enumerate()
                    .map(|(from, &weight)| weight * matrix_count(matrix[from][to], total))
                    .sum();
                assert_eq!(
                    inbound,
                    weights[to] * total,
                    "n={n}, base={base}, state={to}"
                );
            }
        }
    }
}

#[test]
fn one_to_three_summands_satisfy_every_detailed_balance_equation() {
    for n in 1..=3 {
        let weights = eulerian(n);
        for base in 2i128..=64 {
            let matrix = carry_matrix(n, base);
            let total = base.pow(n as u32);
            for from in 0..n {
                for to in 0..n {
                    assert_eq!(
                        weights[from] * matrix_count(matrix[from][to], total),
                        weights[to] * matrix_count(matrix[to][from], total),
                        "n={n}, base={base}, {from}<->{to}"
                    );
                }
            }
            assert!(detailed_balance_defect(n, base).is_zero());
        }
    }
}

#[test]
fn factored_corner_table_detects_nonreversibility_for_four_to_eight_summands() {
    for n in 4..=8 {
        let weights = eulerian(n);
        assert_eq!(weights[0], 1);
        assert_eq!(weights[1], (1i128 << n) - n as i128 - 1);
        for base in 2i128..=64 {
            let total = base.pow(n as u32);
            // Every reduced joint-probability denominator divides n!*b^n.
            // Its square fits i128 throughout this intentionally finite grid,
            // including the library's cross-multiplication defect comparison.
            let denominator = factorial(n) * total;
            assert!(denominator.checked_mul(denominator).is_some());
            let matrix = carry_matrix(n, base);
            let t01 = choose(2 * base + n as i128 - 1, n)
                - (n as i128 + 1) * choose(base + n as i128 - 1, n);
            let t10 = choose(base + n as i128 - 2, n);
            assert_eq!(matrix_count(matrix[0][1], total), t01);
            assert_eq!(matrix_count(matrix[1][0], total), t10);
            let gap = t01 - weights[1] * t10;
            assert_eq!(gap, corner_gap(n, base));
            assert_eq!(gap, factored_corner_gap(n, base), "n={n}, base={base}");
            assert!(gap < 0, "n={n}, base={base}: corner must violate balance");
            let corner_flux = Frac::new(-gap, denominator);
            let defect = detailed_balance_defect(n, base);
            assert!(!defect.is_zero());
            assert!(
                !corner_flux.gt(defect),
                "maximum defect must include corner flux"
            );
        }
    }
}

#[test]
fn positive_newton_coefficients_reproduce_the_factored_corner_table() {
    let table: &[(usize, &[i128])] = &[
        (4, &[1, 3, 3, 1]),
        (5, &[6, 24, 36, 24, 6]),
        (6, &[22, 111, 224, 226, 114, 23]),
        (7, &[64, 392, 1000, 1360, 1040, 424, 72]),
        (8, &[163, 1178, 3646, 6265, 6455, 3988, 1368, 201]),
    ];
    for &(n, coefficients) in table {
        assert!(coefficients.iter().all(|&value| value > 0));
        for base in 2i128..=64 {
            let magnitude: i128 = coefficients
                .iter()
                .enumerate()
                .map(|(k, &coefficient)| coefficient * choose(base - 2, k))
                .sum();
            assert_eq!(-magnitude, factored_corner_gap(n, base));
            assert_eq!(-magnitude, corner_gap(n, base));
        }
    }
}

#[test]
fn binary_corner_counts_and_published_defects_are_pinned() {
    for (n, expected) in [(4, -1), (5, -6), (6, -22), (7, -64), (8, -163)] {
        assert_eq!(corner_gap(n, 2), expected);
    }
    assert_eq!(detailed_balance_defect(4, 2), Frac::new(1, 384));
    assert_eq!(detailed_balance_defect(4, 10), Frac::new(11, 16_000));
    assert_eq!(detailed_balance_defect(5, 10), Frac::new(99, 400_000));
}

#[test]
fn independent_driving_digits_do_not_require_independent_carry_states() {
    let matrix = carry_matrix(2, 2);
    let stationary = eulerian_stationary(2);
    assert_eq!(stationary, vec![Frac::new(1, 2), Frac::new(1, 2)]);
    assert_eq!(matrix[0][0], Frac::new(3, 4));
    assert_eq!(matrix[1][0], Frac::new(1, 4));
    // Conditional next-carry laws differ, even in stationarity.
    assert_ne!(matrix[0][0], stationary[0]);
    assert_ne!(matrix[1][0], stationary[0]);
    // Dependence between carry states does not prevent time reversibility.
    assert_eq!(stationary[0] * matrix[0][1], stationary[1] * matrix[1][0]);
    assert!(detailed_balance_defect(2, 2).is_zero());
}
