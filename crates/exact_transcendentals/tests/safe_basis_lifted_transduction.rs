//! Exact theorem/regression harness for Safe-Basis repacking, composite
//! adjacency and lift-aware transduction.
//!
//! A1/A2: integer arithmetic only. No floating point.

use exact_transcendentals::k_elim::{gcd, modd};
use exact_transcendentals::transduction::{S6_BASIS, S8_BASIS};
use std::collections::HashSet;

fn product(xs: &[i128]) -> i128 {
    xs.iter().copied().product()
}

fn signature(x: i128, basis: &[i128]) -> Vec<i128> {
    basis.iter().map(|&m| modd(x, m)).collect()
}

fn pairwise_coprime(basis: &[i128]) -> bool {
    for i in 0..basis.len() {
        for j in (i + 1)..basis.len() {
            if gcd(basis[i], basis[j]) != 1 {
                return false;
            }
        }
    }
    true
}

fn mod_inverse_adjacent(m: i128) -> i128 {
    let a = m + 1;
    // m == -1 mod a, and (-1)^-1 == -1.
    modd(-1, a)
}

fn adjacency_k(x: i128, m: i128) -> i128 {
    let a = m + 1;
    let r_m = modd(x, m);
    let r_a = modd(x, a);
    modd((r_a - r_m) * mod_inverse_adjacent(m), a)
}

fn project_with_lift(g_mod_b: i128, k_mod_b: i128, m_mod_b: i128, b: i128) -> i128 {
    assert!(b > 0);
    modd(g_mod_b + k_mod_b * m_mod_b, b)
}

fn lcm(a: i128, b: i128) -> i128 {
    (a / gcd(a, b)) * b
}

#[test]
fn s6_saturates_exactly_30030_states() {
    let m6 = product(&S6_BASIS);
    assert_eq!(m6, 30_030);

    let mut seen = HashSet::with_capacity(m6 as usize);
    for x in 0..m6 {
        assert!(seen.insert(signature(x, &S6_BASIS)), "collision at x={x}");
    }
    assert_eq!(seen.len(), 30_030);
}

#[test]
fn safe_basis_repack_to_composite_carriers_preserves_product_space() {
    const S6_COMPOSITE: [i128; 3] = [6, 35, 143];
    const S8_COMPOSITE: [i128; 4] = [6, 35, 143, 323];

    assert!(pairwise_coprime(&S6_COMPOSITE));
    assert!(pairwise_coprime(&S8_COMPOSITE));
    assert_eq!(product(&S6_COMPOSITE), product(&S6_BASIS));
    assert_eq!(product(&S8_COMPOSITE), product(&S8_BASIS));
    assert_eq!(product(&S8_COMPOSITE), 9_699_690);

    // Exhaust the full S6 product: no state may collide after repacking.
    let m6 = product(&S6_BASIS);
    let mut seen = HashSet::with_capacity(m6 as usize);
    for x in 0..m6 {
        let packed = signature(x, &S6_COMPOSITE);
        assert!(seen.insert(packed), "composite repack collision at x={x}");
    }
    assert_eq!(seen.len() as i128, m6);

    // S8: deterministic sample spanning boundaries and many sheets.
    let m8 = product(&S8_BASIS);
    let probes = [
        0,
        1,
        2,
        35,
        36,
        37,
        30_029,
        30_030,
        30_031,
        m8 / 2,
        m8 - 2,
        m8 - 1,
    ];
    for &x in &probes {
        let prime = signature(x, &S8_BASIS);
        let packed = signature(x, &S8_COMPOSITE);
        for (&p, &rp) in S8_BASIS.iter().zip(prime.iter()) {
            // Find the composite carrier containing p and assert its residue
            // reduces back to the original prime lane.
            let carrier = S8_COMPOSITE.iter().copied().find(|c| c % p == 0).unwrap();
            let rc = packed[S8_COMPOSITE.iter().position(|&c| c == carrier).unwrap()];
            assert_eq!(rc % p, rp, "x={x}, p={p}, carrier={carrier}");
        }
    }
}

#[test]
fn overlapping_composites_are_views_not_full_product_basis() {
    const OVERLAP: [i128; 4] = [6, 10, 15, 21];
    let independent_capacity = OVERLAP.into_iter().fold(1, lcm);
    assert_eq!(independent_capacity, 210);
    assert!(independent_capacity < product(&OVERLAP));

    // Over [0, 30030), signatures repeat every lcm=210.
    for x in 0..210i128 {
        assert_eq!(signature(x, &OVERLAP), signature(x + 210, &OVERLAP));
    }
}

#[test]
fn adjacency_lift_is_exact_for_composite_and_prime_neighbors() {
    let mut checks = 0u64;
    for m in 2i128..=100 {
        let a = m + 1;
        assert_eq!(gcd(m, a), 1);
        assert_eq!(modd(m, a), a - 1);
        assert_eq!(mod_inverse_adjacent(m), a - 1);

        for x in 0..(m * a) {
            assert_eq!(adjacency_k(x, m), x / m, "m={m}, x={x}");
            checks += 1;
        }
    }
    assert_eq!(checks, 343_398);
}

#[test]
fn canonical_adjacent_products_include_composite_anchors() {
    let m6 = product(&S6_BASIS);
    let a6 = m6 + 1;
    assert_eq!(m6, 30_030);
    assert_eq!(a6, 30_031);
    assert_eq!(a6, 59 * 509);

    let m8 = product(&S8_BASIS);
    let a8 = m8 + 1;
    assert_eq!(m8, 9_699_690);
    assert_eq!(a8, 9_699_691);
    assert_eq!(a8, 347 * 27_953);

    for &m in &[36i128, m6, m8] {
        for &k in &[0i128, 1, 2, 5, 17] {
            for &r in &[0i128, 1, m - 1] {
                let x = k * m + r;
                // These probes all satisfy k < m+1.
                assert_eq!(adjacency_k(x, m), k, "m={m}, k={k}, r={r}");
            }
        }
    }
}

#[test]
fn universal_projection_accepts_composite_and_shared_factor_targets() {
    let m = product(&S6_BASIS);
    let a = m + 1;
    let targets = [
        1i128, 4, 6, 8, 9, 10, 12, 18, 25, 35, 36, 37, 49, 77, 121, 143, 256,
    ];
    let xs = [
        0i128,
        1,
        m - 1,
        m,
        m + 1,
        2 * m - 1,
        2 * m,
        2 * m + 1,
        17 * m + 29,
        m * a - 1,
    ];

    for &x in &xs {
        let g = modd(x, m);
        let k = adjacency_k(x, m);
        assert_eq!(k, x / m);
        for &b in &targets {
            let got = project_with_lift(modd(g, b), modd(k, b), modd(m, b), b);
            assert_eq!(got, modd(x, b), "x={x}, target={b}");
        }
    }
}

#[test]
fn lift_aware_s6_to_s8_regression_distinguishes_the_first_wrapped_sheet() {
    let m6 = product(&S6_BASIS);
    let x0 = 0i128;
    let x1 = m6;

    // Same source tray: plain S6 residues cannot distinguish the two values.
    assert_eq!(signature(x0, &S6_BASIS), signature(x1, &S6_BASIS));

    // But the S8 extension lanes must distinguish them.
    assert_eq!(modd(x1, 17), 8);
    assert_eq!(modd(x1, 19), 10);

    let g = modd(x1, m6); // 0
    let k = adjacency_k(x1, m6); // 1, derived from M6/(M6+1) phase lock
    assert_eq!(g, 0);
    assert_eq!(k, 1);

    let r17 = project_with_lift(modd(g, 17), modd(k, 17), modd(m6, 17), 17);
    let r19 = project_with_lift(modd(g, 19), modd(k, 19), modd(m6, 19), 19);
    assert_eq!((r17, r19), (8, 10));
}

#[test]
fn heterogeneous_affine_maps_are_reversible_on_composite_product_state() {
    const MODS: [i128; 4] = [6, 35, 143, 323];
    // f_i(x) = a_i*x+b_i mod m_i. Every a_i is a unit.
    const OPS: [(i128, i128); 4] = [(5, 1), (2, 4), (7, 3), (5, 6)];

    for ((&m, &(a, _b)), i) in MODS.iter().zip(OPS.iter()).zip(0usize..) {
        assert_eq!(gcd(a, m), 1, "lane {i} multiplier must be a unit");
    }

    // Exhaust each coordinate independently. Since the global map is the
    // Cartesian product of coordinate bijections, coordinate exhaustiveness
    // proves the full product map bijective without looping over 9,699,690 states.
    for (&m, &(a, b)) in MODS.iter().zip(OPS.iter()) {
        // extended Euclid via the public K-Elim inverse helper would also work;
        // brute force is tiny and keeps this test independent of that helper.
        let inv = (1..m).find(|&u| modd(a * u, m) == 1).unwrap();
        for x in 0..m {
            let y = modd(a * x + b, m);
            let back = modd(inv * modd(y - b, m), m);
            assert_eq!(back, x, "m={m}, x={x}");
        }
    }
}

#[test]
fn s6_expansion_to_17x19_is_not_product_uniform() {
    let m6 = product(&S6_BASIS);
    let mut counts = vec![0u64; 17 * 19];
    let mut c17 = [0u64; 17];
    let mut c19 = [0u64; 19];

    for x in 0..m6 {
        let a = modd(x, 17) as usize;
        let b = modd(x, 19) as usize;
        counts[a * 19 + b] += 1;
        c17[a] += 1;
        c19[b] += 1;
    }

    // Product independence would require
    // count(a,b) * N == count(a) * count(b) for every cell.
    let n = m6 as u64;
    let mut violations = 0usize;
    for a in 0..17usize {
        for b in 0..19usize {
            if counts[a * 19 + b] * n != c17[a] * c19[b] {
                violations += 1;
            }
        }
    }
    assert_eq!(violations, 17 * 19);

    let min = *counts.iter().min().unwrap();
    let max = *counts.iter().max().unwrap();
    assert_eq!((min, max), (92, 93));
}
