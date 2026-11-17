//! Exhaustive and large-sample exact verification of every K-Elim operation.
//! A1: zero floats. A2: exact integers. All state spaces enumerated where
//! tractable; large pairs sampled deterministically.

use kelim::*;

/// Theorem 1: K-Elim recovers ⌊X/M⌋ over the full CRT range, any coprime pair.
#[test]
fn k_elim_exhaustive_coprime_pairs() {
    let pairs = [(4, 9), (8, 9), (35, 36), (25, 49), (15, 16), (36, 37)];
    for (m, a) in pairs {
        assert_eq!(gcd(m, a), 1, "pair must be coprime");
        for x in 0..(m * a) {
            let (v_m, v_a) = (x % m, x % a);
            let k = k_elim(v_m, v_a, m, a);
            assert_eq!(k, (x / m) % a, "K-Elim failed at X={} pair=({},{})", x, m, a);
        }
    }
}

/// Corollary 4.4: adjacent subtraction form equals general K-Elim.
#[test]
fn k_elim_adjacent_matches_general() {
    for m in [8, 14, 35, 36, 48, 99] {
        let a = m + 1;
        for x in 0..(m * a) {
            let (v_m, v_a) = (x % m, x % a);
            let sub = k_elim_adjacent(v_m, v_a, m);
            let gen = k_elim(v_m, v_a, m, a);
            assert_eq!(sub, gen, "adjacent != general at X={} m={}", x, m);
            assert_eq!(sub, (x / m) % a, "adjacent wrong at X={} m={}", x, m);
        }
    }
}

/// Theorem 5.1: dual recovers ⌊X/A⌋ over the full range.
#[test]
fn k_elim_dual_exhaustive() {
    let (m, a) = (36, 37);
    for x in 0..(m * a) {
        let (v_m, v_a) = (x % m, x % a);
        assert_eq!(k_elim_dual(v_m, v_a, m, a), (x / a) % m, "dual failed at X={}", x);
    }
}

/// When M|X, standard K-Elim gives (X/M) mod A exactly (vM=0).
#[test]
fn exact_division_when_m_divides_x() {
    let (m, a) = (35, 36);
    for q in 0..a {
        let x = m * q;
        if x >= m * a {
            break;
        }
        let (v_m, v_a) = (x % m, x % a);
        assert_eq!(v_m, 0, "M|X means vM=0");
        assert_eq!(k_elim(v_m, v_a, m, a), q % a, "exact div failed q={}", q);
    }
}

/// Theorem 6.1: resolution gradient recovers ⌊X/M⌋ mod (A/d).
#[test]
fn resolution_gradient_exhaustive() {
    let pairs = [(4, 6), (6, 9), (10, 15), (584, 780)];
    for (m, a) in pairs {
        let d = gcd(m, a);
        assert!(d > 1, "gradient pair must be non-coprime");
        let limit = m * a;
        // full enumerate small, sample large
        let step = if limit > 60_000 { 7 } else { 1 };
        let mut x = 0;
        while x < limit {
            let (v_m, v_a) = (x % m, x % a);
            let (k, ad) = k_elim_gradient(v_m, v_a, m, a);
            assert_eq!(k, (x / m) % ad, "gradient failed X={} pair=({},{})", x, m, a);
            x += step;
        }
    }
}

/// Signed comparison: exact when operands occupy the signed-RNS lower half.
#[test]
fn signed_comparison_exhaustive() {
    let m = 35i128;
    let a = m + 1;
    let half = (m * a) / 2;
    for xx in 0..half {
        for yy in 0..half {
            let x_res = (xx % m, xx % a);
            let y_res = (yy % m, yy % a);
            let lt = rns_less_than(x_res, y_res, m);
            assert_eq!(lt, xx < yy, "compare failed X={} Y={}", xx, yy);
        }
    }
}

/// Tower digit equals the per-level winding.
#[test]
fn tower_digit_levels() {
    let (m1, m2, m3) = (36i128, 37, 73);
    let limit = m1 * m2 * m3;
    let mut x = 0i128;
    while x < limit {
        let (v1, v2, v3) = (x % m1, x % m2, x % m3);
        assert_eq!(tower_digit(v1, v2, m1, m2), (x / m1) % m2, "L1 X={}", x);
        assert_eq!(tower_digit(v2, v3, m2, m3), (x / m2) % m3, "L2 X={}", x);
        x += 113;
    }
}

/// Selector picks the correct strategy and computes the right winding.
#[test]
fn selector_dispatch_correct() {
    use kelim::selector::{select, apply, Strategy};

    // Adjacent → subtraction
    let s = select(36, 37);
    assert_eq!(s, Strategy::AdjacentSubtraction);
    for x in 0..(36 * 37) {
        let (w, m) = apply(s, x % 36, x % 37, 36, 37);
        assert_eq!(w, (x / 36) % m);
    }

    // Coprime non-adjacent → general
    let s = select(25, 49);
    assert!(matches!(s, Strategy::GeneralKElim { .. }));
    for x in 0..(25 * 49) {
        let (w, m) = apply(s, x % 25, x % 49, 25, 49);
        assert_eq!(w, (x / 25) % m);
    }

    // Non-coprime → gradient
    let s = select(584, 780);
    assert!(matches!(s, Strategy::ResolutionGradient { .. }));
    let mut x = 0i128;
    while x < 584 * 780 {
        let (w, m) = apply(s, x % 584, x % 780, 584, 780);
        assert_eq!(w, (x / 584) % m);
        x += 7;
    }
}

/// Winding residues read per-lane in residue space — the magnitude axis
/// descended WITHOUT Garner/mixed-radix reconstruction. Each lane independent.
#[test]
fn winding_residue_in_residue_space() {
    use kelim::winding_residue;
    // Core Colony = product of S8; spine lanes coprime to it carry the winding
    let core: i128 = 9_699_690; // 2·3·5·7·11·13·17·19
    let spine = [23i128, 29, 31, 37, 41, 43, 47, 53];
    // Test over many X spanning several windings of the core
    let mut x: i128 = 0;
    while x < core * 500 {
        let v_core = x % core;
        let k_true = x / core; // the winding (true value, for checking only)
        for &p in spine.iter() {
            let v_p = x % p;
            let kr = winding_residue(v_core, v_p, core, p);
            assert_eq!(kr, k_true % p, "winding residue wrong: X={} p={}", x, p);
        }
        x += 7919; // stride
    }
}

/// The winding's residue family is independent per lane (CRT coordinates).
/// Knowing k mod p constrains nothing about k mod q for coprime p,q.
/// This is the i.i.d.-preserving property: no cross-level cascade.
#[test]
fn winding_residues_are_independent_coordinates() {
    use kelim::winding_residue;
    let core: i128 = 9_699_690;
    let x: i128 = (1i128 << 100) - 1; // large, deep winding
    let v_core = x % core;
    let k_true = x / core;
    // Each spine residue must match its own CRT coordinate, with no lane
    // depending on another (verified by matching independent ground truth).
    for &p in [23i128, 29, 31, 37].iter() {
        let kr = winding_residue(v_core, x % p, core, p);
        assert_eq!(kr, k_true % p);
    }
}
