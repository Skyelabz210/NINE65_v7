//! Arrow-emission reversibility — the JOINT property, exercised.
//!
//! `arrow_emission_reversibility.rs` states the contract:
//!
//! > reversibility of the folded operator `A^N mod p` is a property of
//! > (operator, dim, prime) JOINTLY, not of the basis.
//!
//! ...but every assertion in that file is measured at a single point of that
//! product space: heat stencil `[1,3,1]`, `dim = 8`. One point cannot
//! distinguish a joint property from a property of the prime alone. If the
//! singular set `{3, 5, 7}` were an artefact of the primes rather than of the
//! (operator, dim) pair, every assertion there would still pass.
//!
//! This file closes that hole WITHOUT touching a single assertion in the
//! original: it holds one factor fixed and varies another, and pins the
//! measured answer at each new point.
//!
//! | operator `[b,a,b]` | dim | measured singular lanes | varies |
//! |---|---|---|---|
//! | `[1,3,1]` | 8  | `{3, 5, 7}` | (the original pin, restated as the baseline) |
//! | `[1,3,1]` | 6  | `{2, 5}`    | **dim only** |
//! | `[1,3,1]` | 4  | `{3, 5}`    | **dim only** |
//! | `[2,5,2]` | 8  | `{3, 5, 17}`| **operator only** |
//! | `[2,7,2]` | 8  | `{3, 7, 11}`| **operator only** |
//! | `[1,2,1]` | 8  | ALL lanes   | **operator only** — structurally one-way |
//! | `[1,2,1]` | 6  | ALL lanes   | operator + dim — one-way at another even dim |
//!
//! Every row above is asserted below. The table and the assertions are meant
//! to be read together, so a row that exists in one and not the other is a
//! defect in a file whose whole purpose is to pin measured facts: the
//! `[2,7,2]` dim=8 and `[1,2,1]` dim=6 rows were asserted before they were
//! listed here.
//!
//! Two conclusions the original file could not reach:
//!
//! * **Prime 7 is reversible at dim 4 and singular at dim 8** for the SAME
//!   operator. A per-prime reversibility table is therefore wrong by
//!   construction, and so is a per-basis one: `TRANSPORT_CORE` membership
//!   carries no information about whether the arrow is two-way.
//! * **The `[1,2,1]` stencil is singular on every lane, at every prime.**
//!   `a - 2b = 0` kills the eigenvalue at the root of unity `-1` for every
//!   even dim, so `det(A) = 0` identically, independent of `p`. There is no
//!   reversible sub-basis to fall back to, which makes it the sharpest
//!   available test of the refusal contract: `unfold` must return `None` for
//!   EVERY basis, not just for bases that happen to contain a bad lane.
//!
//! Same discipline as the original: exact integer arithmetic, every lane
//! folded/gated/unfolded independently, measured sets PINNED rather than
//! assumed, and refusal asserted as refusal (`None`) rather than as a
//! partially-correct answer — discarding information is projection, not
//! reversal (T-X-PROJ).
use exact_transcendentals::arrow_step::{heat_circulant, mat_inv_mod, mat_mul_mod, ArrowStep};

/// Same basis as `arrow_emission_reversibility.rs`: S8 odd part plus a 30-bit
/// NTT prime. Reused verbatim so that a differing singular set below is
/// attributable to (operator, dim) and to nothing else.
fn basis() -> Vec<u64> {
    vec![2, 3, 5, 7, 11, 13, 17, 19, 998244353]
}

/// The measured singular lanes of `[b,a,b]` at `dim`, over `basis()`.
fn singular_lanes(dim: usize, a: u64, b: u64, steps: u64) -> Vec<u64> {
    let arrow = ArrowStep::for_heat(dim, a, b, steps, &basis());
    let gate = arrow.reversible_lanes(a, b);
    basis()
        .iter()
        .zip(gate.iter())
        .filter(|(_, &ok)| !ok)
        .map(|(&p, _)| p)
        .collect()
}

/// A state vector per lane, values reduced into each lane independently.
fn seeded_state(dim: usize, primes: &[u64]) -> Vec<Vec<u64>> {
    primes
        .iter()
        .map(|&p| (0..dim as u64).map(|i| (i * 7 + 2) % p).collect())
        .collect()
}

// ===========================================================================
// VARY DIM, HOLD OPERATOR FIXED
// ===========================================================================

/// The singular set moves when ONLY `dim` changes. Pins three points of the
/// same operator so the dependence is a measured fact, not an inference.
#[test]
fn singular_set_depends_on_dim_with_the_operator_held_fixed() {
    // Baseline, identical to the original file's pin.
    assert_eq!(
        singular_lanes(8, 3, 1, 1_000_000),
        vec![3, 5, 7],
        "heat [1,3,1] dim=8 baseline must stay {{3,5,7}} — this restates the \
         pin in arrow_emission_reversibility.rs and must never diverge from it"
    );

    // Same operator, dim 6: a DIFFERENT set, and not a subset or superset.
    assert_eq!(
        singular_lanes(6, 3, 1, 1_000_000),
        vec![2, 5],
        "heat [1,3,1] dim=6 must stay {{2,5}} — measured 2026-08-22"
    );

    // Same operator, dim 4.
    assert_eq!(
        singular_lanes(4, 3, 1, 1_000_000),
        vec![3, 5],
        "heat [1,3,1] dim=4 must stay {{3,5}} — measured 2026-08-22"
    );
}

/// The sharpest single fact available: ONE prime, ONE operator, two dims,
/// opposite answers. This is what makes the property joint rather than
/// per-prime, and it is why transport-lane selection may not be cached
/// against a prime or against basis membership.
#[test]
fn one_prime_one_operator_two_dims_opposite_reversibility() {
    let p = 7u64;
    let a = 3u64;
    let b = 1u64;

    let rev_at_4 = mat_inv_mod(&heat_circulant(4, a, b, p), 4, p).is_some();
    let rev_at_8 = mat_inv_mod(&heat_circulant(8, a, b, p), 8, p).is_some();

    assert!(
        rev_at_4,
        "lane 7 must be REVERSIBLE for heat [1,3,1] at dim=4"
    );
    assert!(
        !rev_at_8,
        "lane 7 must be SINGULAR for heat [1,3,1] at dim=8"
    );
    assert_ne!(
        rev_at_4, rev_at_8,
        "same prime, same operator, different dim, different answer — the \
         reversibility gate cannot be memoised per prime"
    );
}

// ===========================================================================
// VARY OPERATOR, HOLD DIM FIXED
// ===========================================================================

/// The singular set moves when ONLY the stencil coefficients change.
#[test]
fn singular_set_depends_on_operator_with_dim_held_fixed() {
    assert_eq!(
        singular_lanes(8, 5, 2, 1_000_000),
        vec![3, 5, 17],
        "heat [2,5,2] dim=8 must stay {{3,5,17}} — measured 2026-08-22. \
         Lane 7 is reversible here and singular for [1,3,1] at the same dim; \
         lane 17 is the reverse."
    );

    assert_eq!(
        singular_lanes(8, 7, 2, 1_000_000),
        vec![3, 7, 11],
        "heat [2,7,2] dim=8 must stay {{3,7,11}} — measured 2026-08-22"
    );
}

/// `a - 2b = 0` annihilates the eigenvalue at the root of unity `-1`, so
/// `[1,2,1]` is singular on EVERY lane at every even dim, for every prime.
/// There is no reversible sub-basis at all — the arrow is structurally
/// one-way, not accidentally one-way on some lanes.
#[test]
fn a_minus_two_b_zero_operator_is_one_way_on_every_lane() {
    let sing = singular_lanes(8, 2, 1, 1_000);
    assert_eq!(
        sing,
        basis(),
        "heat [1,2,1] dim=8 must be singular on EVERY lane of the basis — \
         a - 2b = 0 kills det(A) independently of p"
    );

    // ...and the same at another even dim, so this is read as structural
    // rather than as another dim-specific coincidence.
    assert_eq!(
        singular_lanes(6, 2, 1, 1_000),
        basis(),
        "heat [1,2,1] dim=6 must also be singular on EVERY lane"
    );
}

// ===========================================================================
// REFUSAL, AT THE NEW POINTS
// ===========================================================================

/// The refusal contract, re-asserted at every new (operator, dim) point:
/// a basis containing a singular lane must make `unfold` return `None`.
/// A partial unfold would reverse the good lanes and leave the bad ones
/// where they were, desynchronising the residue frame — projection, not
/// reversal.
#[test]
fn unfold_refuses_loudly_at_every_new_operator_dim_point() {
    // (dim, a, b, a basis containing at least one lane measured singular there)
    let cases: &[(usize, u64, u64, &[u64])] = &[
        (6, 3, 1, &[2, 11, 13]),      // 2 singular at dim=6
        (4, 3, 1, &[3, 11, 13]),      // 3 singular at dim=4
        (8, 5, 2, &[17, 11, 13]),     // 17 singular for [2,5,2] dim=8
        (8, 7, 2, &[11, 13, 19]),     // 11 singular for [2,7,2] dim=8
    ];

    for &(dim, a, b, lanes) in cases {
        let arrow = ArrowStep::for_heat(dim, a, b, 10, lanes);
        let emitted = arrow.apply(&seeded_state(dim, lanes));
        assert!(
            arrow.unfold(a, b, &emitted).is_none(),
            "unfold over basis {lanes:?} for operator [{b},{a},{b}] dim={dim} \
             must REFUSE, not partially reverse"
        );
    }
}

/// The structurally one-way operator must refuse over EVERY basis, including
/// bases made entirely of large well-behaved NTT primes. This is stronger
/// than the original refusal test, which used a basis chosen to contain a
/// known-bad lane: here no such choice is available.
#[test]
fn structurally_one_way_operator_refuses_over_every_basis() {
    let bases: &[&[u64]] = &[
        &[998244353],
        &[11, 13, 17, 19],
        &[2, 3, 5, 7],
        &[998244353, 11, 13],
    ];
    for &lanes in bases {
        let arrow = ArrowStep::for_heat(8, 2, 1, 10, lanes);
        let emitted = arrow.apply(&seeded_state(8, lanes));
        assert!(
            arrow.unfold(2, 1, &emitted).is_none(),
            "heat [1,2,1] dim=8 must refuse to unfold over basis {lanes:?} — \
             det(A) = 0 on every lane, so there is nothing to fall back to"
        );
    }
}

// ===========================================================================
// EXACTNESS AT THE NEW POINTS
// ===========================================================================

/// Where the gate says a lane IS reversible at a new (operator, dim) point,
/// the folded operator must unfold to the EXACT initial state — same
/// standard as the original million-step test, applied to the new points so
/// the positive answers are pinned as well as the negative ones.
#[test]
fn reversible_sub_basis_unfolds_exactly_at_every_new_operator_dim_point() {
    const STEPS: u64 = 1_000_000;
    let cases: &[(usize, u64, u64, usize)] = &[
        (6, 3, 1, 7),  // 9 lanes - 2 singular
        (4, 3, 1, 7),  // 9 lanes - 2 singular
        (8, 5, 2, 6),  // 9 lanes - 3 singular
        (8, 7, 2, 6),  // 9 lanes - 3 singular
    ];

    for &(dim, a, b, expected_rev) in cases {
        let full = basis();
        let gate = ArrowStep::for_heat(dim, a, b, STEPS, &full).reversible_lanes(a, b);
        let rev: Vec<u64> = full
            .iter()
            .zip(gate.iter())
            .filter(|(_, &ok)| ok)
            .map(|(&p, _)| p)
            .collect();
        assert_eq!(
            rev.len(),
            expected_rev,
            "reversible lane count for [{b},{a},{b}] dim={dim} is pinned"
        );

        let arrow = ArrowStep::for_heat(dim, a, b, STEPS, &rev);
        let initial = seeded_state(dim, &rev);
        let emitted = arrow.apply(&initial);
        let recovered = arrow
            .unfold(a, b, &emitted)
            .expect("every lane in the reversible sub-basis must unfold");
        assert_eq!(
            recovered, initial,
            "unfold(fold(state)) must be the EXACT initial state for \
             [{b},{a},{b}] dim={dim}"
        );
    }
}

/// `A * A^-1 == I` on every lane the gate accepted, at each new point. Guards
/// against a gate that answers `true` while `mat_inv_mod` returns something
/// that is not actually the inverse.
#[test]
fn inverse_is_a_true_inverse_at_every_new_operator_dim_point() {
    for &(dim, a, b) in &[(6usize, 3u64, 1u64), (4, 3, 1), (8, 5, 2), (8, 7, 2)] {
        for &p in &basis() {
            let single = heat_circulant(dim, a, b, p);
            let Some(inv) = mat_inv_mod(&single, dim, p) else {
                continue; // gate said one-way; the refusal tests cover that
            };
            let prod = mat_mul_mod(&single, &inv, dim, p);
            let mut id = vec![0u64; dim * dim];
            for i in 0..dim {
                id[i * dim + i] = 1 % p;
            }
            assert_eq!(
                prod, id,
                "A * A^-1 != I mod {p} for [{b},{a},{b}] dim={dim}"
            );
        }
    }
}
