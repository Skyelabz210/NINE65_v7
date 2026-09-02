//! Arrow-emission reversibility — permanent regression gate.
//!
//! Contract (measured 2026-08-12, CRAM index entry [35]): reversibility of
//! the folded operator A^N mod p is a property of (operator, dim, prime)
//! JOINTLY, not of the basis. For the heat stencil [1,3,1] at dim=8, lanes
//! {3, 5, 7} are singular — the arrow is one-way there — while every other
//! lane, including a 30-bit NTT prime, reverses exactly through 10^6 folded
//! steps. Two of the singular lanes sit in TRANSPORT_CORE: transport-lane
//! selection must consult the gate, never basis membership.
//!
//! Exact integer arithmetic throughout. No cascades: every lane folds,
//! gates, and unfolds independently.
use exact_transcendentals::arrow_step::{heat_circulant, mat_inv_mod, ArrowStep};

const DIM: usize = 8;
const A: u64 = 3;
const B: u64 = 1;
const STEPS: u64 = 1_000_000;

fn basis() -> Vec<u64> {
    // S8 basis (odd part) + a 30-bit NTT prime; includes the lanes measured
    // singular so the gate's negative answers stay pinned.
    vec![2, 3, 5, 7, 11, 13, 17, 19, 998244353]
}

#[test]
fn gate_pins_the_measured_singular_set() {
    let arrow = ArrowStep::for_heat(DIM, A, B, STEPS, &basis());
    let gate = arrow.reversible_lanes(A, B);

    let singular: Vec<u64> = basis()
        .iter()
        .zip(gate.iter())
        .filter(|(_, &ok)| !ok)
        .map(|(&p, _)| p)
        .collect();

    assert_eq!(
        singular,
        vec![3, 5, 7],
        "singular set for heat [1,3,1] dim=8 must stay exactly {{3,5,7}} — \
         a change here means the operator, dim, or gate changed"
    );
}

#[test]
fn reversible_lanes_unfold_exactly_through_a_million_steps() {
    let full = basis();
    let arrow_full = ArrowStep::for_heat(DIM, A, B, STEPS, &full);
    let gate = arrow_full.reversible_lanes(A, B);

    // Reversible sub-basis only.
    let rev: Vec<u64> = full
        .iter()
        .zip(gate.iter())
        .filter(|(_, &ok)| ok)
        .map(|(&p, _)| p)
        .collect();
    assert_eq!(
        rev.len(),
        6,
        "6/9 lanes reversible per the measured contract"
    );

    let arrow = ArrowStep::for_heat(DIM, A, B, STEPS, &rev);
    let initial: Vec<Vec<u64>> = rev
        .iter()
        .map(|&p| (0..DIM as u64).map(|i| (i * 5 + 3) % p).collect())
        .collect();

    let emitted = arrow.apply(&initial);
    let recovered = arrow
        .unfold(A, B, &emitted)
        .expect("every lane in the reversible sub-basis must unfold");

    assert_eq!(
        recovered, initial,
        "unfold(fold(state)) must be the EXACT initial state on every lane"
    );
}

#[test]
fn unfold_refuses_partial_reversal_loudly() {
    // Basis containing a singular lane: unfold must return None rather than
    // silently unfolding the reversible lanes and desynchronising the rest
    // (T-X-PROJ: discarding information is projection, not reversal).
    let mixed = vec![3u64, 11, 13]; // 3 is singular for this operator/dim
    let arrow = ArrowStep::for_heat(DIM, A, B, 10, &mixed);
    let initial: Vec<Vec<u64>> = mixed
        .iter()
        .map(|&p| (0..DIM as u64).map(|i| (i + 1) % p).collect())
        .collect();
    let emitted = arrow.apply(&initial);
    assert!(
        arrow.unfold(A, B, &emitted).is_none(),
        "unfold over a basis containing a singular lane must refuse, not project"
    );
}

#[test]
fn inverse_sanity_on_reversible_lanes() {
    for &p in &[2u64, 11, 13, 17, 19, 998244353] {
        let single = heat_circulant(DIM, A, B, p);
        let inv =
            mat_inv_mod(&single, DIM, p).unwrap_or_else(|| panic!("lane {p} expected reversible"));
        // A * A^-1 == I, lanewise exact
        let prod = exact_transcendentals::arrow_step::mat_mul_mod(&single, &inv, DIM, p);
        let mut id = vec![0u64; DIM * DIM];
        for i in 0..DIM {
            id[i * DIM + i] = 1;
        }
        assert_eq!(prod, id, "A * A^-1 != I mod {p}");
    }
}
