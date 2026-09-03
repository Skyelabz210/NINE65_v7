//! External-crate compile and behavior gate for the promoted lift-aware
//! transduction module.
//!
//! `exact_transcendentals::lifted_transduction` is now a real, exported
//! module (`pub mod lifted_transduction;` in `lib.rs`) rather than a staged
//! sibling source file — the theorem battery below exercises it exactly as
//! any downstream crate would, through the public API only.

use exact_transcendentals::k_elim::modd;
use exact_transcendentals::lifted_transduction::{
    project_with_lift, transduct_with_lift, transduct_with_lift_provider, LiftEvidence,
    LiftEvidenceProvider, LiftedTransductionError, PrecomputedLiftEvidence,
};
use exact_transcendentals::transduction::{S6_BASIS, S8_BASIS};

fn residues(x: i128, basis: &[i128]) -> Vec<i128> {
    basis.iter().map(|&m| modd(x, m)).collect()
}

#[test]
fn exported_module_resolves_first_s6_wrap() {
    let x = 30_030i128;
    let source = residues(x, &S6_BASIS);
    assert_eq!(source, residues(0, &S6_BASIS));

    // The phase-lock layer derives K=1 for the first wrapped S6 sheet. The
    // transducer consumes only K modulo each target lane.
    let k_mod_targets: Vec<i128> = S8_BASIS.iter().map(|&b| 1 % b).collect();
    let out = transduct_with_lift(&S6_BASIS, &S8_BASIS, &source, &k_mod_targets)
        .expect("lift-aware transduction must accept the certified first sheet");

    assert_eq!(out, residues(x, &S8_BASIS));
    assert_eq!((out[6], out[7]), (8, 10));
}

#[test]
fn exported_projection_handles_shared_factor_composites() {
    let m = 30_030i128;
    let g = 29i128;
    let k = 17i128;
    let x = g + k * m;

    for b in [1i128, 4, 6, 9, 12, 18, 35, 77, 143, 256] {
        let got = project_with_lift(modd(g, b), modd(k, b), modd(m, b), b)
            .expect("positive target modulus");
        assert_eq!(got, modd(x, b), "b={b}");
    }
}

#[test]
fn exported_typed_provider_api_matches_the_slice_api_from_outside_the_crate() {
    let x = 30_030i128;
    let source = residues(x, &S6_BASIS);
    let k_mod_targets: Vec<i128> = S8_BASIS.iter().map(|&b| 1 % b).collect();

    let via_slice = transduct_with_lift(&S6_BASIS, &S8_BASIS, &source, &k_mod_targets).unwrap();

    let provider = PrecomputedLiftEvidence::new(&k_mod_targets);
    let via_provider =
        transduct_with_lift_provider(&S6_BASIS, &S8_BASIS, &source, &provider).unwrap();

    assert_eq!(via_slice, via_provider);
}

#[test]
fn exported_closure_provider_derives_k_on_demand() {
    // A downstream caller's phase-lock/anchor mechanism can be a plain
    // closure: no per-lane Vec is ever materialized ahead of time.
    let x = 30_030i128;
    let source = residues(x, &S6_BASIS);
    let k = 1i128;
    let provider = |_lane: usize, target_modulus: i128| -> Result<i128, LiftedTransductionError> {
        Ok(modd(k, target_modulus))
    };

    let out = transduct_with_lift_provider(&S6_BASIS, &S8_BASIS, &source, &provider).unwrap();
    assert_eq!(out, residues(x, &S8_BASIS));
}

#[test]
fn exported_absent_evidence_and_bad_source_basis_fail_closed() {
    let source = vec![0i128; S6_BASIS.len()];

    // Absent evidence: only 1 of 8 target lanes supplied.
    let short = [0i128];
    let provider = PrecomputedLiftEvidence::new(&short);
    let err = transduct_with_lift_provider(&S6_BASIS, &S8_BASIS, &source, &provider).unwrap_err();
    assert_eq!(
        err,
        LiftedTransductionError::EvidenceUnavailable { lane: 1 }
    );

    // Non-pairwise-coprime source basis: must fail closed, not panic.
    let bad_basis = [6i128, 9, 5];
    let bad_source = vec![0i128; 3];
    let k_mod_targets = vec![0i128; S8_BASIS.len()];
    let err = transduct_with_lift(&bad_basis, &S8_BASIS, &bad_source, &k_mod_targets).unwrap_err();
    assert!(matches!(
        err,
        LiftedTransductionError::SourceBasisNotPairwiseCoprime { .. }
    ));

    // Directly constructing evidence against a non-positive modulus fails
    // closed too.
    assert!(LiftEvidence::new(0, 0, 5).is_err());
}
