//! Public API regressions for the PR #170 review findings.
//! Expected arithmetic uses exact identities at the signed-integer boundary.

use exact_transcendentals::k_elim::{mod_inv, modd, mulmod};
use exact_transcendentals::lifted_transduction::{
    project_with_lift, transduct_with_lift, transduct_with_lift_provider, LiftEvidence,
    LiftedTransductionError, PrecomputedLiftEvidence,
};
use exact_transcendentals::transduction::{
    TransductionBasisError, TransductionBuildError, TransductionCapacityError, TransductionMap,
};

#[test]
fn builder_refuses_nonpositive_target_moduli() {
    for modulus in [0, -1, -7, i128::MIN] {
        for source in [&[3, 5][..], &[][..]] {
            assert!(matches!(
                TransductionMap::try_build(source, &[7, modulus]),
                Err(TransductionBuildError::Basis(
                    TransductionBasisError::InvalidTargetModulus { index: 1, modulus: m }
                )) if m == modulus
            ));
        }
    }
}

#[test]
fn shared_factor_and_overlapping_targets_remain_valid() {
    let source = [3, 5];
    let targets = [1, 3, 6, 10, 15, 6];
    let map = TransductionMap::try_build(&source, &targets).unwrap();
    for value in 0..15 {
        let residues = [value % 3, value % 5];
        let expected: Vec<_> = targets.iter().map(|b| value % b).collect();
        assert_eq!(map.apply(&residues), expected);
    }
}

#[test]
fn lifted_apis_refuse_accumulator_capacity_even_when_product_fits() {
    let source = [998244353, 985661441, 754974721, 469762049];
    assert!(source
        .iter()
        .try_fold(1i128, |acc, &a| acc.checked_mul(a))
        .is_some());
    let provider = PrecomputedLiftEvidence::new(&[0]);
    for result in [
        transduct_with_lift(&source, &[17], &[0; 4], &[0]),
        transduct_with_lift_provider(&source, &[17], &[0; 4], &provider),
    ] {
        assert!(matches!(
            result,
            Err(LiftedTransductionError::Capacity(
                TransductionCapacityError::InsufficientI128Capacity { .. }
            ))
        ));
    }
}

#[test]
fn normalization_and_inverse_cover_signed_extremes() {
    let m = i128::MAX;
    // i128::MIN = -m - 1, so its residue is m - 1.
    for (value, expected) in [
        (1, 1),
        (m - 1, m - 1),
        (m, 0),
        (-1, m - 1),
        (i128::MIN, m - 1),
    ] {
        assert_eq!(modd(value, m), expected);
        assert_eq!(modd(value, 1), 0);
    }
    assert_eq!(mod_inv(-2, m), Some((m - 1) / 2));
    assert_eq!(mod_inv(i128::MIN, m), Some(m - 1));
    assert_eq!(mod_inv(1, 0), None);
    assert_eq!(mod_inv(1, -7), None);
}

#[test]
fn multiplication_reduces_before_narrowing_to_i128() {
    for m in [i128::MAX, i128::MAX - 2, (1i128 << 126) + 1] {
        assert_eq!(mulmod(m - 1, m - 1, m), 1);
        assert_eq!(mulmod(m - 2, m - 3, m), 6);
        assert_eq!(mulmod(-2, -3, m), 6);
    }
    assert_eq!(mulmod(i128::MIN, i128::MIN, i128::MAX), 1);
    assert_eq!(mulmod((1i128 << 126) + 1, 2, i128::MAX), 3);
    // Independent widening oracle: these products fit u128, even when
    // they exceed i128. Also exercise composite and unit moduli.
    for a in [0u128, 1, 1 << 63, u64::MAX as u128] {
        for b in [0u128, 1, 1 << 63, u64::MAX as u128] {
            for m in [1i128, 6, 97, i128::MAX] {
                assert_eq!(
                    mulmod(a as i128, b as i128, m),
                    ((a * b) % m as u128) as i128
                );
            }
        }
    }
}

#[test]
fn projection_and_evidence_preserve_canonical_residues_at_i128_limit() {
    let m = i128::MAX;
    for (g, k, source_mod, expected) in [
        (1, 0, 1, 1),
        (m - 1, m - 1, m - 1, 0),
        (0, i128::MIN, i128::MIN, 1),
        (3, -1, 2, 1),
        (0, (1i128 << 126) + 1, 2, 3),
    ] {
        assert_eq!(project_with_lift(g, k, source_mod, m), Some(expected));
    }
    assert_eq!(LiftEvidence::new(0, m, 1).unwrap().k_mod_target(), 1);
    assert_eq!(
        LiftEvidence::new(0, m, i128::MIN).unwrap().k_mod_target(),
        m - 1
    );
}
