//! Regression gates for K-Elimination safe-basis construction.

use nine65::arithmetic::KElimination;

#[test]
fn class_f_alpha_lanes_must_be_prime_and_distinct() {
    assert!(
        KElimination::try_new(&[15, 17], &[23]).is_err(),
        "CLASS-F alpha lanes must reject composite moduli"
    );
    assert!(
        KElimination::try_new(&[17, 17], &[23]).is_err(),
        "CLASS-F alpha lanes must reject duplicates"
    );
}

#[test]
fn class_r_beta_lanes_must_be_pairwise_coprime_and_distinct() {
    assert!(
        KElimination::try_new(&[17, 19], &[23, 46]).is_err(),
        "CLASS-R beta lanes must be pairwise coprime inside the family"
    );
    assert!(
        KElimination::try_new(&[17, 19], &[23, 23]).is_err(),
        "CLASS-R beta lanes must reject duplicates"
    );
}

#[test]
fn alpha_and_beta_families_must_be_cross_coprime() {
    assert!(
        KElimination::try_new(&[17, 19], &[23, 29]).is_ok(),
        "known safe basis must construct"
    );
    assert!(
        KElimination::try_new(&[17, 19], &[17, 23]).is_err(),
        "anchor family must be coprime to every CLASS-F lane"
    );
}

#[test]
fn zero_and_unit_moduli_are_rejected() {
    assert!(KElimination::try_new(&[0, 17], &[23]).is_err());
    assert!(KElimination::try_new(&[1, 17], &[23]).is_err());
    assert!(KElimination::try_new(&[17, 19], &[0, 23]).is_err());
    assert!(KElimination::try_new(&[17, 19], &[1, 23]).is_err());
}
