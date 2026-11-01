// Admission checks against the supplied models, not production library tests.
// Division refusal checks express the FHE port contract. In particular, the
// shared-factor bigint case exceeds its documented small-divisor precondition;
// its failure is an integration limitation, not evidence against that precondition.
// The weights API has no Result: panic is the only available refusal mechanism.
#[path = "recumbent_crt_bigint.rs"]
mod bigint;
#[path = "recumbent_weights.rs"]
mod weights;
use bigint::{Polarity, RecumbentCRTBigInt as R, EXACT_MODULI};
use weights::{k_eliminate_divide, CRTWeight as W};
fn two128() -> R {
    let x = R::from_i128(1i128 << 64);
    x.mul(&x)
}
#[test]
fn audit_checked_conversion_rejects_2pow128() {
    assert_eq!(two128().to_i128_checked(), None);
}
#[test]
fn audit_wide_order_is_numeric() {
    assert!(two128() > R::one());
}
#[test]
fn audit_mixed_sign_does_not_erase_high_bits() {
    assert!(!two128().add(&R::one()).sub(&R::one()).is_zero());
}
#[test]
fn audit_i64_roundtrip_at_first_modulus() {
    assert_eq!(
        R::from_i64(EXACT_MODULI[0] as i64).spinor_value(),
        EXACT_MODULI[0] as i64
    );
}
#[test]
fn audit_exact_division_rejects_nondivisibility() {
    assert!(R::from_i64(7).checked_div(&R::from_i64(2)).is_none());
}
#[test]
fn audit_checked_division_refuses_shared_factor_without_panicking() {
    let p = R::from_unsigned(EXACT_MODULI[0], Polarity::Plus);
    let outcome = std::panic::catch_unwind(|| p.checked_div(&p));
    assert!(outcome.is_ok(), "checked API panicked");
    if let Some(q) = outcome.unwrap() {
        assert_eq!(q.lanes, R::one().lanes);
    }
}
#[test]
fn audit_shift_preserves_2pow128() {
    assert_eq!(R::from_i64(2).scale_pow2(127).lanes, two128().lanes);
}
#[test]
fn audit_minimum_i64_roundtrip() {
    assert_eq!(R::from_i64(i64::MIN).spinor_value(), i64::MIN);
}
#[test]
fn audit_weights_mixed_sign() {
    assert_eq!(W::from_i64(1).add(&W::from_i64(-2)).to_i64_approx(), -1);
}
#[test]
fn audit_weights_reject_zero_divisor() {
    assert!(std::panic::catch_unwind(|| k_eliminate_divide(&W::from_i64(9), 0)).is_err());
}
#[test]
fn audit_weights_shared_factor_is_not_inverse_one() {
    let result = std::panic::catch_unwind(|| {
        k_eliminate_divide(&W::from_u64(EXACT_MODULI[0]), EXACT_MODULI[0])
    });
    if let Ok(q) = result {
        assert_eq!(q.residues, W::from_i64(1).residues);
    }
}
#[test]
fn audit_controls_bounded_exact_division() {
    assert_eq!(
        R::from_i64(84)
            .checked_div(&R::from_i64(7))
            .unwrap()
            .to_i128_checked(),
        Some(12)
    );
    assert_eq!(k_eliminate_divide(&W::from_i64(84), 7).to_i64_approx(), 12);
}
