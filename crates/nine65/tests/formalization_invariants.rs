//! Formalization integration tests
//!
//! These tests exercise proof-aligned invariants to keep the
//! proof-to-code linkage alive in CI.

use nine65::arithmetic::{
    ExactDivider, IntegerSoftmax, MobiusInt, PadeEngine, PADE_SCALE, SOFTMAX_SCALE,
};

#[test]
fn test_integer_softmax_sum_exact() {
    let softmax = IntegerSoftmax::new();
    let cases = [
        vec![0i128, 0, 0],
        vec![1i128, 2, 3],
        vec![-3i128, 0, 3],
        vec![42i128],
    ];

    for logits in cases {
        let output = softmax.compute(&logits);
        let sum: u128 = output.iter().sum();
        assert_eq!(sum, SOFTMAX_SCALE, "softmax sum must equal scale");
    }
}

#[test]
fn test_mobius_int_add_roundtrip() {
    let a = MobiusInt::from_i64(7);
    let b = MobiusInt::from_i64(-3);
    let c = a.add(&b);
    let d = b.add(&a);

    assert_eq!(c.spinor_value(), 4);
    assert_eq!(d.spinor_value(), 4);

    let zero = b.neg().add(&b);
    assert_eq!(zero.spinor_value(), 0);
}

#[test]
fn test_pade_engine_zero_identities() {
    let engine = PadeEngine::default();

    assert_eq!(engine.exp_integer(0), PADE_SCALE);
    assert_eq!(engine.sin_integer(0), 0);
    assert_eq!(engine.cos_integer(0), PADE_SCALE);
    assert_eq!(engine.tanh_integer(0), 0);
    assert_eq!(engine.sigmoid_integer(0), PADE_SCALE / 2);
}

#[test]
fn test_exact_divider_roundtrip() {
    let divider = ExactDivider::new(97, 89);
    let x: u128 = 861; // 7 * 123, and 861 < 97 * 89
    let (m_res, a_res) = divider.encode(x);

    let reconstructed = divider.reconstruct_exact(m_res, a_res);
    assert_eq!(reconstructed, x);

    let quotient = divider.exact_divide(m_res, a_res, 7);
    assert_eq!(quotient, 123);
}
