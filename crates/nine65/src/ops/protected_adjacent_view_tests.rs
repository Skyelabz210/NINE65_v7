//! Conditional consumers of client-supplied views. These tests do not create
//! a public producer of r36/r37 from the native encrypted Y.

use super::*;
use crate::entropy::ShadowHarvester;
use crate::ops::direct_slot_phase::SlotEncoding;
use crate::ops::public_refresh_circuit::PublicRefreshCircuitPlan;
use crate::ops::public_refresh_slots::PublicSlotReturn;
use crate::params::FHEConfig;

const P: u64 = 65_537;
const PRIMES: [u64; 13] = [
    998244353,
    985661441,
    754974721,
    469762049,
    576460752301785089,
    576460752301391873,
    576460752300015617,
    576460752298835969,
    576460752298180609,
    576460752293134337,
    576460752291954689,
    576460752290775041,
    575870995836829697,
];

fn config(n: usize, t: u64, lanes: usize) -> FHEConfig {
    FHEConfig {
        n,
        primes: PRIMES[..lanes].to_vec(),
        q: PRIMES[0],
        t,
        eta: 3,
        security_bits: 0,
        name: "INSECURE preproduced adjacent-view consumer oracle",
    }
}

// For authentic views of Y in [0,96], d=r36-r37 is one of
// {-36,-35,0,1,2}. This polynomial is canonical d mod 37 on that set.
fn canonical_sheet_dag() -> (Dag, usize) {
    let mut dag = Dag::new(P);
    let minus_one = dag.constant(-1);
    let minus_two = dag.constant(-2);
    let d1 = dag.add(0, minus_one);
    let d2 = dag.add(0, minus_two);
    let scaled = dag.scale(0, 12783);
    let constant = dag.constant(19490);
    let affine = dag.add(scaled, constant);
    let left = dag.product(0, d1);
    let right = dag.product(d2, affine);
    let correction = dag.product(left, right);
    let output = dag.add(0, correction);
    (dag, output)
}

#[test]
fn linear_adjacency_consumes_compatible_views_but_cannot_change_plaintext_modulus() {
    let small = RNSFHEContext::try_new(&config(8, 37, 2)).unwrap();
    let native_field = RNSFHEContext::try_new(&config(8, P, 2)).unwrap();
    let mut rng = ShadowHarvester::with_seed(0x4144_4a41_4345_4e54);
    let small_keys = small.generate_keys(&mut rng);
    let native_keys = native_field.generate_keys(&mut rng);
    let mut native_mismatches = 0;
    for y in 0..=96 {
        // Only the client knows these clear views. No native view producer is
        // being exercised or admitted by this conditional consumer test.
        let g = y % 36;
        let a = y % 37;
        let cg = small.encrypt_with_rng(g, &small_keys.public_key, &mut rng);
        let ca = small.encrypt_with_rng(a, &small_keys.public_key, &mut rng);
        let sheet = small.sub(&cg, &ca);
        assert_eq!(small.decrypt(&sheet, &small_keys.secret_key), y / 36);

        let cg = native_field.encrypt_with_rng(g, &native_keys.public_key, &mut rng);
        let ca = native_field.encrypt_with_rng(a, &native_keys.public_key, &mut rng);
        let difference = native_field.sub(&cg, &ca);
        let observed = native_field.decrypt(&difference, &native_keys.secret_key);
        assert_eq!(observed, (g as i64 - a as i64).rem_euclid(P as i64) as u64);
        native_mismatches += usize::from(observed != y / 36);
    }
    // Y=36,72,73 need canonical correction.
    assert_eq!(native_mismatches, 3);

    // The same Q and key do not make plaintext-36 and plaintext-37 scales
    // compatible. This subtraction misdecodes Y=20's zero sheet as one.
    let modulus36 = RNSFHEContext::try_new(&config(8, 36, 2)).unwrap();
    let cg = modulus36.encrypt_with_rng(20, &small_keys.public_key, &mut rng);
    let ca = small.encrypt_with_rng(20, &small_keys.public_key, &mut rng);
    assert_eq!(
        small.decrypt(&small.sub(&cg, &ca), &small_keys.secret_key),
        1
    );
    assert!(SlotEncoding::new(32768, 37).is_err());
}

#[test]
fn derived_defect_is_tautological_and_zero_plaintext_need_not_have_zero_error() {
    let ctx = RNSFHEContext::try_new(&config(8, 37, 2)).unwrap();
    let mut rng = ShadowHarvester::with_seed(0x4445_4645_4354_3337);
    let keys = ctx.generate_keys(&mut rng);
    let cg = ctx.encrypt_with_rng(4, &keys.public_key, &mut rng);
    let ca = ctx.encrypt_with_rng(3, &keys.public_key, &mut rng);
    let sheet = ctx.sub(&cg, &ca);
    // In F_37, -36=1. Reusing the derived sheet cancels identically.
    let base = ctx.sub(&ca, &cg);
    let tautology = ctx.add(&base, &sheet);
    assert!(tautology.c0.limbs.iter().flatten().all(|&v| v == 0));
    assert!(tautology.c1.limbs.iter().flatten().all(|&v| v == 0));

    // A different valid encoding of the same sheet, with exactly one added
    // raw phase-error unit. The zero defect now has error one, not zero.
    let mut another_sheet = sheet;
    for (lane, &q) in ctx.config.primes.iter().enumerate() {
        let one = ctx.rns.mont_contexts[lane].to_montgomery(1);
        another_sheet.c0.limbs[lane][0] = (another_sheet.c0.limbs[lane][0] + one) % q;
    }
    assert_eq!(ctx.decrypt(&another_sheet, &keys.secret_key), 1);
    let defect = ctx.add(&base, &another_sheet);
    assert_eq!(ctx.decrypt(&defect, &keys.secret_key), 0);
    assert!(defect.c1.limbs.iter().flatten().all(|&v| v == 0));
    for (lane, mont) in ctx.rns.mont_contexts.iter().enumerate() {
        assert_eq!(mont.from_montgomery(defect.c0.limbs[lane][0]), 1);
    }
}

#[test]
fn bounded_adjacency_correction_evaluates_under_encryption_on_all_97_values() {
    let ctx = RNSFHEContext::try_new(&config(8, P, 4)).unwrap();
    let mut rng = ShadowHarvester::with_seed(0x4144_4a34_4649_454c);
    let keys = ctx.generate_keys(&mut rng);
    let exact = ctx.try_exact_evaluator().unwrap();
    let relin = exact.generate_hybrid_gadget_key_with_rng(&keys.secret_key, &mut rng);
    let (dag, output) = canonical_sheet_dag();
    let polynomial = dag.symbolic(output);
    assert_eq!(polynomial.len(), 5);
    assert_eq!(
        dag.nodes
            .iter()
            .filter(|n| matches!(n, Node::Product(..)))
            .count(),
        3
    );
    // Public-key error eta*(2N+1), plus a conservative ideal-grid charge p,
    // for each constant-message encryption before subtraction.
    let input = U1024::from_u64(2 * (3 * (2 * ctx.n as u64 + 1) + P));
    Noise::new(&ctx, &exact).unwrap().dag(&dag, input).unwrap();
    for y in 0..=96 {
        let g = y % 36;
        let a = y % 37;
        let d = (g as i64 - a as i64).rem_euclid(P as i64) as u64;
        assert_eq!(polynomial_value(&polynomial, d, P), y / 36);
        let cg = ctx.encrypt_with_rng(g, &keys.public_key, &mut rng);
        let ca = ctx.encrypt_with_rng(a, &keys.public_key, &mut rng);
        let result = evaluate_dag(
            &ctx,
            &exact,
            &dag,
            output,
            &ctx.sub(&cg, &ca),
            GadgetKeyView::Raw(&relin),
            "conditional adjacent consumer",
            &mut |_, _, _| {},
        )
        .unwrap();
        assert_eq!(ctx.decrypt(&result, &keys.secret_key), y / 36);
    }
}

#[test]
fn native_adjacency_consumer_budget_is_conditional_and_does_not_fund_slot_return() {
    let native = PublicRefreshCircuitPlan::native_research(4 << 30).unwrap();
    let ctx = RNSFHEContext::try_new(&config(32768, P, 13)).unwrap();
    let exact = ctx.try_exact_evaluator().unwrap();
    let ledger = Noise::new(&ctx, &exact).unwrap();
    let (dag, output) = canonical_sheet_dag();
    // Hypothesis only: two compatible views have each ALREADY been produced
    // with error <= the native carry bound. Their production cost is missing.
    let input = native
        .certificate()
        .carry_error_bound
        .checked_add(native.certificate().carry_error_bound)
        .unwrap();
    let error = ledger.dag(&dag, input).unwrap()[output];
    assert!(error < ledger.half);
    let inverse = PublicSlotReturn::new(&ctx, 8192).unwrap();
    let returned = error
        .checked_mul_u128(inverse.certificate().input_error_factor)
        .unwrap()
        .checked_add(U1024::from_u128(inverse.certificate().added_error))
        .unwrap();
    assert!(returned >= ledger.half);
    eprintln!(
        "conditional adjacency consumer: {} error bits; existing slot return: {}; half-Delta: {}",
        error.bit_length(),
        returned.bit_length(),
        ledger.half.bit_length()
    );
}
