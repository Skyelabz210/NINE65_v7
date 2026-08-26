//! M2b — the elimination-first rescale on a manufactured chain, end to end.
//!
//! The chain is minted, not hunted: `Q = t·D1·D2` with `t = 65537` itself a
//! main lane and `D = (2N·j)·t + 1` prime, so `Δ = Q/t = D1·D2` EXACTLY and
//! every lane is `≡ 1 mod 2N` (NTT) and the Δ-lanes `≡ 1 mod t` (star
//! transparency) by construction. `mul_dual_public_manufactured` runs the
//! standard public pipeline with the rescale swapped to
//! `k_elim_rescale_manufactured`: align-and-drop (cross-lane READS only),
//! direct γ read off the t-lane, winding over a capacity-certified anchor
//! subset merged by parallel summation (R8) — no `to_u256_level`, no U256
//! value materialization, no Garner anywhere in the rescale.

use nine65::entropy::ShadowHarvester;
use nine65::ops::cram_public::{CramPublicEvaluator, EmissionClass};
use nine65::ops::rns_fhe::RNSFHEContext;
use nine65::params::FHEConfig;

fn cfg() -> FHEConfig {
    FHEConfig::manufactured_m2b_insecure()
}

#[test]
fn chain_is_manufactured_by_construction() {
    let c = cfg();
    let two_n = 2 * c.n as u64;
    let q_product: u128 = c.primes.iter().map(|&p| p as u128).product();

    assert_eq!(c.primes[0], c.t, "t itself is the surviving main lane");
    assert_eq!(q_product % c.t as u128, 0, "t | Q exactly — manufactured, not hunted");
    let delta = q_product / c.t as u128;
    let delta_expected: u128 = c.primes[1..].iter().map(|&p| p as u128).product();
    assert_eq!(delta, delta_expected, "Delta = Q/t is exactly the Delta-lane product");

    for &p in &c.primes {
        assert_eq!(p % two_n, 1, "lane {p} must be NTT-friendly (≡ 1 mod 2N)");
    }
    for &d in &c.primes[1..] {
        assert_eq!(d % c.t, 1, "Delta-lane {d} must be ≡ 1 mod t (star transparency)");
        let cc = (d - 1) / c.t;
        assert_eq!(cc % two_n, 0, "multiplier of {d} must be ≡ 0 mod 2N");
    }
    // Star transparency composes: Delta ≡ 1 (mod t), so on the t-lane the
    // encryption scaling is the identity.
    assert_eq!(delta % c.t as u128, 1);
}

#[test]
fn encrypt_decrypt_roundtrip_on_manufactured_chain() {
    let ctx = RNSFHEContext::new(&cfg());
    let mut rng = ShadowHarvester::with_seed(42);
    let keys = ctx.generate_keys_dual_full(&mut rng);
    for (i, m) in [0u64, 1, 2, 97, 30030, 65535, 65536].into_iter().enumerate() {
        let mut r = ShadowHarvester::with_seed(1000 + i as u64);
        let ct = ctx.encrypt_dual(m, &keys.public_key, &mut r);
        assert_eq!(ctx.decrypt_dual(&ct, &keys.secret_key), m % ctx.t);
    }
}

#[test]
fn m2b_public_multiply_roundtrip_battery() {
    let eval = CramPublicEvaluator::new(&cfg());
    let mut rng = ShadowHarvester::with_seed(8888);
    let (pk, client) = eval.keygen_with_rng(&mut rng);
    let mut eval = eval;

    let t = eval.context().t;
    let pairs: Vec<(u64, u64)> = vec![
        (2, 3), (6, 7), (0, 5), (1, 1), (255, 255), (251, 257),
        (1000, 65), (12345, 5), (100, 100), (65535, 1),
    ];
    for (i, (m1, m2)) in pairs.into_iter().enumerate() {
        let mut r1 = ShadowHarvester::with_seed(2000 + 2 * i as u64);
        let mut r2 = ShadowHarvester::with_seed(2001 + 2 * i as u64);
        let a = eval.encrypt_with_rng(m1, &client.public_key, &mut r1);
        let b = eval.encrypt_with_rng(m2, &client.public_key, &mut r2);
        let ab = eval
            .mul_manufactured(&a, &b, &pk)
            .unwrap_or_else(|e| panic!("m2b multiply failed on ({m1},{m2}): {e:?}"));
        assert_eq!(
            eval.decrypt(&ab, &client),
            (m1 as u128 * m2 as u128 % t as u128) as u64,
            "m2b multiply must decrypt exactly for ({m1},{m2})"
        );
    }
    println!("{}", eval.ledger().report());
}

#[test]
fn m2b_depth3_squaring_chain() {
    let eval = CramPublicEvaluator::new(&cfg());
    let mut rng = ShadowHarvester::with_seed(4242);
    let (pk, client) = eval.keygen_with_rng(&mut rng);
    let mut eval = eval;

    let mut r = ShadowHarvester::with_seed(7);
    let mut ct = eval.encrypt_with_rng(2, &client.public_key, &mut r);
    let mut expected = 2u64;
    for depth in 1..=3 {
        ct = eval
            .mul_manufactured(&ct, &ct, &pk)
            .unwrap_or_else(|e| panic!("m2b squaring failed at depth {depth}: {e:?}"));
        expected *= expected;
        assert_eq!(
            eval.decrypt(&ct, &client),
            expected,
            "depth-{depth} m2b squaring"
        );
    }
    assert_eq!(expected, 256);
}

/// M3 — the RNS-limb gadget relin through the PUBLIC evaluator surface
/// (`keygen_with_gadget_with_rng` / `mul_manufactured_gadget`).
///
/// SCOPED TO DEPTH 2, NOT 3 — see the DO-NOT header on
/// `ops::rns_fhe::tests::m3_rns_limb_relin_depth2_squaring_chain` for the
/// measured finding (30-seed sweep: depth 1-2 reliable, depth 3 fails in
/// 18/30 seeds — a real noise-budget limit of the single-full-lane-digit
/// gadget, not a correctness bug). Do not widen to depth 3 here either.
#[test]
fn m3_gadget_depth2_squaring_chain_through_evaluator() {
    let eval = CramPublicEvaluator::new(&cfg());
    let mut rng = ShadowHarvester::with_seed(9797);
    let (_pk, gadget, client) = eval
        .keygen_with_gadget_with_rng(&mut rng)
        .expect("gadget keygen on a manufactured chain");
    let mut eval = eval;

    let mut r = ShadowHarvester::with_seed(70);
    let mut ct = eval.encrypt_with_rng(2, &client.public_key, &mut r);
    let mut expected = 2u64;
    for depth in 1..=2 {
        ct = eval
            .mul_manufactured_gadget(&ct, &ct, &gadget)
            .unwrap_or_else(|e| panic!("m3 gadget squaring failed at depth {depth}: {e:?}"));
        expected *= expected;
        assert_eq!(
            eval.decrypt(&ct, &client),
            expected,
            "depth-{depth} m3 gadget squaring"
        );
    }
    assert_eq!(expected, 16);
    println!("{}", eval.ledger().report());
}

/// M4 — the gadget-relin multiply's ledger classification. Never-vacuous
/// both directions: the digit-based `mul_manufactured` (unchanged, still
/// `Materialization`) is checked on the SAME evaluator/ledger instance, so
/// a change that made everything read as `EliminationFirst` regardless of
/// path would be caught here too.
#[test]
fn manufactured_gadget_multiply_ledger_shows_elimination_first() {
    let eval = CramPublicEvaluator::new(&cfg());
    let mut rng = ShadowHarvester::with_seed(48120);
    let (pk, gadget, client) = eval
        .keygen_with_gadget_with_rng(&mut rng)
        .expect("gadget keygen");
    let mut eval = eval;

    let mut r1 = ShadowHarvester::with_seed(48121);
    let mut r2 = ShadowHarvester::with_seed(48122);
    let a = eval.encrypt_with_rng(3, &client.public_key, &mut r1);
    let b = eval.encrypt_with_rng(5, &client.public_key, &mut r2);

    let materialization_before = eval.ledger().materialization_count();
    let elimination_first_before = eval.ledger().elimination_first_count();

    let gadget_ct = eval
        .mul_manufactured_gadget(&a, &b, &gadget)
        .expect("gadget multiply");
    assert_eq!(eval.decrypt(&gadget_ct, &client), 15, "gadget multiply correctness");
    assert_eq!(
        eval.ledger().materialization_count(),
        materialization_before,
        "REGRESSION: mul_manufactured_gadget must NOT add a Materialization \
         ledger entry — its rescale (M2b) and relin (M3) are both \
         elimination-first"
    );
    assert_eq!(
        eval.ledger().elimination_first_count(),
        elimination_first_before + 1,
        "mul_manufactured_gadget must record exactly one new EliminationFirst event"
    );
    assert_eq!(
        eval.ledger().events().last().unwrap().class,
        EmissionClass::EliminationFirst
    );

    // Never-vacuous: the digit-based path, same evaluator/ledger, must
    // still record Materialization.
    let digit_ct = eval.mul_manufactured(&a, &b, &pk).expect("digit multiply");
    assert_eq!(eval.decrypt(&digit_ct, &client), 15, "digit multiply correctness");
    assert_eq!(
        eval.ledger().materialization_count(),
        materialization_before + 1,
        "guardrail-shape failure: the digit-based path must still record \
         Materialization — if this fails, the classifications aren't \
         actually distinguishing anything"
    );
}

/// Both rescale paths on the same inputs must agree at the plaintext level.
/// (Bit-level ciphertext equality is NOT asserted: the materializing path
/// centers signed values around Q/2 while the M2b path uses the derived
/// shift S = N·Q²; the two rounding conventions may differ by representation
/// while decrypting identically. The print records whether they happened to
/// agree bit-for-bit.)
#[test]
fn m2b_agrees_with_materializing_path_at_plaintext_level() {
    let ctx = RNSFHEContext::new(&cfg());
    let mut rng = ShadowHarvester::with_seed(31337);
    let keys = ctx.generate_keys_dual_full(&mut rng);

    let mut bit_equal = 0usize;
    let cases = [(6u64, 7u64), (100, 200), (65535, 3), (444, 555)];
    for (i, (m1, m2)) in cases.into_iter().enumerate() {
        let mut r1 = ShadowHarvester::with_seed(5000 + 2 * i as u64);
        let mut r2 = ShadowHarvester::with_seed(5001 + 2 * i as u64);
        let a = ctx.encrypt_dual(m1, &keys.public_key, &mut r1);
        let b = ctx.encrypt_dual(m2, &keys.public_key, &mut r2);

        let old = ctx
            .mul_dual_public(&a, &b, &keys.eval_key)
            .expect("materializing multiply");
        let new = ctx
            .mul_dual_public_manufactured(&a, &b, &keys.eval_key)
            .expect("m2b multiply");

        let d_old = ctx.decrypt_dual(&old, &keys.secret_key);
        let d_new = ctx.decrypt_dual(&new, &keys.secret_key);
        let want = (m1 as u128 * m2 as u128 % ctx.t as u128) as u64;
        assert_eq!(d_old, want, "materializing path wrong on ({m1},{m2})");
        assert_eq!(d_new, want, "m2b path wrong on ({m1},{m2})");
        if old.c0.main == new.c0.main && old.c1.main == new.c1.main {
            bit_equal += 1;
        }
    }
    println!("m2b vs materializing: {bit_equal}/4 cases bit-identical on main lanes");
}
