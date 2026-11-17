use super::*;
use crate::entropy::ShadowHarvester;
use crate::params::SecureConfig;

fn setup(n: usize) -> (CramMainClient, CramMainEvaluator) {
    let mut config = SecureConfig::secure_256().into_config();
    config.n = n;
    config.t = 3;
    config.security_bits = 0;
    config.name = "encrypted GCD research arithmetic";
    CramMainEvaluator::generate_with_rng(&config, &mut ShadowHarvester::with_seed(0x6cd65)).unwrap()
}

fn check_coefficients(client: &CramMainClient, word: &EncryptedUint, expected: u64) {
    let ctx = &client.state.ctx;
    let scale = CanonicalScaleRound::new(&ctx.config.primes, ctx.t).unwrap();
    for (i, bit) in word.bits.iter().enumerate() {
        let phase = ctx.convert_from_montgomery_form(
            &bit.raw
                .c0
                .add(&ctx.rns_poly_mul(&bit.raw.c1, &client.secret.s), &ctx.rns),
        );
        for coefficient in 0..ctx.n {
            let residues: Vec<_> = phase.limbs.iter().map(|lane| lane[coefficient]).collect();
            let expected = if coefficient == 0 {
                (expected >> i) & 1
            } else {
                0
            };
            assert_eq!(scale.scale_round(&residues).unwrap(), expected);
        }
    }
}

#[test]
fn encrypted_gcd_one_bit_exhaustive_and_public_schedule() {
    let (client, eval) = setup(8);
    let mut public = crate::ops::cram_public::CramPublicEvaluator::new(eval.config());
    let words: Vec<_> = (0..2).map(|x| eval.encrypt_uint(x, 1).unwrap()).collect();
    let mut previous_plan = None;
    for a in 0..2 {
        for b in 0..2 {
            let plan = eval.plan_integer_gcd(&words[a], &words[b]).unwrap();
            let shape = (
                plan.rounds(),
                plan.gates(),
                plan.multiplications(),
                plan.output_budget_millibits(),
            );
            if let Some(previous) = previous_plan {
                assert_eq!(shape, previous);
            }
            previous_plan = Some(shape);
            let result = public.gcd_integer(&words[a], &words[b], &eval).unwrap();
            let expected = (a | b) as u64;
            assert_eq!(client.decrypt_uint(&result).unwrap(), expected);
            check_coefficients(&client, &result, expected);
            assert_eq!(client.decrypt_uint(&words[a]).unwrap(), a as u64);
        }
    }
    assert_eq!(public.ledger().events().len(), 4);
    assert!(public
        .ledger()
        .events()
        .iter()
        .all(|event| event.op == "gcd_integer"));
    eprintln!(
        "encrypted GCD n=8 exhaustive one-bit plan: {:?}",
        previous_plan.unwrap()
    );
}

#[test]
fn encrypted_gcd_width_key_and_noise_refusals() {
    let (_, eval) = setup(8);
    let (_, foreign_eval) = setup(8);
    let one = eval.encrypt_uint(1, 1).unwrap();
    let foreign = foreign_eval.encrypt_uint(1, 1).unwrap();
    for (a, b) in [(&one, &foreign), (&foreign, &one)] {
        assert!(matches!(
            eval.gcd_integer(a, b),
            Err(IntegerDivisionError::Evaluator(
                CramMainError::DomainMismatch
            ))
        ));
    }
    let wide = eval.encrypt_uint(1, 9).unwrap();
    assert!(matches!(
        eval.plan_integer_gcd(&one, &wide),
        Err(IntegerDivisionError::GcdWidth)
    ));
    let eight = eval.encrypt_uint(255, 8).unwrap();
    assert!(matches!(
        eval.plan_integer_gcd(&eight, &eight),
        Err(IntegerDivisionError::Noise { .. })
    ));
    assert!(matches!(
        eval.plan_integer_gcd_with_strategy(&eight, &one, IntegerGcdStrategy::SmallTruthTable),
        Err(IntegerDivisionError::GcdTableWidth)
    ));
    let mut wrong = eval.config().clone();
    wrong.t = 5;
    let mut public = crate::ops::cram_public::CramPublicEvaluator::new(&wrong);
    assert!(matches!(
        public.gcd_integer(&one, &one, &eval),
        Err(IntegerDivisionError::Evaluator(
            CramMainError::DomainMismatch
        ))
    ));
    assert!(public.ledger().events().is_empty());
}

#[test]
fn encrypted_gcd_direct_target_covers_all_small_widths() {
    let (client, eval) = setup(8);
    for width in 1..=4 {
        let largest = (1u64 << width) - 1;
        for (a, b) in [
            (0, 0),
            (largest, 0),
            (largest, largest),
            (largest, largest - 1),
        ] {
            let (mut x, mut y) = (a, b);
            while y != 0 {
                (x, y) = (y, x % y);
            }
            let aa = eval.encrypt_uint(a, width).unwrap();
            let bb = eval.encrypt_uint(b, width).unwrap();
            let plan = eval.plan_integer_gcd(&aa, &bb).unwrap();
            assert_eq!(plan.strategy(), IntegerGcdStrategy::SmallTruthTable);
            let result = eval.gcd_integer(&aa, &bb).unwrap();
            assert_eq!(client.decrypt_uint(&result).unwrap(), x);
            check_coefficients(&client, &result, x);
            eprintln!(
                "DIRECT GCD n=8 width={width} gcd({a},{b})={x} products={} budget={}",
                plan.multiplications(),
                plan.output_budget_millibits()
            );
        }
    }
}

#[test]
fn encrypted_gcd_profiles_and_admitted_two_bit_cases() {
    let (client, eval) = setup(8);
    let mut admitted = 0;
    for width in 1..=8 {
        let word = eval.encrypt_uint(0, width).unwrap();
        match eval.plan_integer_gcd_with_strategy(&word, &word, IntegerGcdStrategy::FixedEuclid) {
            Ok(plan) => {
                admitted += 1;
                eprintln!(
                    "GCD width {width}: rounds={}, gates={}, products={}, budget={}",
                    plan.rounds(),
                    plan.gates(),
                    plan.multiplications(),
                    plan.output_budget_millibits()
                );
                if width == 2 {
                    for (a, b, expected) in [
                        (0, 0, 0),
                        (0, 3, 3),
                        (3, 0, 3),
                        (2, 2, 2),
                        (3, 2, 1),
                        (2, 3, 1),
                    ] {
                        let aa = eval.encrypt_uint(a, 2).unwrap();
                        let bb = eval.encrypt_uint(b, 2).unwrap();
                        let gcd = eval
                            .gcd_integer_with_strategy(&aa, &bb, IntegerGcdStrategy::FixedEuclid)
                            .unwrap();
                        assert_eq!(client.decrypt_uint(&gcd).unwrap(), expected);
                        check_coefficients(&client, &gcd, expected);
                    }
                }
            }
            Err(IntegerDivisionError::Noise { gate, reason }) => {
                eprintln!("GCD width {width}: REFUSED at gate {gate}: {reason}")
            }
            Err(error) => panic!("unexpected GCD admission result: {error}"),
        }
    }
    assert!(admitted >= 1);
}

#[test]
fn native_encrypted_gcd_checks_every_plaintext_coefficient() {
    let mut config = SecureConfig::secure_128().into_config();
    config.t = 3;
    config.name = "native encrypted GCD t3";
    let (client, eval) =
        CramMainEvaluator::generate_with_rng(&config, &mut ShadowHarvester::with_seed(0x6cd8192))
            .unwrap();
    for (a, b, expected, width) in [(0, 0, 0, 1), (1, 0, 1, 1)] {
        let aa = eval.encrypt_uint(a, width).unwrap();
        let bb = eval.encrypt_uint(b, width).unwrap();
        let plan = eval
            .plan_integer_gcd_with_strategy(&aa, &bb, IntegerGcdStrategy::FixedEuclid)
            .unwrap();
        eprintln!(
            "native GCD n={} width={} gcd({a},{b})={expected} rounds={} products={} budget={}",
            config.n,
            width,
            plan.rounds(),
            plan.multiplications(),
            plan.output_budget_millibits()
        );
        let result = eval
            .gcd_integer_with_strategy(&aa, &bb, IntegerGcdStrategy::FixedEuclid)
            .unwrap();
        assert_eq!(client.decrypt_uint(&result).unwrap(), expected);
        check_coefficients(&client, &result, expected);
    }
    let aa = eval.encrypt_uint(3, 2).unwrap();
    let bb = eval.encrypt_uint(2, 2).unwrap();
    assert!(matches!(
        eval.plan_integer_gcd_with_strategy(&aa, &bb, IntegerGcdStrategy::FixedEuclid),
        Err(IntegerDivisionError::Noise { .. })
    ));
    for (a, b, expected) in [(3, 2, 1), (0, 0, 0), (2, 2, 2)] {
        let aa = eval.encrypt_uint(a, 2).unwrap();
        let bb = eval.encrypt_uint(b, 2).unwrap();
        let plan = eval.plan_integer_gcd(&aa, &bb).unwrap();
        assert_eq!(plan.strategy(), IntegerGcdStrategy::SmallTruthTable);
        assert_eq!(plan.rounds(), 0);
        assert!(plan.multiplications() < 54);
        eprintln!(
            "native DIRECT GCD n={} width=2 gcd({a},{b})={expected} products={} budget={}",
            config.n,
            plan.multiplications(),
            plan.output_budget_millibits()
        );
        let result = eval.gcd_integer(&aa, &bb).unwrap();
        assert_eq!(client.decrypt_uint(&result).unwrap(), expected);
        check_coefficients(&client, &result, expected);
    }
}

#[test]
fn large_ring_research_gcd_two_bit_refuses_exhausted_budget() {
    // Larger existing modulus chain, deliberately a research tuple rather
    // than a security admission for this modified n/t configuration.
    let (client, eval) = setup(8192);
    let aa = eval.encrypt_uint(3, 2).unwrap();
    let bb = eval.encrypt_uint(2, 2).unwrap();
    let result = eval.plan_integer_gcd_with_strategy(&aa, &bb, IntegerGcdStrategy::FixedEuclid);
    assert!(matches!(result, Err(IntegerDivisionError::Noise { .. })));
    // Refusal does not mutate the original encrypted inputs.
    assert_eq!(client.decrypt_uint(&aa).unwrap(), 3);
    assert_eq!(client.decrypt_uint(&bb).unwrap(), 2);
}

#[test]
fn encrypted_gcd_history_eventually_refuses_without_reset() {
    let (client, eval) = setup(8);
    let original = eval.encrypt_uint(1, 1).unwrap();
    let zero = eval.encrypt_uint(0, 1).unwrap();
    let mut word = original.clone();
    let mut completed = 0;
    let mut refused = false;
    for _ in 0..16 {
        match eval.gcd_integer_with_strategy(&word, &zero, IntegerGcdStrategy::FixedEuclid) {
            Ok(next) => {
                assert_eq!(client.decrypt_uint(&next).unwrap(), 1);
                word = next;
                completed += 1;
            }
            Err(IntegerDivisionError::Noise { .. }) => {
                refused = true;
                break;
            }
            Err(error) => panic!("unexpected history error: {error}"),
        }
    }
    assert!(completed > 0 && refused);
    assert_eq!(client.decrypt_uint(&original).unwrap(), 1);
    eprintln!("GCD repeated-history completed={completed}, then typed noise refusal");
}
