use super::*;
use crate::entropy::ShadowHarvester;
use crate::params::SecureConfig;

fn setup(n: usize, t: u64) -> (CramMainClient, CramMainEvaluator) {
    let mut config = SecureConfig::secure_256().into_config();
    config.n = n;
    config.t = t;
    config.security_bits = 0;
    config.name = "encrypted integer division test";
    CramMainEvaluator::generate_with_rng(&config, &mut ShadowHarvester::with_seed(0xdecaf)).unwrap()
}

#[test]
fn encrypted_division_small_words_and_zero_status() {
    let (client, evaluator) = setup(8, 3);
    let inputs: Vec<_> = (0..8)
        .map(|n| evaluator.encrypt_uint(n, 3).unwrap())
        .collect();
    for n in 0..8 {
        for d in 0..8 {
            let result = evaluator.divide_integer(&inputs[n], &inputs[d]).unwrap();
            let got = client.decrypt_division(&result).unwrap();
            let expected = if d == 0 {
                (0, n, true)
            } else {
                (n / d, n % d, false)
            };
            assert_eq!(
                (
                    got.quotient as usize,
                    got.remainder as usize,
                    got.divide_by_zero
                ),
                expected
            );
        }
    }
}

#[test]
fn native_integer_division_preflight_profiles() {
    for (secure, max_width) in [
        (SecureConfig::secure_128(), 1),
        (SecureConfig::secure_192(), 2),
        (SecureConfig::secure_256(), 4),
    ] {
        let config = secure.into_config();
        let (_, eval) = CramMainEvaluator::generate_with_rng(
            &config,
            &mut ShadowHarvester::with_seed(0xc1ac017),
        )
        .unwrap();
        for width in 1..=5 {
            let a = eval.encrypt_uint(0, width).unwrap();
            let result = eval.plan_integer_division(&a, &a);
            assert_eq!(
                result.is_ok(),
                width <= max_width,
                "{} width {width}",
                config.name
            );
            match result {
                Ok(p) => eprintln!(
                    "{} width {width}: {} products, {} millibits",
                    config.name,
                    p.multiplications(),
                    p.output_budget_millibits()
                ),
                Err(e) => eprintln!("{} width {width}: {e}", config.name),
            }
        }
    }
}

#[test]
fn encrypted_divisor_sharing_a_ciphertext_lane() {
    let mut config = SecureConfig::secure_256().into_config();
    config.n = 2;
    config.t = 3;
    config.security_bits = 0;
    config.name = "shared-lane encrypted integer division test";
    config.primes = vec![17];
    config
        .primes
        .extend_from_slice(&crate::keys::bootstrap::BOOTSTRAP_PRIMES[..7]);
    config.q = 17;
    for seed in [0xfac701, 0xfac702, 0xfac703] {
        let (client, eval) =
            CramMainEvaluator::generate_with_rng(&config, &mut ShadowHarvester::with_seed(seed))
                .unwrap();
        for (n, d) in [(31, 17), (17, 17), (16, 17), (31, 0)] {
            let a = eval.encrypt_uint(n, 5).unwrap();
            let b = eval.encrypt_uint(d, 5).unwrap();
            let result = eval.divide_integer(&a, &b).unwrap();
            let expected = if d == 0 {
                UnsignedDivRem {
                    quotient: 0,
                    remainder: n,
                    divide_by_zero: true,
                }
            } else {
                UnsignedDivRem {
                    quotient: n / d,
                    remainder: n % d,
                    divide_by_zero: false,
                }
            };
            assert_eq!(client.decrypt_division(&result).unwrap(), expected);
            check_all_coefficients(&client, &result, &expected);
        }
    }
}

fn check_all_coefficients(
    client: &CramMainClient,
    result: &EncryptedDivRem,
    expected: &UnsignedDivRem,
) {
    let ctx = &client.state.ctx;
    let scale = CanonicalScaleRound::new(&ctx.config.primes, ctx.t).unwrap();
    let bits = result
        .quotient
        .bits
        .iter()
        .enumerate()
        .map(|(i, c)| (c, (expected.quotient >> i) & 1))
        .chain(
            result
                .remainder
                .bits
                .iter()
                .enumerate()
                .map(|(i, c)| (c, (expected.remainder >> i) & 1)),
        )
        .chain(std::iter::once((
            &result.divide_by_zero,
            u64::from(expected.divide_by_zero),
        )));
    for (bit, expected_bit) in bits {
        let phase = ctx.convert_from_montgomery_form(
            &bit.raw
                .c0
                .add(&ctx.rns_poly_mul(&bit.raw.c1, &client.secret.s), &ctx.rns),
        );
        for coefficient in 0..ctx.n {
            let residues: Vec<_> = phase.limbs.iter().map(|lane| lane[coefficient]).collect();
            let expected_coefficient = if coefficient == 0 { expected_bit } else { 0 };
            assert_eq!(scale.scale_round(&residues).unwrap(), expected_coefficient);
        }
    }
}

#[test]
fn integer_ingress_checks_width_and_key_domain() {
    let (client, eval) = setup(8, 3);
    for width in [0, 65] {
        assert!(matches!(
            eval.encrypt_uint(0, width),
            Err(IntegerDivisionError::Width)
        ));
    }
    assert!(matches!(
        eval.encrypt_uint(8, 3),
        Err(IntegerDivisionError::InputRange)
    ));
    let wide = eval.encrypt_uint(u64::MAX, 64).unwrap();
    assert_eq!(client.decrypt_uint(&wide).unwrap(), u64::MAX);
    assert!(matches!(
        eval.divide_integer(&wide, &wide),
        Err(IntegerDivisionError::Noise { .. })
    ));
    let (_, other) = setup(8, 3);
    let foreign = other.encrypt_uint(3, 3).unwrap();
    let a = eval.encrypt_uint(7, 3).unwrap();
    assert!(matches!(
        eval.divide_integer(&a, &foreign),
        Err(IntegerDivisionError::Evaluator(
            CramMainError::DomainMismatch
        ))
    ));
    assert!(matches!(
        eval.divide_integer(&foreign, &a),
        Err(IntegerDivisionError::Evaluator(
            CramMainError::DomainMismatch
        ))
    ));
    assert!(matches!(
        client.decrypt_uint(&foreign),
        Err(CramMainError::DomainMismatch)
    ));
    assert_eq!(client.decrypt_uint(&a).unwrap(), 7);
}

#[test]
fn division_preserves_history_and_hides_zero_in_public_metadata() {
    let (client, eval) = setup(8, 3);
    let original = eval.encrypt_uint(7, 3).unwrap();
    let zero = eval.encrypt_uint(0, 3).unwrap();
    let divisor = eval.encrypt_uint(2, 3).unwrap();
    let a = eval.divide_integer(&original, &zero).unwrap();
    let b = eval.divide_integer(&original, &divisor).unwrap();
    let plan_a = eval.plan_integer_division(&original, &zero).unwrap();
    let plan_b = eval.plan_integer_division(&original, &divisor).unwrap();
    assert_eq!(plan_a.gates(), plan_b.gates());
    assert_eq!(plan_a.multiplications(), plan_b.multiplications());
    assert_eq!(a.divide_by_zero.bound, b.divide_by_zero.bound);
    for (x, y) in a
        .quotient
        .bits
        .iter()
        .chain(&a.remainder.bits)
        .zip(b.quotient.bits.iter().chain(&b.remainder.bits))
    {
        assert_eq!(x.bound, y.bound);
    }
    let mut numerator = original.clone();
    let mut expected = 7;
    let mut completed = 0;
    loop {
        match eval.divide_integer(&numerator, &divisor) {
            Ok(result) => {
                expected /= 2;
                assert_eq!(client.decrypt_uint(&result.quotient).unwrap(), expected);
                numerator = result.quotient;
                completed += 1;
                assert!(completed < 16);
            }
            Err(IntegerDivisionError::Noise { .. }) => break,
            Err(e) => panic!("unexpected refusal: {e}"),
        }
    }
    assert!(completed >= 2);
    assert_eq!(client.decrypt_uint(&original).unwrap(), 7);
}
