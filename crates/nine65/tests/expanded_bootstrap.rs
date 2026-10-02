//! Real encrypted expanded-phase checks. Secret keys are used only by test
//! oracles; the evaluator takes public components and its encrypted work key.

use nine65::arithmetic::canonical_scale_round::CanonicalScaleRound;
use nine65::arithmetic::rns::U512;
use nine65::entropy::{FheRng, ShadowHarvester};
use nine65::errors::Nine65Error;
use nine65::keys::bootstrap::BOOTSTRAP_PRIMES;
use nine65::keys::expanded_bootstrap::ExpandedBootstrapKey;
use nine65::ops::expanded_bootstrap::ExpandedPhaseEvaluator;
use nine65::ops::expanded_phase1::ExpandedPhase1Components;
use nine65::ops::expanded_phase1::ExpandedPhase1Plan;
use nine65::ops::rns_fhe::{DualRNSSecretKey, RNSCiphertext, RNSFHEContext};
use nine65::ops::ExactMulPlan;
use nine65::params::{FHEConfig, SecureConfig};

fn boot_config(work: &FHEConfig, exponent: u32, lanes: usize) -> FHEConfig {
    let mut config = work.clone();
    config.t = work.t.checked_pow(exponent).unwrap();
    config.primes = BOOTSTRAP_PRIMES[..lanes].to_vec();
    config.q = config.primes[0];
    config.name = "expanded_bfv_inner_product";
    config
}

fn wide_bits(x: U512) -> u32 {
    for (offset, limb) in [(384, x.d3), (256, x.d2), (128, x.d1), (0, x.d0)] {
        if limb != 0 {
            return offset + 128 - limb.leading_zeros();
        }
    }
    0
}

#[test]
fn four_primes_admit_t_squared_and_five_admit_t_cubed() {
    let work = SecureConfig::secure_128().into_config();
    assert_eq!(work.primes, BOOTSTRAP_PRIMES[..4]);
    for (exponent, lanes, admitted) in [(2, 4, true), (3, 4, false), (3, 5, true)] {
        let config = boot_config(&work, exponent, lanes);
        let ctx = RNSFHEContext::try_new(&config).unwrap();
        let evaluator = ExpandedPhaseEvaluator::new(&ctx, work.t, exponent);
        match evaluator {
            Ok(evaluator) => {
                assert!(admitted);
                let certificate = evaluator.certificate();
                println!(
                    "P=t^{exponent}, {lanes} primes: error bound {} bits, half-Delta {} bits",
                    wide_bits(certificate.phase_error_bound),
                    wide_bits(certificate.half_delta)
                );
                assert!(certificate.security_screen.meets_claim_under_both);
                let mul = ExactMulPlan::new(&config.primes, config.n, config.t).unwrap();
                let capacity = mul.certificate();
                println!(
                    "P=t^{exponent}: exact multiply needs {} bits; {} transient lanes supply {} bits",
                    capacity.required_bits, capacity.aux_lanes, capacity.aux_bits
                );
                for level in 1..=work.primes.len() {
                    let plan = ExpandedPhase1Plan::new(&work, level, exponent).unwrap();
                    let result = plan.input_noise_budget();
                    if level == 1 {
                        assert!(matches!(
                            result,
                            Err(nine65::ops::expanded_phase1::ExpandedPhase1Error::NoDigitRemovalMargin)
                        ));
                        continue;
                    }
                    let budget = result.unwrap();
                    let q = work.primes[..level]
                        .iter()
                        .map(|&prime| prime as u128)
                        .product::<u128>();
                    // Independently evaluate the rational inequality using
                    // this work chain's exact u128 metadata.
                    let p = config.t as u128;
                    let t = work.t as u128;
                    // Divide out P before forming P*Q (which exceeds u128
                    // at t^3). For integral 2*t*E, the strict inequality
                    // is 2*t*E < Q-r*(t-1)-floor(t*Q*(N+1)/P).
                    let component_factor = t * (work.n as u128 + 1);
                    let component_cost =
                        (q / p) * component_factor + (q % p) * component_factor / p;
                    let rhs = q - (q % t) * (t - 1) - component_cost;
                    let maximum = (rhs - 1) / (2 * t);
                    assert_eq!(budget.max_centered_error.d0, maximum);
                    assert_eq!(
                        (
                            budget.max_centered_error.d1,
                            budget.max_centered_error.d2,
                            budget.max_centered_error.d3
                        ),
                        (0, 0, 0)
                    );
                    assert!(2 * t * maximum < rhs);
                    assert!(2 * t * (maximum + 1) >= rhs);
                }
            }
            Err(error) => {
                assert!(!admitted, "unexpected refusal: {error}");
                assert!(matches!(error, Nine65Error::BootstrapFailed { .. }));
            }
        }
    }
}

fn decode_all(ctx: &RNSFHEContext, ct: &RNSCiphertext, secret: &DualRNSSecretKey) -> Vec<u64> {
    let scale = CanonicalScaleRound::new(&ctx.config.primes, ctx.t).unwrap();
    let inner: Vec<Vec<u64>> = ctx
        .config
        .primes
        .iter()
        .enumerate()
        .map(|(lane, &prime)| {
            let mont = &ctx.rns.mont_contexts[lane];
            let c1: Vec<u64> = ct.c1.limbs[lane]
                .iter()
                .map(|&v| mont.from_montgomery(v))
                .collect();
            let product = ctx.ntt_engines[lane].multiply(&c1, &secret.s.main[lane]);
            ct.c0.limbs[lane]
                .iter()
                .zip(product)
                .map(|(&v, product)| {
                    ((mont.from_montgomery(v) as u128 + product as u128) % prime as u128) as u64
                })
                .collect()
        })
        .collect();
    (0..ctx.n)
        .map(|coefficient| {
            let residues: Vec<u64> = inner.iter().map(|lane| lane[coefficient]).collect();
            scale.scale_round(&residues).unwrap()
        })
        .collect()
}

fn pow_mod(mut base: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut value = 1u64;
    while exponent != 0 {
        if exponent & 1 != 0 {
            value = ((value as u128 * base as u128) % modulus as u128) as u64;
        }
        base = ((base as u128 * base as u128) % modulus as u128) as u64;
        exponent >>= 1;
    }
    value
}

// Independent test-only sequential CRT: a0+a1*s has fewer than 63 bits at
// P=t^3,N=8192, so three work primes give an unambiguous signed integer.
fn oracle_phases(
    ctx: &RNSFHEContext,
    c0: &[u64],
    c1: &[u64],
    secret: &DualRNSSecretKey,
    expanded: u64,
) -> Vec<i128> {
    let primes = &ctx.config.primes[..3];
    let q = primes.iter().map(|&p| p as u128).product::<u128>();
    let residues: Vec<Vec<u64>> = primes
        .iter()
        .enumerate()
        .map(|(lane, &prime)| {
            let centered = |value: u64| {
                if value <= expanded / 2 {
                    value % prime
                } else {
                    let negative = (expanded - value) % prime;
                    if negative == 0 {
                        0
                    } else {
                        prime - negative
                    }
                }
            };
            let a1: Vec<u64> = c1.iter().map(|&v| centered(v)).collect();
            let product = ctx.ntt_engines[lane].multiply(&a1, &secret.s.main[lane]);
            c0.iter()
                .zip(product)
                .map(|(&v, product)| {
                    ((centered(v) as u128 + product as u128) % prime as u128) as u64
                })
                .collect()
        })
        .collect();
    let inverses: Vec<u64> = primes
        .iter()
        .enumerate()
        .map(|(lane, &prime)| {
            let prefix = primes[..lane].iter().map(|&p| p as u128).product::<u128>();
            pow_mod((prefix % prime as u128) as u64, prime - 2, prime)
        })
        .collect();
    (0..ctx.n)
        .map(|coefficient| {
            let (mut x, mut product) = (0u128, 1u128);
            for (lane, &prime) in primes.iter().enumerate() {
                let difference = (residues[lane][coefficient] as u128 + prime as u128
                    - x % prime as u128)
                    % prime as u128;
                x += product * (difference * inverses[lane] as u128 % prime as u128);
                product *= prime as u128;
            }
            if x > q / 2 {
                x as i128 - q as i128
            } else {
                x as i128
            }
        })
        .collect()
}

#[test]
fn encrypted_inner_product_matches_all_coefficients_at_both_precisions() {
    let work = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&work).unwrap();
    let mut rng = ShadowHarvester::with_seed(0x4558_505f_4253_4b);
    let keys = ctx.generate_keys_dual_full(&mut rng);
    let mut cases = Vec::new();
    for message in [0, 1, 7, work.t - 1] {
        let ct = ctx.encrypt_dual(message, &keys.public_key, &mut rng);
        cases.push((format!("fresh {message}"), ct.clone(), message));
        for level in 2..ct.level {
            cases.push((
                format!("level {level} {message}"),
                ctx.mod_switch_ct_to_level(&ct, level).unwrap(),
                message,
            ));
        }
    }
    let one = ctx.encrypt_dual(1, &keys.public_key, &mut rng);
    let seven = ctx.encrypt_dual(7, &keys.public_key, &mut rng);
    cases.push(("added".into(), ctx.add_dual(&one, &seven), 8));
    cases.push((
        "multiplied and relinearized".into(),
        ctx.mul_dual_public(&one, &seven, &keys.eval_key).unwrap(),
        7,
    ));
    for (exponent, lanes) in [(2, 4), (3, 5)] {
        let config = boot_config(&work, exponent, lanes);
        let boot = RNSFHEContext::try_new(&config).unwrap();
        let evaluator = ExpandedPhaseEvaluator::new(&boot, work.t, exponent).unwrap();
        let bootstrap =
            ExpandedBootstrapKey::generate_with_rng(&work, &keys.secret_key, &evaluator, &mut rng)
                .unwrap();
        let decoded_secret = decode_all(
            &boot,
            bootstrap.bootstrap_key.encrypted_secret(),
            &bootstrap.boot_keys.secret_key,
        );
        for (coefficient, &value) in decoded_secret.iter().enumerate() {
            let expected = match keys.secret_key.s.main[0][coefficient] {
                0 => 0,
                1 => 1,
                _ => config.t - 1,
            };
            assert_eq!(
                value, expected,
                "centered encrypted secret, coefficient={coefficient}"
            );
        }
        for (label, ct, message) in &cases {
            assert_eq!(
                ctx.decrypt_dual(ct, &keys.secret_key),
                *message,
                "input {label}"
            );
            let plan = ExpandedPhase1Plan::new(&work, ct.level, exponent).unwrap();
            let prepared = plan.prepare(ct).unwrap();
            let result = evaluator
                .inner_product(&prepared, &bootstrap.bootstrap_key)
                .unwrap();
            result.validate(work.n, lanes).unwrap();
            let decoded = decode_all(&boot, &result, &bootstrap.boot_keys.secret_key);
            let integer_phases =
                oracle_phases(&ctx, &prepared.c0, &prepared.c1, &keys.secret_key, config.t);
            for (coefficient, (&actual, &phase)) in decoded.iter().zip(&integer_phases).enumerate()
            {
                assert_eq!(
                    actual,
                    phase.rem_euclid(config.t as i128) as u64,
                    "{label}, e={exponent}, coefficient={coefficient}"
                );
            }
            let divisor = prepared.digit_divisor;
            let extracted =
                ((decoded[0] as u128 + divisor as u128 / 2) / divisor as u128) % work.t as u128;
            assert_eq!(
                extracted as u64, *message,
                "clear digit oracle for {label}, e={exponent}"
            );
            // Safe-Basis capacity and composite repacking check for the
            // expanded phase's bounded winding. This is a test oracle, not
            // an evaluator-side derivation of encrypted K.
            let phase = integer_phases[0];
            let centered =
                (phase + config.t as i128 / 2).rem_euclid(config.t as i128) - config.t as i128 / 2;
            let winding = (phase - centered) / config.t as i128;
            let bound = work.n as i128 + 1;
            assert!(winding.abs() <= bound);
            let shifted = winding + bound;
            let s6 = exact_transcendentals::transduction::S6_BASIS;
            let s8 = exact_transcendentals::transduction::S8_BASIS;
            assert!(2 * bound + 1 < s6.iter().product::<i128>());
            for basis in [&s6[..], &[6i128, 35, 143][..]] {
                let tray: Vec<i128> = basis.iter().map(|&m| shifted % m).collect();
                let map = exact_transcendentals::transduction::TransductionMap::try_new(basis, &s8)
                    .unwrap();
                assert_eq!(
                    map.apply(&tray),
                    s8.iter().map(|&m| shifted % m).collect::<Vec<_>>()
                );
            }
        }
    }
}

#[test]
fn malformed_work_key_is_refused_before_rng_consumption() {
    let work = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&work).unwrap();
    let boot = RNSFHEContext::try_new(&boot_config(&work, 2, 4)).unwrap();
    let evaluator = ExpandedPhaseEvaluator::new(&boot, work.t, 2).unwrap();
    let mut key_rng = ShadowHarvester::with_seed(0x4558_505f_5641_4c);
    let keys = ctx.generate_keys_dual(&mut key_rng);
    for defect in 0..3 {
        let mut bad = keys.secret_key.clone();
        match defect {
            0 => bad.s.main[0][0] = 2,
            1 => bad.s.main[1][0] = 2,
            _ => {
                bad.s.main[1].pop();
            }
        }
        let mut probe = ShadowHarvester::with_seed(12345);
        let mut untouched = ShadowHarvester::with_seed(12345);
        assert!(matches!(
            ExpandedBootstrapKey::generate_with_rng(&work, &bad, &evaluator, &mut probe),
            Err(Nine65Error::KeyGenFailed { .. })
        ));
        assert_eq!(
            FheRng::next_u64(&mut probe),
            FheRng::next_u64(&mut untouched)
        );
    }
}

#[test]
fn malformed_public_components_and_parameter_regimes_are_refused() {
    let work = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&work).unwrap();
    let config = boot_config(&work, 2, 4);
    let boot = RNSFHEContext::try_new(&config).unwrap();
    let evaluator = ExpandedPhaseEvaluator::new(&boot, work.t, 2).unwrap();
    let mut rng = ShadowHarvester::with_seed(0x4558_505f_5348_4150);
    let keys = ctx.generate_keys_dual(&mut rng);
    let bootstrap =
        ExpandedBootstrapKey::generate_with_rng(&work, &keys.secret_key, &evaluator, &mut rng)
            .unwrap();
    let components = ExpandedPhase1Components {
        c0: vec![0; work.n],
        c1: vec![0; work.n],
        plaintext_modulus: config.t,
        digit_divisor: work.t,
        source_level: work.primes.len(),
    };
    for defect in 0..7 {
        let mut bad = components.clone();
        match defect {
            0 => {
                bad.c0.pop();
            }
            1 => {
                bad.c1.pop();
            }
            2 => bad.c0[0] = config.t,
            3 => bad.c1[0] = config.t,
            4 => bad.source_level = 0,
            5 => bad.source_level = work.primes.len() + 1,
            _ => bad.digit_divisor += 1,
        }
        let result = evaluator.inner_product(&bad, &bootstrap.bootstrap_key);
        assert!(match defect {
            0 | 1 => matches!(result, Err(Nine65Error::InvalidPolynomialDegree { .. })),
            2 | 3 => matches!(result, Err(Nine65Error::InvalidParameter { .. })),
            _ => matches!(result, Err(Nine65Error::BootstrapConfigMismatch { .. })),
        });
    }
    let wrong = RNSFHEContext::try_new(&boot_config(&work, 3, 5)).unwrap();
    let wrong_evaluator = ExpandedPhaseEvaluator::new(&wrong, work.t, 3).unwrap();
    assert!(matches!(
        wrong_evaluator.inner_product(&components, &bootstrap.bootstrap_key),
        Err(Nine65Error::BootstrapConfigMismatch { .. })
    ));
    assert!(matches!(
        ExpandedPhaseEvaluator::new(&boot, work.t, 3),
        Err(Nine65Error::BootstrapConfigMismatch { .. })
    ));
}

#[test]
fn safe_basis_repacking_preserves_the_entire_signed_carry_window() {
    let n = SecureConfig::secure_128().into_config().n as i128;
    let bound = n + 1;
    let s6 = exact_transcendentals::transduction::S6_BASIS;
    let s8 = exact_transcendentals::transduction::S8_BASIS;
    let product = s6.iter().product::<i128>();
    assert_eq!(product, 30030);
    assert_eq!(2 * bound + 1, 16387);
    assert!(2 * bound + 1 <= product);
    for basis in [&s6[..], &[6i128, 35, 143][..]] {
        let map =
            exact_transcendentals::transduction::TransductionMap::try_new(basis, &s8).unwrap();
        for carry in -bound..=bound {
            let shifted = carry + bound;
            let tray: Vec<i128> = basis.iter().map(|&m| shifted % m).collect();
            assert_eq!(
                map.apply(&tray),
                s8.iter().map(|&m| shifted % m).collect::<Vec<_>>()
            );
        }
    }
}
