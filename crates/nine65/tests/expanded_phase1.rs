//! Differential checks for public expanded-plaintext preprocessing.
//! Canonical integers and secret-dependent digit removal appear only in these
//! test oracles. The production plan returns public component polynomials.

use nine65::arithmetic::canonical_scale_round::{CanonicalScaleRound, CanonicalScaleRoundError};
use nine65::arithmetic::main_only_base_ext::MainOnlyBaseExtError;
use nine65::arithmetic::rns::{U256, U512};
use nine65::entropy::ShadowHarvester;
use nine65::keys::bootstrap::BOOTSTRAP_PRIMES;
use nine65::ops::expanded_phase1::{ExpandedPhase1Error, ExpandedPhase1Plan};
use nine65::ops::rns_fhe::{DualRNSCiphertext, DualRNSPoly, RNSFHEContext};
use nine65::params::{FHEConfig, SecureConfig};

fn words(x: U512) -> (u128, u128, u128, u128) {
    (x.d3, x.d2, x.d1, x.d0)
}

// Independent integer quotient oracle: binary-search Q*y against P*x+Q/2.
// U512 keeps the numerator exact even when Q fits U256 but P*Q does not.
fn reference_scale(x: U512, q: U512, target: u64) -> u64 {
    let numerator = x.mul_u128(target as u128).add(q.div_u64(2));
    let (mut low, mut high) = (0u64, target);
    while low < high {
        let mid = low + (high - low).div_ceil(2);
        if words(q.mul_u128(mid as u128)) <= words(numerator) {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    low % target
}

fn pow_mod(mut base: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = ((result as u128 * base as u128) % modulus as u128) as u64;
        }
        base = ((base as u128 * base as u128) % modulus as u128) as u64;
        exponent >>= 1;
    }
    result
}

// Independent sequential CRT reference for the 90-bit secure_128 work chain.
// This reconstruction is deliberately confined to the integration test.
fn reference_reconstruct_u128(residues: &[u64], primes: &[u64]) -> u128 {
    let (mut x, mut product) = (0u128, 1u128);
    for (&residue, &prime) in residues.iter().zip(primes) {
        let difference = (residue as u128 + prime as u128 - x % prime as u128) % prime as u128;
        let inverse = pow_mod((product % prime as u128) as u64, prime - 2, prime);
        let step = difference * inverse as u128 % prime as u128;
        x += product * step;
        product = product
            .checked_mul(prime as u128)
            .expect("reference Q fits u128");
    }
    x
}

#[test]
fn exhaustive_small_basis_matches_integer_rounding() {
    let main = [17u64, 13];
    let q = 17 * 13u64;
    for target in [3, 5, 125, 625, i64::MAX as u64] {
        let scale = CanonicalScaleRound::new(&main, target).unwrap();
        for x in 0..q {
            let residues = main.map(|prime| x % prime);
            let expected =
                ((x as u128 * target as u128 + q as u128 / 2) / q as u128) % target as u128;
            assert_eq!(
                scale.scale_round(&residues).unwrap(),
                expected as u64,
                "x={x}, target={target}"
            );
        }
    }
}

#[test]
fn every_chain_prefix_matches_wide_reference_at_rounding_boundaries() {
    for level in 1..=BOOTSTRAP_PRIMES.len() {
        let main = &BOOTSTRAP_PRIMES[..level];
        let q = U512::product_u64s(main);
        let q256 = q.to_u256_truncated();
        for target in [125, 65537u64.pow(3)] {
            let scale = CanonicalScaleRound::new(main, target).unwrap();
            let mut values = vec![
                U256::zero(),
                U256::from_u64(1),
                q.div_u64(2).to_u256_truncated(),
                q256.sub(U256::from_u64(1)),
            ];
            // These are the first integers at/above several half-step rounding
            // boundaries. Q is odd, so no boundary is an integer.
            for digit in [0, 1, target / 2, target - 1] {
                let edge = q
                    .mul_u128(2 * digit as u128 + 1)
                    .div_u64(2 * target)
                    .to_u256_truncated()
                    .add(U256::from_u64(1));
                if (edge.hi, edge.lo) < (q256.hi, q256.lo) {
                    values.extend([
                        edge.sub(U256::from_u64(1)),
                        edge,
                        edge.add(U256::from_u64(1)),
                    ]);
                }
            }
            let mut state = 0x4558_5041_4e44u64;
            for _ in 0..128 {
                let mut next = || {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state
                };
                let random = U256 {
                    lo: next() as u128 | ((next() as u128) << 64),
                    hi: next() as u128 | ((next() as u128) << 64),
                };
                values.push(U512::from_u256(random).mod_u256(q256));
            }
            for x in values {
                let residues: Vec<u64> = main.iter().map(|&prime| x.mod_u64(prime)).collect();
                assert_eq!(
                    scale.scale_round(&residues).unwrap(),
                    reference_scale(U512::from_u256(x), q, target),
                    "level={level}, target={target}, x={x:?}"
                );
            }
        }
    }
}

#[test]
fn arithmetic_refuses_invalid_shapes_moduli_and_capacity() {
    assert!(matches!(
        CanonicalScaleRound::new(&[], 125),
        Err(CanonicalScaleRoundError::EmptyMainBasis)
    ));
    for target in [0, 1, 2, 4, u64::MAX] {
        assert!(matches!(
            CanonicalScaleRound::new(&[17, 13], target),
            Err(CanonicalScaleRoundError::InvalidTarget { .. })
        ));
    }
    assert!(matches!(
        CanonicalScaleRound::new(&[16, 13], 125),
        Err(CanonicalScaleRoundError::EvenMainModulus { .. })
    ));
    assert!(matches!(
        CanonicalScaleRound::new(&[17, 13], 17),
        Err(CanonicalScaleRoundError::NonCoprimeTarget { .. })
    ));
    assert!(matches!(
        CanonicalScaleRound::new(&[17, 17], 125),
        Err(CanonicalScaleRoundError::Projection(
            MainOnlyBaseExtError::NonCoprimeMain { .. }
        ))
    ));
    // Pairwise-coprime lanes known to fit at eight lanes and exceed capacity
    // at nine: the refusal cannot be caused by an earlier modulus check.
    let wide = [
        2013265921, 2281701377, 2483027969, 2885681153, 3221225473, 3221422081, 3222306817,
        3222372353, 3222568961,
    ];
    CanonicalScaleRound::new(&wide[..8], 125).expect("eight lanes fit");
    assert!(matches!(
        CanonicalScaleRound::new(&wide, 125),
        Err(CanonicalScaleRoundError::Projection(
            MainOnlyBaseExtError::FallbackAccumulatorOverCapacity { .. }
        ))
    ));
    let scale = CanonicalScaleRound::new(&[17, 13], 125).unwrap();
    for residues in [vec![], vec![0], vec![0, 0, 0]] {
        assert!(matches!(
            scale.scale_round(&residues),
            Err(CanonicalScaleRoundError::InputShapeMismatch { .. })
        ));
    }
    assert!(matches!(
        scale.scale_round(&[17, 0]),
        Err(CanonicalScaleRoundError::NonCanonicalInput { lane: 0, .. })
    ));
}

fn small_config() -> FHEConfig {
    let mut config = SecureConfig::secure_128().into_config();
    config.n = 2;
    config.t = 5;
    config.primes = vec![17, 13];
    config
}

fn small_ciphertext() -> DualRNSCiphertext {
    let poly = DualRNSPoly {
        main: vec![vec![0, 1], vec![0, 1]],
        anchor: vec![],
        n: 2,
    };
    DualRNSCiphertext {
        c0: poly.clone(),
        c1: poly,
        level: 2,
    }
}

#[test]
fn input_margin_recovers_messages_at_both_error_extremes() {
    let config = small_config();
    let plan = ExpandedPhase1Plan::new(&config, 2, 2).unwrap();
    let budget = plan.input_noise_budget().unwrap();
    assert_eq!(words(budget.max_centered_error), (0, 0, 0, 8));
    let q = config.primes.iter().product::<u64>() as i128;
    let t = config.t as i128;
    let delta = q / t;
    let candidates = [0, 1, q / 2, q / 2 + 1, q - 1];
    let errors = [[0, 0], [-8, -8], [-8, 8], [8, -8], [8, 8]];
    let product =
        |a: [i128; 2], b: [i128; 2]| [a[0] * b[0] - a[1] * b[1], a[0] * b[1] + a[1] * b[0]];
    for s0 in -1..=1 {
        for s1 in -1..=1 {
            for m0 in -2..=2 {
                for m1 in -2..=2 {
                    for &x0 in &candidates {
                        for &x1 in &candidates {
                            let c1 = [x0, x1];
                            let inner = product(c1, [s0, s1]);
                            for error in errors {
                                let c0 = [
                                    (delta * m0 + error[0] - inner[0]).rem_euclid(q),
                                    (delta * m1 + error[1] - inner[1]).rem_euclid(q),
                                ];
                                let poly = |values: [i128; 2]| DualRNSPoly {
                                    main: config
                                        .primes
                                        .iter()
                                        .map(|&prime| {
                                            values
                                                .iter()
                                                .map(|&v| v.rem_euclid(prime as i128) as u64)
                                                .collect()
                                        })
                                        .collect(),
                                    anchor: vec![],
                                    n: 2,
                                };
                                let ct = DualRNSCiphertext {
                                    c0: poly(c0),
                                    c1: poly(c1),
                                    level: 2,
                                };
                                let prepared = plan.prepare(&ct).unwrap();
                                let p = prepared.plaintext_modulus as i128;
                                let centered = |v: u64| {
                                    if v <= p as u64 / 2 {
                                        v as i128
                                    } else {
                                        v as i128 - p
                                    }
                                };
                                let a1 = [centered(prepared.c1[0]), centered(prepared.c1[1])];
                                let phase_product = product(a1, [s0, s1]);
                                for (coefficient, message) in [m0, m1].into_iter().enumerate() {
                                    let phase = (centered(prepared.c0[coefficient])
                                        + phase_product[coefficient])
                                        .rem_euclid(p);
                                    let divisor = prepared.digit_divisor as i128;
                                    assert_eq!(
                                        ((phase + divisor / 2) / divisor).rem_euclid(t),
                                        message.rem_euclid(t),
                                        "s=[{s0},{s1}], m=[{m0},{m1}], c1={c1:?}, error={error:?}"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    let mut no_margin = config.clone();
    no_margin.n = config.t as usize;
    assert!(matches!(
        ExpandedPhase1Plan::new(&no_margin, 2, 2)
            .unwrap()
            .input_noise_budget(),
        Err(ExpandedPhase1Error::NoDigitRemovalMargin)
    ));
}

#[test]
fn plan_uses_actual_level_and_ignores_untrusted_anchors() {
    let config = small_config();
    let mut ct = small_ciphertext();
    for level in [1, 2] {
        ct.level = level;
        ct.c0.main.truncate(level);
        ct.c1.main.truncate(level);
        // Restore the second lane for the second iteration.
        if level == 2 {
            ct.c0.main.push(vec![0, 1]);
            ct.c1.main.push(vec![0, 1]);
        }
        let plan = ExpandedPhase1Plan::new(&config, level, 3).unwrap();
        let prepared = plan.prepare(&ct).unwrap();
        let q = config.primes[..level].iter().product::<u64>();
        assert_eq!(prepared.c0, vec![0, ((125 + q / 2) / q) % 125]);
        assert_eq!(prepared.c1, prepared.c0);
        assert_eq!(prepared.plaintext_modulus, 125);
        assert_eq!(prepared.digit_divisor, 25);
        assert_eq!(prepared.source_level, level);
        ct.c0.anchor = vec![vec![u64::MAX]];
        ct.c1.anchor = vec![vec![]];
        assert_eq!(plan.prepare(&ct).unwrap(), prepared);
    }
}

#[test]
fn plan_refuses_malformed_ciphertext_and_parameters() {
    let config = small_config();
    for level in [0, 3] {
        assert!(matches!(
            ExpandedPhase1Plan::new(&config, level, 3),
            Err(ExpandedPhase1Error::InvalidLevel { .. })
        ));
    }
    assert!(matches!(
        ExpandedPhase1Plan::new(&config, 2, 1),
        Err(ExpandedPhase1Error::InvalidExponent { .. })
    ));
    assert!(matches!(
        ExpandedPhase1Plan::new(&config, 2, 100),
        Err(ExpandedPhase1Error::PlaintextPowerOverflow { .. })
    ));
    let plan = ExpandedPhase1Plan::new(&config, 2, 3).unwrap();
    let mut ct = small_ciphertext();
    ct.level = 1;
    assert!(matches!(
        plan.prepare(&ct),
        Err(ExpandedPhase1Error::CiphertextLevelMismatch { .. })
    ));
    ct = small_ciphertext();
    ct.c1.n = 1;
    assert!(matches!(
        plan.prepare(&ct),
        Err(ExpandedPhase1Error::PolynomialDegreeMismatch {
            component: "c1",
            ..
        })
    ));
    ct = small_ciphertext();
    ct.c1.main.pop();
    assert!(matches!(
        plan.prepare(&ct),
        Err(ExpandedPhase1Error::LaneCountMismatch {
            component: "c1",
            ..
        })
    ));
    ct = small_ciphertext();
    ct.c1.main[1].pop();
    assert!(matches!(
        plan.prepare(&ct),
        Err(ExpandedPhase1Error::CoefficientCountMismatch {
            component: "c1",
            lane: 1,
            ..
        })
    ));
    ct = small_ciphertext();
    ct.c0.main[1][0] = 13;
    assert!(matches!(
        plan.prepare(&ct),
        Err(ExpandedPhase1Error::Arithmetic(
            CanonicalScaleRoundError::NonCanonicalInput { lane: 1, .. }
        ))
    ));
}

/// Full-size reference: check every component coefficient against an independent
/// integer oracle, then check the secret-dependent constant phase in the clear.
/// This proves the public preprocessing, not encrypted digit removal or refresh.
#[test]
fn expanded_plaintext_phase_recovers_real_ciphertext() {
    let config = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&config).expect("work context");
    let mut rng = ShadowHarvester::with_seed(0x4558_5041_4e44);
    let keys = ctx.generate_keys_dual_full(&mut rng);
    let level = config.primes.len();
    let q = U512::product_u64s(&config.primes);
    let plan = ExpandedPhase1Plan::new(&config, level, 3).unwrap();
    let first_prime = config.primes[0];
    let signed_secret: Vec<i128> = keys.secret_key.s.main[0]
        .iter()
        .map(|&x| match x {
            0 => 0,
            1 => 1,
            x if x == first_prime - 1 => -1,
            _ => panic!("secret is not ternary"),
        })
        .collect();
    for message in [0, 1, 7, config.t - 1] {
        let ct = ctx.encrypt_dual(message, &keys.public_key, &mut rng);
        assert_eq!(ctx.decrypt_dual(&ct, &keys.secret_key), message);
        let prepared = plan.prepare(&ct).unwrap();
        let expanded = prepared.plaintext_modulus;
        for (main, scaled) in [(&ct.c0.main, &prepared.c0), (&ct.c1.main, &prepared.c1)] {
            for (coefficient, &actual) in scaled.iter().enumerate() {
                let residues: Vec<u64> = main.iter().map(|lane| lane[coefficient]).collect();
                let canonical = reference_reconstruct_u128(&residues, &config.primes);
                assert_eq!(
                    actual,
                    reference_scale(U512::from_u128(canonical), q, expanded),
                    "message={message}, coefficient={coefficient}"
                );
            }
        }
        let mut phase = prepared.c0[0] as i128 + prepared.c1[0] as i128 * signed_secret[0];
        for j in 1..config.n {
            phase -= prepared.c1[j] as i128 * signed_secret[config.n - j];
        }
        let divisor = prepared.digit_divisor as i128;
        let extracted = ((phase.rem_euclid(expanded as i128) + divisor / 2) / divisor)
            .rem_euclid(config.t as i128) as u64;
        assert_eq!(extracted, message);
    }
}
