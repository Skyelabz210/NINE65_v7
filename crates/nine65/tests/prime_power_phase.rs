//! Independent checks of the authentic t/t^2 views. All secret-key phase
//! evaluation and integer reconstruction in this file are test oracles.

use nine65::arithmetic::canonical_scale_round::CanonicalScaleRound;
use nine65::arithmetic::rns::U512;
use nine65::entropy::ShadowHarvester;
use nine65::ops::expanded_bootstrap::ExpandedPhaseEvaluator;
use nine65::ops::expanded_phase1::ExpandedPhase1Plan;
use nine65::ops::prime_power_phase::PrimePowerPhaseEvaluator;
use nine65::ops::rns_fhe::{
    DualRNSCiphertext, DualRNSPoly, DualRNSSecretKey, RNSCiphertext, RNSFHEContext,
};
use nine65::params::{FHEConfig, SecureConfig};

fn boot_config(work: &FHEConfig) -> FHEConfig {
    let mut config = work.clone();
    config.t = work.t * work.t;
    config.name = "same_prime_phase_test";
    config
}

fn decode_all(ctx: &RNSFHEContext, ct: &RNSCiphertext, sk: &DualRNSSecretKey) -> Vec<u64> {
    let decoder = CanonicalScaleRound::new(&ctx.config.primes, ctx.t).unwrap();
    let phases: Vec<Vec<u64>> = ctx
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
            let product = ctx.ntt_engines[lane].multiply(&c1, &sk.s.main[lane]);
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
        .map(|j| {
            decoder
                .scale_round(&phases.iter().map(|lane| lane[j]).collect::<Vec<_>>())
                .unwrap()
        })
        .collect()
}

fn pow_mod(mut a: u64, mut e: u64, p: u64) -> u64 {
    let mut out = 1;
    while e != 0 {
        if e & 1 != 0 {
            out = (out as u128 * a as u128 % p as u128) as u64;
        }
        a = (a as u128 * a as u128 % p as u128) as u64;
        e >>= 1;
    }
    out
}

// Three work primes uniquely determine this small, unwrapped public-component
// convolution. This sequential CRT is confined to the independent test oracle.
fn phase_oracle(
    ctx: &RNSFHEContext,
    c0: &[u64],
    c1: &[u64],
    sk: &DualRNSSecretKey,
    p: u64,
) -> Vec<u64> {
    let primes = &ctx.config.primes[..3];
    let residues: Vec<Vec<u64>> = primes
        .iter()
        .enumerate()
        .map(|(lane, &prime)| {
            let center = |v: u64| {
                if v <= p / 2 {
                    v % prime
                } else {
                    (prime - (p - v) % prime) % prime
                }
            };
            let a1: Vec<u64> = c1.iter().map(|&v| center(v)).collect();
            let product = ctx.ntt_engines[lane].multiply(&a1, &sk.s.main[lane]);
            c0.iter()
                .zip(product)
                .map(|(&v, product)| ((center(v) as u128 + product as u128) % prime as u128) as u64)
                .collect()
        })
        .collect();
    let q = primes.iter().map(|&v| v as u128).product::<u128>();
    let inverse: Vec<u64> = primes
        .iter()
        .enumerate()
        .map(|(lane, &prime)| {
            let prefix = primes[..lane].iter().map(|&v| v as u128).product::<u128>();
            pow_mod((prefix % prime as u128) as u64, prime - 2, prime)
        })
        .collect();
    (0..ctx.n)
        .map(|j| {
            let (mut x, mut prefix) = (0u128, 1u128);
            for (lane, &prime) in primes.iter().enumerate() {
                let difference =
                    (residues[lane][j] as u128 + prime as u128 - x % prime as u128) % prime as u128;
                x += prefix * (difference * inverse[lane] as u128 % prime as u128);
                prefix *= prime as u128;
            }
            let signed = if x > q / 2 {
                x as i128 - q as i128
            } else {
                x as i128
            };
            signed.rem_euclid(p as i128) as u64
        })
        .collect()
}

fn boundary_input(work: &FHEConfig, level: usize, error: i128, message: u64) -> DualRNSCiphertext {
    let q = work.primes[..level]
        .iter()
        .map(|&v| v as u128)
        .product::<u128>();
    let m = if message <= work.t / 2 {
        message as i128
    } else {
        message as i128 - work.t as i128
    };
    let phase = (q as i128 / work.t as i128 * m + error).rem_euclid(q as i128) as u128;
    let mut c0 = vec![vec![0; work.n]; level];
    for (lane, &prime) in work.primes[..level].iter().enumerate() {
        c0[lane][0] = (phase % prime as u128) as u64;
    }
    DualRNSCiphertext {
        c0: DualRNSPoly {
            main: c0,
            anchor: vec![],
            n: work.n,
        },
        c1: DualRNSPoly {
            main: vec![vec![0; work.n]; level],
            anchor: vec![],
            n: work.n,
        },
        level,
    }
}

#[test]
fn paired_views_are_authentic_at_every_admitted_level_and_noise_boundary() {
    let work = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&work).unwrap();
    let boot = RNSFHEContext::try_new(&boot_config(&work)).unwrap();
    let high = ExpandedPhaseEvaluator::new(&boot, work.t, 2).unwrap();
    let evaluator = PrimePowerPhaseEvaluator::new(&high, &work).unwrap();
    let mut rng = ShadowHarvester::with_seed(0x5050_5f50_4149_5253);
    let keys = ctx.generate_keys_dual_full(&mut rng);
    let bootstrap = evaluator
        .generate_keys_with_rng(&keys.secret_key, &mut rng)
        .unwrap();
    let mut cases = Vec::new();
    for message in [0, 1, 7, work.t - 1] {
        let ct = ctx.encrypt_dual(message, &keys.public_key, &mut rng);
        for level in 2..=work.primes.len() {
            let leveled = ctx.mod_switch_ct_to_level(&ct, level).unwrap();
            cases.push((format!("fresh {message}, level {level}"), leveled, message));
        }
    }
    let one = ctx.encrypt_dual(1, &keys.public_key, &mut rng);
    let seven = ctx.encrypt_dual(7, &keys.public_key, &mut rng);
    cases.push(("added".into(), ctx.add_dual(&one, &seven), 8));
    cases.push((
        "multiplied/relinearized".into(),
        ctx.mul_dual_public(&one, &seven, &keys.eval_key).unwrap(),
        7,
    ));
    for level in 2..=work.primes.len() {
        let budget = ExpandedPhase1Plan::new(&work, level, 2)
            .unwrap()
            .input_noise_budget()
            .unwrap();
        assert_eq!(
            (
                budget.max_centered_error.d1,
                budget.max_centered_error.d2,
                budget.max_centered_error.d3
            ),
            (0, 0, 0)
        );
        let error = budget.max_centered_error.d0 as i128;
        for message in [0, 1, 7, work.t - 1] {
            for signed in [-error, error] {
                cases.push((
                    format!("maximum error {signed}, level {level}, message {message}"),
                    boundary_input(&work, level, signed, message),
                    message,
                ));
            }
        }
    }
    let p = work.t * work.t;
    let h = (work.t - 1) / 2;
    for (label, ct, message) in &cases {
        let prepared = ExpandedPhase1Plan::new(&work, ct.level, 2)
            .unwrap()
            .prepare(ct)
            .unwrap();
        let shifted: Vec<u64> = prepared.c0.iter().map(|&v| (v + h) % p).collect();
        let expected = phase_oracle(&ctx, &shifted, &prepared.c1, &keys.secret_key, p);
        let pair = evaluator.evaluate(ct, &bootstrap.bootstrap_key).unwrap();
        let high = decode_all(&boot, pair.high_lift(), &bootstrap.boot_keys.secret_key);
        let low = decode_all(
            evaluator.low_context(),
            pair.low_view(),
            &bootstrap.boot_keys.secret_key,
        );
        let trace_input = decode_all(
            &boot,
            pair.coefficient_projection_view(),
            &bootstrap.boot_keys.secret_key,
        );
        let inverse = pair.coefficient_projection_inverse();
        assert_eq!(inverse, -524304);
        let inverse_residue = (inverse as i128).rem_euclid(p as i128) as u128;
        assert_eq!(inverse_residue * work.n as u128 % p as u128, 1);
        assert_eq!(high, expected, "{label}: authentic high phase");
        for (j, (&x, &r)) in high.iter().zip(&low).enumerate() {
            assert_eq!(
                trace_input[j],
                (x as u128 * inverse_residue % p as u128) as u64,
                "{label}, coefficient {j}: directly preconditioned trace input"
            );
            assert_eq!(
                r,
                x % work.t,
                "{label}, coefficient {j}: authentic low view"
            );
            assert_eq!(
                x / work.t,
                if j == 0 { *message } else { 0 },
                "{label}, coefficient {j}: clear digit oracle"
            );
        }
        assert_eq!(pair.noise_certificate().source_level, ct.level);
        assert_eq!(pair.noise_certificate().rounding_shift, h);
        assert_eq!(pair.high_lift().num_primes, 4);
        assert_eq!(pair.low_view().num_primes, 4);
    }
    println!(
        "verified {} full-ring paired phases, including both allowed error extremes",
        cases.len()
    );

    let pair = evaluator
        .evaluate(&seven, &bootstrap.bootstrap_key)
        .unwrap();
    let mut poisoned = seven.clone();
    poisoned.c0.anchor = vec![vec![u64::MAX; 3]];
    poisoned.c1.anchor.clear();
    let same = evaluator
        .evaluate(&poisoned, &bootstrap.bootstrap_key)
        .unwrap();
    assert_eq!(pair.lineage(), same.lineage());
    assert_eq!(pair.high_lift().c0.limbs, same.high_lift().c0.limbs);
    assert_eq!(pair.low_view().c0.limbs, same.low_view().c0.limbs);
    assert_eq!(
        pair.coefficient_projection_view().c0.limbs,
        same.coefficient_projection_view().c0.limbs
    );
    assert_ne!(
        pair.lineage(),
        evaluator
            .evaluate(&one, &bootstrap.bootstrap_key)
            .unwrap()
            .lineage()
    );
    // Ordinary work modulus switching already refuses level one. Construct
    // a valid one-lane diagnostic input to test this evaluator's own gate.
    let level_one = boundary_input(&work, 1, 0, 7);
    assert!(evaluator
        .evaluate(&level_one, &bootstrap.bootstrap_key)
        .is_err());
    let mut malformed = seven.clone();
    malformed.c1.main[0].pop();
    assert!(evaluator
        .evaluate(&malformed, &bootstrap.bootstrap_key)
        .is_err());
}

#[test]
fn winding_cancels_and_same_prime_quotient_matches_rounding() {
    for t in [3i128, 5, 17] {
        let p = t * t;
        let h = (t - 1) / 2;
        for w in 0..p {
            let x = (w + h).rem_euclid(p);
            let r = x % t;
            let d = (x - r) / t;
            for k in -20..=20 {
                let rounded = (w + k * p + h).div_euclid(t).rem_euclid(t);
                assert_eq!(d, rounded, "t={t}, w={w}, K={k}");
            }
        }
    }
    let t = 65537i128;
    let h = (t - 1) / 2;
    for m in [0, 1, 7, t / 2, t - 1] {
        for offset in [-h - 1, -h, -1, 0, 1, h, h + 1] {
            let w = (m * t + offset).rem_euclid(t * t);
            let x = (w + h).rem_euclid(t * t);
            assert_eq!(x / t, (m + (offset + h).div_euclid(t)).rem_euclid(t));
        }
    }
}

fn mul_mod(mut a: u128, mut b: u128, q: u128) -> u128 {
    let mut out = 0;
    while b != 0 {
        if b & 1 != 0 {
            out = (out + a) % q;
        }
        a = (a + a) % q;
        b >>= 1;
    }
    out
}

fn inverse(a: u128, q: u128) -> u128 {
    let (mut r0, mut r1) = (q as i128, a as i128);
    let (mut s0, mut s1) = (0i128, 1i128);
    while r1 != 0 {
        let quotient = r0 / r1;
        (r0, r1) = (r1, r0 - quotient * r1);
        (s0, s1) = (s1, s0 - quotient * s1);
    }
    assert_eq!(r0, 1);
    s0.rem_euclid(q as i128) as u128
}

#[test]
fn modular_division_of_ordinary_low_encoding_amplifies_unit_noise() {
    let work = SecureConfig::secure_128().into_config();
    let q = work.primes.iter().map(|&p| p as u128).product::<u128>();
    let t = work.t as u128;
    let high_delta = q / (t * t);
    let low_delta = q / t;
    assert_eq!(low_delta - t * high_delta, 49185);
    let a = mul_mod(low_delta, inverse(t * high_delta, q), q);
    let b = q - inverse(t, q);
    // These are the unique affine scalars making noiseless floor encodings
    // agree for every x=t*d+r. They are not ordinary integer division by t.
    assert_eq!(mul_mod(a, t * high_delta, q), low_delta);
    assert_eq!(
        (mul_mod(a, high_delta, q) + mul_mod(b, low_delta, q)) % q,
        0
    );
    let decode = |value: u128| {
        CanonicalScaleRound::new(&work.primes, work.t)
            .unwrap()
            .scale_round(
                &work
                    .primes
                    .iter()
                    .map(|&p| (value % p as u128) as u64)
                    .collect::<Vec<_>>(),
            )
            .unwrap()
    };
    for d in [0, 1, 7, t - 1] {
        for r in [0, 1, t / 2, t - 1] {
            let x = t * d + r;
            let candidate = (mul_mod(a, high_delta * x, q) + mul_mod(b, low_delta * r, q)) % q;
            assert_eq!(decode(candidate), d as u64);
        }
    }
    assert_eq!(
        decode(1),
        0,
        "unit error is harmless in the authentic low encoding"
    );
    assert_eq!(
        decode(b),
        1111,
        "the same unit error breaks the affine quotient"
    );
    // The failure is also present at the rounding shift itself: w=0 gives
    // x=r=h, so it does not depend on a low digit near a rounding boundary.
    let h = (t - 1) / 2;
    let low_phase = low_delta * h + 1;
    assert_eq!(decode(low_phase), h as u64);
    let candidate = (mul_mod(a, high_delta * h, q) + mul_mod(b, low_phase, q)) % q;
    assert_eq!(decode(candidate), 1111, "w=0 should have quotient zero");
    assert!(U512::from_u64(1).d0 < low_delta / 2);
}
