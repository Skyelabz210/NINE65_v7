//! Encrypted toy proof of the coefficient/slot bridge needed by a
//! coefficientwise CRAM carry or digit gate. The linear transform is the
//! direct automorphism-diagonal decomposition (N terms), intentionally a
//! correctness prototype rather than a production-cost transform.

use nine65::arithmetic::canonical_scale_round::CanonicalScaleRound;
use nine65::arithmetic::RNSPolynomial;
use nine65::entropy::ShadowHarvester;
use nine65::ops::rns_fhe::exact_mul::{ExactMulEvaluator, RNSHybridGadgetKey};
use nine65::ops::rns_fhe::{RNSCiphertext, RNSFHEContext, RNSKeySet};
use nine65::ops::rns_galois::{RNSGaloisEvaluator, RNSGaloisKey};
use nine65::params::SecureConfig;
use std::collections::BTreeMap;

fn inverse(a: u64, modulus: u64) -> u64 {
    let (mut r, mut next_r) = (modulus as i128, a as i128);
    let (mut t, mut next_t) = (0i128, 1i128);
    while next_r != 0 {
        let quotient = r / next_r;
        (r, next_r) = (next_r, r - quotient * next_r);
        (t, next_t) = (next_t, t - quotient * next_t);
    }
    assert_eq!(r, 1, "inverse exists");
    t.rem_euclid(modulus as i128) as u64
}

fn mod_pow(base: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut result = 1u128;
    let mut b = base as u128;
    let m = modulus as u128;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = result * b % m;
        }
        b = b * b % m;
        exponent >>= 1;
    }
    result as u64
}

fn primitive_2n_root(n: usize, modulus: u64) -> u64 {
    (2..modulus)
        .find(|&candidate| mod_pow(candidate, n as u64, modulus) == modulus - 1)
        .expect("plaintext modulus contains a primitive 2N-th root")
}

fn roots(n: usize, modulus: u64) -> Vec<u64> {
    let zeta = primitive_2n_root(n, modulus);
    (0..n)
        .map(|k| mod_pow(zeta, (2 * k + 1) as u64, modulus))
        .collect()
}

fn inverse_ntt(values: &[u64], root_values: &[u64], modulus: u64) -> Vec<u64> {
    let n = values.len();
    let inv_n = inverse(n as u64, modulus);
    (0..n)
        .map(|coefficient| {
            let sum = values
                .iter()
                .zip(root_values)
                .fold(0u128, |sum, (&value, &root)| {
                    let inverse_root = inverse(root, modulus);
                    let power = mod_pow(inverse_root, coefficient as u64, modulus);
                    (sum + value as u128 * power as u128) % modulus as u128
                });
            (sum * inv_n as u128 % modulus as u128) as u64
        })
        .collect()
}

fn coefficient_matrices(
    n: usize,
    modulus: u64,
    root_values: &[u64],
) -> (Vec<Vec<u64>>, Vec<Vec<u64>>) {
    let inv_n = inverse(n as u64, modulus);
    let to_slots = (0..n)
        .map(|slot| {
            (0..n)
                .map(|coefficient| mod_pow(root_values[slot], coefficient as u64, modulus))
                .collect()
        })
        .collect();
    let to_coefficients = (0..n)
        .map(|coefficient| {
            (0..n)
                .map(|slot| {
                    let inverse_root = inverse(root_values[slot], modulus);
                    (mod_pow(inverse_root, coefficient as u64, modulus) as u128 * inv_n as u128
                        % modulus as u128) as u64
                })
                .collect()
        })
        .collect();
    (to_slots, to_coefficients)
}

fn local_carry_coefficients(source_q: i64, r0: i64, r1: i64, plaintext: u64) -> (i64, i64) {
    let nearest = |value: i64| (value + source_q / 2).div_euclid(source_q);
    assert!(r0.abs() <= source_q / 2 && r1.abs() <= source_q / 2);
    assert_eq!(nearest(r0), 0);
    let center = |value: i64| {
        let residue = value.rem_euclid(plaintext as i64);
        if residue > plaintext as i64 / 2 {
            residue - plaintext as i64
        } else {
            residue
        }
    };
    let minus = nearest(r0 - r1);
    let plus = nearest(r0 + r1);
    let inverse_two = ((plaintext + 1) / 2) as i64;
    (
        center((plus + minus) * inverse_two),
        center((plus - minus) * inverse_two),
    )
}

fn linear_map_from_slots(
    ctx: &RNSFHEContext,
    input: &RNSCiphertext,
    matrix: &[Vec<u64>],
    roots: &[u64],
    galois: &RNSGaloisEvaluator<'_>,
    keys: &BTreeMap<u64, RNSGaloisKey>,
) -> RNSCiphertext {
    let n = ctx.n;
    let two_n = 2 * n;
    let mut output: Option<RNSCiphertext> = None;
    for exponent in (1..two_n).step_by(2) {
        let permuted = if exponent == 1 {
            input.clone()
        } else {
            galois.apply(input, &keys[&(exponent as u64)]).unwrap()
        };
        let diagonal: Vec<u64> = (0..n)
            .map(|slot| {
                let odd_root_index = exponent * (2 * slot + 1) % two_n;
                let source_slot = (odd_root_index - 1) / 2;
                matrix[slot][source_slot]
            })
            .collect();
        let diagonal_polynomial = inverse_ntt(&diagonal, roots, ctx.t);
        let term = multiply_plain(ctx, &permuted, &diagonal_polynomial);
        output = Some(match output {
            None => term,
            Some(previous) => add(ctx, &previous, &term),
        });
    }
    output.expect("N is positive")
}

fn add(ctx: &RNSFHEContext, a: &RNSCiphertext, b: &RNSCiphertext) -> RNSCiphertext {
    RNSCiphertext {
        c0: a.c0.add(&b.c0, &ctx.rns),
        c1: a.c1.add(&b.c1, &ctx.rns),
        num_primes: a.num_primes,
    }
}

fn multiply_plain(ctx: &RNSFHEContext, input: &RNSCiphertext, polynomial: &[u64]) -> RNSCiphertext {
    let multiply = |poly: &RNSPolynomial| {
        let limbs = ctx
            .config
            .primes
            .iter()
            .enumerate()
            .map(|(lane, &q)| {
                let mont = &ctx.rns.mont_contexts[lane];
                let ordinary: Vec<_> = poly.limbs[lane]
                    .iter()
                    .map(|&value| mont.from_montgomery(value))
                    .collect();
                let plain: Vec<_> = polynomial.iter().map(|&value| value % q).collect();
                ctx.ntt_engines[lane]
                    .multiply(&ordinary, &plain)
                    .into_iter()
                    .map(|value| mont.to_montgomery(value))
                    .collect()
            })
            .collect();
        RNSPolynomial { limbs, n: ctx.n }
    };
    RNSCiphertext {
        c0: multiply(&input.c0),
        c1: multiply(&input.c1),
        num_primes: input.num_primes,
    }
}

fn add_plain_constant(ctx: &RNSFHEContext, input: &RNSCiphertext, value: u64) -> RNSCiphertext {
    let mut output = input.clone();
    for (lane, &q) in ctx.config.primes.iter().enumerate() {
        let encoded = (ctx.delta_rns[lane] as u128 * value as u128 % q as u128) as u64;
        let encoded = ctx.rns.mont_contexts[lane].to_montgomery(encoded);
        output.c0.limbs[lane][0] =
            ((output.c0.limbs[lane][0] as u128 + encoded as u128) % q as u128) as u64;
    }
    output
}

fn encrypt_polynomial(
    ctx: &RNSFHEContext,
    keys: &RNSKeySet,
    message: &[u64],
    rng: &mut ShadowHarvester,
) -> RNSCiphertext {
    let mut ciphertext = ctx.encrypt(0, &keys.public_key, rng);
    for (lane, &q) in ctx.config.primes.iter().enumerate() {
        let mont = &ctx.rns.mont_contexts[lane];
        for (coefficient, &value) in message.iter().enumerate() {
            let encoded = (ctx.delta_rns[lane] as u128 * value as u128 % q as u128) as u64;
            let encoded = mont.to_montgomery(encoded);
            ciphertext.c0.limbs[lane][coefficient] =
                ((ciphertext.c0.limbs[lane][coefficient] as u128 + encoded as u128) % q as u128)
                    as u64;
        }
    }
    ciphertext
}

fn decrypt_coefficients(
    ctx: &RNSFHEContext,
    ciphertext: &RNSCiphertext,
    keys: &RNSKeySet,
) -> Vec<u64> {
    let phases: Vec<Vec<u64>> = ctx
        .config
        .primes
        .iter()
        .enumerate()
        .map(|(lane, &q)| {
            let mont = &ctx.rns.mont_contexts[lane];
            let c0: Vec<_> = ciphertext.c0.limbs[lane]
                .iter()
                .map(|&value| mont.from_montgomery(value))
                .collect();
            let c1: Vec<_> = ciphertext.c1.limbs[lane]
                .iter()
                .map(|&value| mont.from_montgomery(value))
                .collect();
            let secret: Vec<_> = keys.secret_key.s.limbs[lane]
                .iter()
                .map(|&value| mont.from_montgomery(value))
                .collect();
            let product = ctx.ntt_engines[lane].multiply(&c1, &secret);
            c0.iter()
                .zip(product)
                .map(|(&a, b)| ((a as u128 + b as u128) % q as u128) as u64)
                .collect()
        })
        .collect();
    let decoder = CanonicalScaleRound::new(&ctx.config.primes, ctx.t).unwrap();
    (0..ctx.n)
        .map(|coefficient| {
            let residues: Vec<_> = phases.iter().map(|lane| lane[coefficient]).collect();
            decoder.scale_round(&residues).unwrap()
        })
        .collect()
}

fn evaluate_full_domain_low_digit(
    ctx: &RNSFHEContext,
    input: &RNSCiphertext,
    base: u64,
    relin: &RNSHybridGadgetKey,
) -> RNSCiphertext {
    // F(x)=x+prod_(a=0..p-1)(x-a) is x mod p in Z/(p^2).
    let exact: ExactMulEvaluator<'_> = ctx.try_exact_evaluator().unwrap();
    let mut factors: Vec<RNSCiphertext> = (0..base)
        .map(|a| add_plain_constant(ctx, input, ctx.t - a % ctx.t))
        .collect();
    while factors.len() > 1 {
        let mut next = Vec::with_capacity(factors.len().div_ceil(2));
        let mut iter = factors.into_iter();
        while let Some(left) = iter.next() {
            if let Some(right) = iter.next() {
                next.push(exact.try_mul_exact(&left, &right, relin).unwrap());
            } else {
                next.push(left);
            }
        }
        factors = next;
    }
    add(ctx, input, &factors.pop().unwrap())
}

#[test]
fn encrypted_slot_bridge_applies_jacobian_digit_gate_to_dense_coefficients() {
    const BASE: u64 = 17;
    let mut config = SecureConfig::secure_128().into_config();
    config.n = 8;
    config.t = BASE * BASE;
    config.security_bits = 0;
    config.name = "INSECURE coefficient/slot gate toy";
    let ctx = RNSFHEContext::try_new(&config).unwrap();
    let mut rng = ShadowHarvester::with_seed(0x5349_4d44_4352_414d);
    let keys = ctx.generate_keys(&mut rng);
    let exact = ctx.try_exact_evaluator().unwrap();
    let relin = exact.generate_hybrid_gadget_key_with_rng(&keys.secret_key, &mut rng);
    let galois = RNSGaloisEvaluator::new(&ctx).unwrap();
    let mut galois_keys = BTreeMap::new();
    for exponent in (3..2 * ctx.n).step_by(2) {
        galois_keys.insert(
            exponent as u64,
            galois
                .generate_key_with_rng(&keys.secret_key, exponent as u64, &mut rng)
                .unwrap(),
        );
    }
    let root_values = roots(ctx.n, ctx.t);
    let (coefficient_to_slot, slot_to_coefficient) =
        coefficient_matrices(ctx.n, ctx.t, &root_values);
    let input = vec![0, 16, 17, 18, 33, 143, 255, 288];
    let encrypted = encrypt_polynomial(&ctx, &keys, &input, &mut rng);

    let coefficient_slots = linear_map_from_slots(
        &ctx,
        &encrypted,
        &slot_to_coefficient,
        &root_values,
        &galois,
        &galois_keys,
    );
    let slots_as_coefficients = decrypt_coefficients(&ctx, &coefficient_slots, &keys);
    let recovered_slots: Vec<u64> = (0..ctx.n)
        .map(|slot| {
            slots_as_coefficients
                .iter()
                .enumerate()
                .fold(0u128, |sum, (coefficient, &value)| {
                    (sum + value as u128
                        * mod_pow(root_values[slot], coefficient as u64, ctx.t) as u128)
                        % ctx.t as u128
                }) as u64
        })
        .collect();
    assert_eq!(recovered_slots, input);

    let low_digits = evaluate_full_domain_low_digit(&ctx, &coefficient_slots, BASE, &relin);
    let output = linear_map_from_slots(
        &ctx,
        &low_digits,
        &coefficient_to_slot,
        &root_values,
        &galois,
        &galois_keys,
    );
    assert_eq!(
        decrypt_coefficients(&ctx, &output, &keys),
        input.iter().map(|value| value % BASE).collect::<Vec<_>>()
    );
    eprintln!(
        "encrypted coefficientwise digit gate: N={}, 2 transforms × {} automorphism-diagonal terms, degree={}, output checked at every coefficient; insecure toy only",
        ctx.n,
        ctx.n,
        BASE
    );
}

#[test]
fn direct_native_slot_bridge_cost_is_explicitly_too_large() {
    let config = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&config).unwrap();
    let exact = ctx.try_exact_evaluator().unwrap();
    let plan = exact.plan().certificate();
    let digit_count: usize = plan.digits_per_lane.iter().sum();
    let words_per_key = 2usize
        .checked_mul(digit_count)
        .and_then(|v| v.checked_mul(config.primes.len()))
        .and_then(|v| v.checked_mul(config.n))
        .expect("key size fits usize");
    let key_count = config.n - 1;
    let total_bytes = words_per_key as u128 * key_count as u128 * 8;
    let total_gib = total_bytes as f64 / (1024.0_f64.powi(3));
    eprintln!(
        "naive N={} coefficient/slot transform needs {} Galois keys; {} gadget digits/lane-set; estimated key payload {:.2} GiB before metadata",
        config.n,
        key_count,
        digit_count,
        total_gib
    );
    assert!(total_gib > 8.0, "the direct transform is a toy only");
}

#[test]
fn encrypted_slot_bridge_applies_dense_cram_ternary_carry_gate() {
    const BASE: u64 = 17;
    const SOURCE_Q: i64 = 101;
    let mut config = SecureConfig::secure_128().into_config();
    config.n = 8;
    config.t = BASE * BASE;
    config.security_bits = 0;
    config.name = "INSECURE dense CRAM carry-gate toy";
    let ctx = RNSFHEContext::try_new(&config).unwrap();
    let mut rng = ShadowHarvester::with_seed(0x4352_414d_4341_5252);
    let keys = ctx.generate_keys(&mut rng);
    let exact = ctx.try_exact_evaluator().unwrap();
    let relin = exact.generate_hybrid_gadget_key_with_rng(&keys.secret_key, &mut rng);
    let galois = RNSGaloisEvaluator::new(&ctx).unwrap();
    let mut galois_keys = BTreeMap::new();
    for exponent in (3..2 * ctx.n).step_by(2) {
        galois_keys.insert(
            exponent as u64,
            galois
                .generate_key_with_rng(&keys.secret_key, exponent as u64, &mut rng)
                .unwrap(),
        );
    }
    let root_values = roots(ctx.n, ctx.t);
    let (coefficient_to_slot, slot_to_coefficient) =
        coefficient_matrices(ctx.n, ctx.t, &root_values);

    let mont = &ctx.rns.mont_contexts[0];
    let q_lane = ctx.config.primes[0];
    let secret: Vec<i8> = keys.secret_key.s.limbs[0]
        .iter()
        .map(|&value| match mont.from_montgomery(value) {
            0 => 0,
            1 => 1,
            v if v == q_lane - 1 => -1,
            _ => panic!("test secret is not ternary"),
        })
        .collect();
    let encrypted_secret = encrypt_polynomial(
        &ctx,
        &keys,
        &secret
            .iter()
            .map(|&value| (value as i64).rem_euclid(ctx.t as i64) as u64)
            .collect::<Vec<_>>(),
        &mut rng,
    );

    // Different public residual pairs in every coefficient exercise the
    // coefficientwise Jacobian gate, not one scalar repeated across the ring.
    let boundaries = [-50, -49, -1, 0, 1, 49, 50];
    let profiles: Vec<(i64, i64)> = (0..ctx.n)
        .map(|j| (boundaries[(3 * j + 2) % 7], boundaries[(5 * j + 1) % 7]))
        .collect();
    let coefficients: Vec<_> = profiles
        .iter()
        .map(|&(r0, r1)| local_carry_coefficients(SOURCE_Q, r0, r1, ctx.t))
        .collect();
    let square_weights: Vec<_> = coefficients
        .iter()
        .map(|&(square, _)| square.rem_euclid(ctx.t as i64) as u64)
        .collect();
    let linear_weights: Vec<_> = coefficients
        .iter()
        .map(|&(_, linear)| linear.rem_euclid(ctx.t as i64) as u64)
        .collect();

    // Negative control: ring squaring is convolution, so it is not the
    // coordinatewise square required by the carry polynomial.
    let direct_square = exact
        .try_mul_exact(&encrypted_secret, &encrypted_secret, &relin)
        .unwrap();
    assert_ne!(
        decrypt_coefficients(&ctx, &direct_square, &keys),
        secret
            .iter()
            .map(|&value| (value as i64 * value as i64).rem_euclid(ctx.t as i64) as u64)
            .collect::<Vec<_>>()
    );

    let secret_slots = linear_map_from_slots(
        &ctx,
        &encrypted_secret,
        &slot_to_coefficient,
        &root_values,
        &galois,
        &galois_keys,
    );
    let square_slots = exact
        .try_mul_exact(&secret_slots, &secret_slots, &relin)
        .unwrap();
    let weighted_square = multiply_plain(
        &ctx,
        &square_slots,
        &inverse_ntt(&square_weights, &root_values, ctx.t),
    );
    let weighted_linear = multiply_plain(
        &ctx,
        &secret_slots,
        &inverse_ntt(&linear_weights, &root_values, ctx.t),
    );
    let carry_slots = add(&ctx, &weighted_square, &weighted_linear);
    let carry_coefficients = linear_map_from_slots(
        &ctx,
        &carry_slots,
        &coefficient_to_slot,
        &root_values,
        &galois,
        &galois_keys,
    );
    let expected: Vec<u64> = profiles
        .iter()
        .zip(&secret)
        .map(|(&(r0, r1), &trit)| {
            ((r0 + r1 * trit as i64 + SOURCE_Q / 2).div_euclid(SOURCE_Q)).rem_euclid(ctx.t as i64)
                as u64
        })
        .collect();
    assert_eq!(
        decrypt_coefficients(&ctx, &carry_coefficients, &keys),
        expected
    );
    eprintln!(
        "dense local CRAM carry gate: N={}, all coefficients checked, each has its own residual pair; direct ring square negative control fails as expected; insecure toy only",
        ctx.n
    );
}
