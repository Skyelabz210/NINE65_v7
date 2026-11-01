//! Encrypted toy proof of the coefficient/slot bridge needed by a
//! coefficientwise CRAM carry or digit gate. The linear transform is the
//! baby-step/giant-step automorphism-diagonal decomposition, intentionally a
//! correctness prototype rather than a production-cost transform. The
//! tropical lift test separately consumes paired encrypted coordinates with
//! a linear K-elimination step, requiring no coefficient/slot transform.

use nine65::arithmetic::canonical_scale_round::CanonicalScaleRound;
use nine65::arithmetic::RNSPolynomial;
use nine65::entropy::ShadowHarvester;
use nine65::ops::rns_fhe::exact_mul::{ExactMulEvaluator, RNSHybridGadgetKey};
use nine65::ops::rns_fhe::{RNSCiphertext, RNSFHEContext, RNSKeySet};
use nine65::ops::rns_galois::{RNSGaloisEvaluator, RNSGaloisKey};
use nine65::params::SecureConfig;
use std::collections::{BTreeMap, BTreeSet};

#[path = "research/tropical_chart_transition.rs"]
mod tropical_chart_transition;

#[path = "research/tropical_cocycle_state.rs"]
mod tropical_cocycle_state;

#[path = "research/phase_clock_compaction.rs"]
mod phase_clock_compaction;

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
    let inverse_two = plaintext.div_ceil(2) as i64;
    (
        center((plus + minus) * inverse_two),
        center((plus - minus) * inverse_two),
    )
}

fn automorphism_factor_sets(n: usize) -> (Vec<u64>, Vec<u64>) {
    assert!(n.is_power_of_two() && n >= 2);
    let two_n = (2 * n) as u64;
    let cyclic_order = (n / 2) as u64;
    let baby_cyclic = 1u64 << (cyclic_order.ilog2() / 2);
    let giant_count = cyclic_order / baby_cyclic;
    let baby_step = giant_count;

    let mut baby = BTreeSet::new();
    for sign in [1u64, two_n - 1] {
        for index in 0..baby_cyclic {
            baby.insert(sign * mod_pow(5, baby_step * index, two_n) % two_n);
        }
    }
    let giant: BTreeSet<u64> = (0..giant_count)
        .map(|index| mod_pow(5, index, two_n))
        .collect();

    // The product map must be a unique factorization of every odd residue.
    let products: BTreeSet<u64> = baby
        .iter()
        .flat_map(|&b| giant.iter().map(move |&c| b * c % two_n))
        .collect();
    assert_eq!(baby.len() * giant.len(), n);
    assert_eq!(products.len(), n);
    assert_eq!(
        products,
        (0..n).map(|index| (2 * index + 1) as u64).collect()
    );

    (baby.into_iter().collect(), giant.into_iter().collect())
}

fn required_galois_exponents(baby: &[u64], giant: &[u64]) -> Vec<u64> {
    baby.iter()
        .chain(giant)
        .copied()
        .filter(|&exponent| exponent != 1)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn linear_map_from_slots_bsgs(
    ctx: &RNSFHEContext,
    input: &RNSCiphertext,
    matrix: &[Vec<u64>],
    roots: &[u64],
    galois: &RNSGaloisEvaluator<'_>,
    keys: &BTreeMap<u64, RNSGaloisKey>,
    baby: &[u64],
    giant: &[u64],
) -> RNSCiphertext {
    let n = ctx.n;
    let two_n = (2 * n) as u64;
    let source_slot =
        |exponent: u64, slot: usize| ((exponent as usize * (2 * slot + 1) % (2 * n)) - 1) / 2;
    let baby_inputs: BTreeMap<u64, RNSCiphertext> = baby
        .iter()
        .map(|&exponent| {
            let permuted = if exponent == 1 {
                input.clone()
            } else {
                galois.apply(input, &keys[&exponent]).unwrap()
            };
            (exponent, permuted)
        })
        .collect();
    let mut output: Option<RNSCiphertext> = None;
    for &giant_exponent in giant {
        let mut giant_sum: Option<RNSCiphertext> = None;
        for &baby_exponent in baby {
            let exponent = baby_exponent * giant_exponent % two_n;
            let diagonal: Vec<u64> = (0..n)
                .map(|slot| matrix[slot][source_slot(exponent, slot)])
                .collect();
            // P_c(D_g P_b x) needs the diagonal reindexed by P_c's
            // permutation: d'[source_c(k)] = d_g[k].
            let mut reindexed_diagonal = vec![0u64; n];
            for slot in 0..n {
                reindexed_diagonal[source_slot(giant_exponent, slot)] = diagonal[slot];
            }
            let polynomial = inverse_ntt(&reindexed_diagonal, roots, ctx.t);
            let term = multiply_plain(ctx, &baby_inputs[&baby_exponent], &polynomial);
            giant_sum = Some(match giant_sum {
                None => term,
                Some(previous) => add(ctx, &previous, &term),
            });
        }
        let giant_sum = giant_sum.expect("each giant factor has baby factors");
        let permuted = if giant_exponent == 1 {
            giant_sum
        } else {
            galois.apply(&giant_sum, &keys[&giant_exponent]).unwrap()
        };
        output = Some(match output {
            None => permuted,
            Some(previous) => add(ctx, &previous, &permuted),
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

fn decrypted_phase_residues(
    ctx: &RNSFHEContext,
    ciphertext: &RNSCiphertext,
    keys: &RNSKeySet,
) -> Vec<Vec<u64>> {
    ctx.config
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
        .collect()
}

fn decrypt_coefficients(
    ctx: &RNSFHEContext,
    ciphertext: &RNSCiphertext,
    keys: &RNSKeySet,
) -> Vec<u64> {
    let phases = decrypted_phase_residues(ctx, ciphertext, keys);
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

// Public residue-pair consumer. The missing refresh construction must supply
// these two authentic coordinates; this function does not center an encrypted
// source phase or use a secret to choose its tropical cell.
fn tropical_winding_from_paired_coordinates(
    ctx: &RNSFHEContext,
    source_period: u64,
    source_residue: &RNSCiphertext,
    centered_chart_residue: &RNSCiphertext,
) -> RNSCiphertext {
    let mut multiplier = vec![0; ctx.n];
    multiplier[0] = inverse(source_period % ctx.t, ctx.t);
    multiply_plain(
        ctx,
        &ctx.sub(source_residue, centered_chart_residue),
        &multiplier,
    )
}

#[test]
fn encrypted_tropical_lift_consumes_paired_coordinates_without_slot_transforms() {
    const SOURCE_PERIOD: i64 = 31;
    let mut config = SecureConfig::secure_128().into_config();
    config.n = 8;
    config.t = 17 * 17; // Composite lift-coordinate modulus, coprime to 31.
    config.security_bits = 0;
    config.name = "INSECURE tropical paired-coordinate lift toy";
    let ctx = RNSFHEContext::try_new(&config).unwrap();
    let mut rng = ShadowHarvester::with_seed(0x5452_4f50_4c49_4654);
    let keys = ctx.generate_keys(&mut rng);
    let exact = ctx.try_exact_evaluator().unwrap();
    let relin = exact.generate_hybrid_gadget_key_with_rng(&keys.secret_key, &mut rng);
    let sheets = [-33i64, -12, -1, 0, 1, 12, 33, 4];
    let chart = [-15i64, -14, -1, 0, 1, 14, 15, 0];
    let reduce = |value: i64| value.rem_euclid(ctx.t as i64) as u64;
    let qb: u128 = config.primes.iter().map(|&prime| prime as u128).product();
    let t = ctx.t as u128;
    // Constructor/sampler bound in ideal-grid units V=t*phase-Q*m mod tQ.
    // Adding the nonnegative encoded polynomial includes floor-Delta bias.
    let fresh_v = t * (2 * ctx.n as u128 + 1) * config.eta as u128 + (qb % t) * (t - 1);
    let inverse_period = inverse(SOURCE_PERIOD as u64, ctx.t) as u128;
    let lift_v = 2 * inverse_period * fresh_v;
    assert!(2 * lift_v < qb);

    for increment in [0i64, 1] {
        // Fixture boundary: the holder supplies BOTH coordinates, rather than
        // claiming this test implements the unknown encrypted chart producer.
        let source: Vec<i64> = chart
            .iter()
            .zip(sheets)
            .map(|(&g, k)| g + SOURCE_PERIOD * k + increment)
            .collect();
        let expected: Vec<i64> = source
            .iter()
            .map(|&s| (s + SOURCE_PERIOD / 2).div_euclid(SOURCE_PERIOD))
            .collect();
        let centered: Vec<u64> = source
            .iter()
            .zip(&expected)
            .map(|(&s, &k)| reduce(s - SOURCE_PERIOD * k))
            .collect();
        let source_residues: Vec<u64> = source.iter().map(|&s| reduce(s)).collect();
        let encrypted_source = encrypt_polynomial(&ctx, &keys, &source_residues, &mut rng);
        let encrypted_chart = encrypt_polynomial(&ctx, &keys, &centered, &mut rng);

        // Evaluator boundary: these calls receive ciphertexts/public periods.
        let winding = tropical_winding_from_paired_coordinates(
            &ctx,
            SOURCE_PERIOD as u64,
            &encrypted_source,
            &encrypted_chart,
        );
        assert_eq!(
            decrypt_coefficients(&ctx, &winding, &keys),
            expected.iter().map(|&k| reduce(k)).collect::<Vec<_>>()
        );

        // Dependent encrypted operation, checked against an independent
        // signed schoolbook negacyclic product (not coefficientwise squaring).
        let square = exact.try_mul_exact(&winding, &winding, &relin).unwrap();
        let mut expected_square = vec![0i64; ctx.n];
        for (i, &a) in expected.iter().enumerate() {
            for (j, &b) in expected.iter().enumerate() {
                let sign = if i + j >= ctx.n { -1 } else { 1 };
                expected_square[(i + j) % ctx.n] += sign * a * b;
            }
        }
        assert_eq!(
            decrypt_coefficients(&ctx, &square, &keys),
            expected_square.into_iter().map(reduce).collect::<Vec<_>>()
        );

        // Omission control: a source residue alone does not supply the chart.
        let mut multiplier = vec![0; ctx.n];
        multiplier[0] = inverse_period as u64;
        let omitted_chart = multiply_plain(&ctx, &encrypted_source, &multiplier);
        assert_ne!(
            decrypt_coefficients(&ctx, &omitted_chart, &keys),
            expected.iter().map(|&k| reduce(k)).collect::<Vec<_>>()
        );
    }
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
    let (baby_exponents, giant_exponents) = automorphism_factor_sets(ctx.n);
    let mut galois_keys = BTreeMap::new();
    for exponent in required_galois_exponents(&baby_exponents, &giant_exponents) {
        galois_keys.insert(
            exponent,
            galois
                .generate_key_with_rng(&keys.secret_key, exponent, &mut rng)
                .unwrap(),
        );
    }
    let root_values = roots(ctx.n, ctx.t);
    let (coefficient_to_slot, slot_to_coefficient) =
        coefficient_matrices(ctx.n, ctx.t, &root_values);
    let input = vec![0, 16, 17, 18, 33, 143, 255, 288];
    let encrypted = encrypt_polynomial(&ctx, &keys, &input, &mut rng);

    let coefficient_slots = linear_map_from_slots_bsgs(
        &ctx,
        &encrypted,
        &slot_to_coefficient,
        &root_values,
        &galois,
        &galois_keys,
        &baby_exponents,
        &giant_exponents,
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
    let output = linear_map_from_slots_bsgs(
        &ctx,
        &low_digits,
        &coefficient_to_slot,
        &root_values,
        &galois,
        &galois_keys,
        &baby_exponents,
        &giant_exponents,
    );
    assert_eq!(
        decrypt_coefficients(&ctx, &output, &keys),
        input.iter().map(|value| value % BASE).collect::<Vec<_>>()
    );
    eprintln!(
        "encrypted coefficientwise digit gate: N={}, 2 BSGS transforms × {} diagonal terms using {} Galois keys, degree={}, output checked at every coefficient; insecure toy only",
        ctx.n,
        ctx.n,
        galois_keys.len(),
        BASE
    );
}

#[test]
fn bsgs_native_slot_bridge_cost_is_explicitly_too_large() {
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
    let direct_key_count = config.n - 1;
    let direct_bytes = words_per_key as u128 * direct_key_count as u128 * 8;
    const GIB: u128 = 1024 * 1024 * 1024;
    let direct_gib_hundredths = direct_bytes * 100 / GIB;
    let (baby, giant) = automorphism_factor_sets(config.n);
    let key_count = required_galois_exponents(&baby, &giant).len();
    let total_bytes = words_per_key as u128 * key_count as u128 * 8;
    let total_gib_hundredths = total_bytes * 100 / GIB;
    eprintln!(
        "N={} coefficient/slot transform: direct={} Galois keys ({}.{:02} GiB); BSGS baby={} giant={} keys={} ({}.{:02} GiB); {} gadget digits/lane-set; diagonal multiply/add count remains N per transform; estimates exclude metadata",
        config.n,
        direct_key_count,
        direct_gib_hundredths / 100,
        direct_gib_hundredths % 100,
        baby.len(),
        giant.len(),
        key_count,
        total_gib_hundredths / 100,
        total_gib_hundredths % 100,
        digit_count,
    );
    assert_eq!(key_count, 190);
    assert!(total_bytes > GIB, "the BSGS transform remains too large");
    assert!(total_bytes * 32 < direct_bytes);
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
    let (baby_exponents, giant_exponents) = automorphism_factor_sets(ctx.n);
    let mut galois_keys = BTreeMap::new();
    for exponent in required_galois_exponents(&baby_exponents, &giant_exponents) {
        galois_keys.insert(
            exponent,
            galois
                .generate_key_with_rng(&keys.secret_key, exponent, &mut rng)
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

    let secret_slots = linear_map_from_slots_bsgs(
        &ctx,
        &encrypted_secret,
        &slot_to_coefficient,
        &root_values,
        &galois,
        &galois_keys,
        &baby_exponents,
        &giant_exponents,
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
    let carry_coefficients = linear_map_from_slots_bsgs(
        &ctx,
        &carry_slots,
        &coefficient_to_slot,
        &root_values,
        &galois,
        &galois_keys,
        &baby_exponents,
        &giant_exponents,
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

// ---------------------------------------------------------------------------
// Bounded digit polynomial (research). Replaces the degree-p full-domain gate.
// F(r + p*m) = r (mod p^2) for |r| <= B and every m, with deg F <= 4B+1.
// Public constants only; evaluated on every slot at once. See
// scripts/bounded_digit_polynomial.py for the independent exact construction.
// ---------------------------------------------------------------------------
fn bounded_digit_polynomial(p: i64, bound: i64) -> Vec<i64> {
    let m2 = p * p;
    let mul = |a: &Vec<i64>, b: &Vec<i64>, m: i64| {
        let mut o = vec![0i64; a.len() + b.len() - 1];
        for (i, x) in a.iter().enumerate() {
            for (j, y) in b.iter().enumerate() {
                o[i + j] = (o[i + j] + x * y).rem_euclid(m);
            }
        }
        o
    };
    let eval = |c: &Vec<i64>, x: i64, m: i64| c.iter().rev().fold(0i64, |o, &k| (o * x + k).rem_euclid(m));
    let mut g = vec![1i64];
    for r in -bound..=bound {
        g = mul(&g, &vec![(-r).rem_euclid(m2), 1], m2);
    }
    let mut h = vec![0i64; g.len() - 1];
    for r in -bound..=bound {
        let l = g.len() - 2;
        let mut q = vec![0i64; l + 1];
        q[l] = g[l + 1].rem_euclid(p);
        for i in (0..l).rev() {
            q[i] = (g[i + 1] + r * q[i + 1]).rem_euclid(p);
        }
        let d = eval(&q, r, p);
        let inv = (0..p - 2).fold(1i64, |a, _| a * d % p);
        for (i, c) in q.iter().enumerate() {
            h[i] = (h[i] + c * inv % p * inv).rem_euclid(p);
        }
    }
    let gh = mul(&g, &h, m2);
    let mut f: Vec<i64> = gh.iter().map(|c| (-c).rem_euclid(m2)).collect();
    f[1] = (f[1] + 1).rem_euclid(m2);
    while f.len() > 1 && *f.last().unwrap() == 0 {
        f.pop();
    }
    f
}

fn centered_mod(v: i64, m: i64) -> i64 {
    let r = v.rem_euclid(m);
    if 2 * r > m { r - m } else { r }
}

fn ntt_primes_below(n: usize, count: usize) -> Vec<u64> {
    fn is_prime(x: u64) -> bool {
        if x < 2 { return false }
        for sp in [2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
            if x % sp == 0 { return x == sp }
        }
        let (mut d, mut r) = (x - 1, 0);
        while d % 2 == 0 { d /= 2; r += 1 }
        'w: for a in [2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
            let mut y = mod_pow(a, d, x);
            if y == 1 || y == x - 1 { continue }
            for _ in 0..r - 1 {
                y = (y as u128 * y as u128 % x as u128) as u64;
                if y == x - 1 { continue 'w }
            }
            return false;
        }
        true
    }
    let step = 2 * n as u64;
    let mut out = Vec::new();
    let mut c = ((1u64 << 31) / step) * step + 1;
    while out.len() < count {
        c -= step;
        if is_prime(c) { out.push(c) }
    }
    out
}

fn evaluate_bounded_digit(
    ctx: &RNSFHEContext,
    input: &RNSCiphertext,
    f: &[i64],
    relin: &RNSHybridGadgetKey,
) -> RNSCiphertext {
    let exact = ctx.try_exact_evaluator().unwrap();
    let t = ctx.t as i64;
    let mut constant = vec![0u64; ctx.n];
    constant[0] = f[f.len() - 1].rem_euclid(t) as u64;
    // acc = f_d*x + f_{d-1}; then acc = acc*x + f_k for k = d-2 .. 0.
    let mut acc = multiply_plain(ctx, input, &constant);
    acc = add_plain_constant(ctx, &acc, f[f.len() - 2].rem_euclid(t) as u64);
    for k in (0..f.len() - 2).rev() {
        acc = exact.try_mul_exact(&acc, input, relin).unwrap();
        acc = add_plain_constant(ctx, &acc, f[k].rem_euclid(t) as u64);
    }
    acc
}

#[test]
fn encrypted_slot_bridge_removes_bounded_digit_error_and_recovers_p_times_message() {
    // p = 17, t = p^2, N = 8. Input coefficients W_j = p*m_j + eps_j, |eps_j| <= B.
    const P: i64 = 17;
    let bound: i64 = std::env::var("BDG_B").ok().and_then(|v| v.parse().ok()).unwrap_or(2);
    #[allow(non_snake_case)]
    let BOUND = bound;
    let lanes: usize = std::env::var("BDG_LANES").ok().and_then(|v| v.parse().ok()).unwrap_or(8);
    let mut config = SecureConfig::secure_128().into_config();
    config.n = 8;
    config.t = (P * P) as u64;
    config.security_bits = 0;
    config.name = "INSECURE bounded digit gate toy";
    config.primes = ntt_primes_below(config.n, lanes);
    config.q = config.primes[0];
    let ctx = RNSFHEContext::try_new(&config).unwrap();
    let mut rng = ShadowHarvester::with_seed(0x4244_4947_4154_4531);
    let keys = ctx.generate_keys(&mut rng);
    let exact = ctx.try_exact_evaluator().unwrap();
    let relin = exact.generate_hybrid_gadget_key_with_rng(&keys.secret_key, &mut rng);
    let galois = RNSGaloisEvaluator::new(&ctx).unwrap();
    let (baby_exponents, giant_exponents) = automorphism_factor_sets(ctx.n);
    let mut galois_keys = BTreeMap::new();
    for exponent in required_galois_exponents(&baby_exponents, &giant_exponents) {
        galois_keys.insert(exponent, galois.generate_key_with_rng(&keys.secret_key, exponent, &mut rng).unwrap());
    }
    let root_values = roots(ctx.n, ctx.t);
    let (coefficient_to_slot, slot_to_coefficient) = coefficient_matrices(ctx.n, ctx.t, &root_values);
    let f = bounded_digit_polynomial(P, BOUND);
    // exhaustive clear check of the construction over the whole domain
    for r in -BOUND..=BOUND {
        for m in 0..P {
            let w = (r + P * m).rem_euclid(P * P);
            let v = f.iter().rev().fold(0i64, |o, &c| (o * w + c).rem_euclid(P * P));
            assert_eq!(centered_mod(v, P * P), r);
        }
    }
    let messages: Vec<i64> = vec![0, 1, 5, 9, 16, 3, 11, 14];
    let eps: Vec<i64> = (0..8).map(|j| (j as i64 % (2 * BOUND + 1)) - BOUND).collect();
    let input: Vec<u64> = (0..ctx.n).map(|j| (P * messages[j] + eps[j]).rem_euclid(P * P) as u64).collect();
    let encrypted = encrypt_polynomial(&ctx, &keys, &input, &mut rng);
    let slots = linear_map_from_slots_bsgs(&ctx, &encrypted, &slot_to_coefficient, &root_values, &galois, &galois_keys, &baby_exponents, &giant_exponents);
    let slot_values = |ct: &RNSCiphertext| -> Vec<u64> {
        let coeffs = decrypt_coefficients(&ctx, ct, &keys);
        (0..ctx.n).map(|slot| coeffs.iter().enumerate().fold(0u128, |sum, (c, &v)| (sum + v as u128 * mod_pow(root_values[slot], c as u64, ctx.t) as u128) % ctx.t as u128) as u64).collect()
    };
    assert_eq!(slot_values(&slots), input, "stage 1: coefficient->slot bridge");
    let digits = evaluate_bounded_digit(&ctx, &slots, &f, &relin);
    let want_digits: Vec<u64> = eps.iter().map(|e| e.rem_euclid(P * P) as u64).collect();
    let got_digits = slot_values(&digits);
    eprintln!("stage 2 digits got {:?} want {:?}", got_digits, want_digits);
    // p*m = W - F(W) on every slot, then back to coefficient form
    let p_times_m = {
        let neg = multiply_plain(&ctx, &digits, &{ let mut c = vec![0u64; ctx.n]; c[0] = ctx.t - 1; c });
        add(&ctx, &slots, &neg)
    };
    let output = linear_map_from_slots_bsgs(&ctx, &p_times_m, &coefficient_to_slot, &root_values, &galois, &galois_keys, &baby_exponents, &giant_exponents);
    let got = decrypt_coefficients(&ctx, &output, &keys);
    let want: Vec<u64> = messages.iter().map(|&m| (P * m) as u64).collect();
    assert_eq!(got, want);
    eprintln!(
        "bounded digit gate: p={P}, B={BOUND}, deg F={}, lanes={}, log2 Q ~ {} bits; p*m recovered exactly at all {} coefficients; insecure toy only",
        f.len() - 1, lanes, lanes * 31, ctx.n
    );
}
