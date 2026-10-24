//! Power-of-two sister-tray K-Elimination ablation.
//!
//! Scaling the existing 2*N chart by L=65536/(2*N) changes its dependent tray
//! to 2^16. Since p=65537, the tray inverse is -1 in the common p encoding.
//! The original p-tray path remains as a consumer oracle. A second path builds
//! the low-tray chart from the same source ciphertext and checks its adjacent
//! modulus phase lock into p.

use super::*;

fn multiply_plain_ring(left: &[u64], right: &[u64], p: u64) -> Vec<u64> {
    let n = left.len();
    let mut accum = vec![0i128; n];
    for (i, &a) in left.iter().enumerate() {
        let a = if a > p / 2 {
            a as i128 - p as i128
        } else {
            a as i128
        };
        for (j, &b) in right.iter().enumerate() {
            let b = if b > p / 2 {
                b as i128 - p as i128
            } else {
                b as i128
            };
            let index = i + j;
            if index < n {
                accum[index] += a * b;
            } else {
                accum[index - n] -= a * b;
            }
        }
    }
    accum
        .into_iter()
        .map(|v| v.rem_euclid(p as i128) as u64)
        .collect()
}

fn check_power_tray_return(n: usize, weight: usize, phase_denominator: u128) {
    let mut config = SecureConfig::secure_128().into_config();
    config.n = n;
    config.security_bits = 0;
    config.name = "UNADMITTED power-tray K-Elimination return, NOT bootstrap";
    let mut source_config = config.clone();
    source_config.primes.truncate(2);
    let source = RNSFHEContext::try_new(&source_config).unwrap();
    let mut outer_config = config;
    outer_config.n = 2 * n;
    outer_config.primes = COMPOSITE_CHART_PRIMES.to_vec();
    outer_config.t = PHASE_P;
    let outer = RNSFHEContext::try_new(&outer_config).unwrap();
    let source_q = source
        .config
        .primes
        .iter()
        .map(|&q| q as u128)
        .product::<u128>();
    let mut rng = ShadowHarvester::with_seed(0x504f_5752_5452_4159 + n as u64);
    let trits = balanced_source(n, weight, &mut rng);
    let source_keys = sparse_keys(&source, &trits, &mut rng);
    let outer_keys = outer.generate_keys(&mut rng);
    let message: Vec<_> = (0..n)
        .map(|j| if j % 2 == 0 { 1 } else { PHASE_P - 1 })
        .collect();
    let mut input = encrypt_polynomial(&source, &source_keys, &message, &mut rng);
    let load = source_q / ((phase_denominator + 4) * PHASE_P as u128);
    let extra = montgomery(
        &source,
        source
            .config
            .primes
            .iter()
            .map(|&q| {
                let v = (load % q as u128) as u64;
                (0..n)
                    .map(|j| if j % 2 == 0 || v == 0 { v } else { q - v })
                    .collect()
            })
            .collect(),
    );
    input.c0 = input.c0.add(&extra, &source.rns);
    let input_v = PHASE_P as u128 * (2 * n + 1) as u128 * source.config.eta as u128
        + (source_q % PHASE_P as u128) * (PHASE_P - 1) as u128
        + load * PHASE_P as u128;
    assert!(observe_polynomial(&source, &input, &source_keys, &message) <= input_v);

    let components = [ordinary(&source, &input.c0), ordinary(&source, &input.c1)];
    let residual0: Vec<_> = (0..n)
        .map(|j| centered_component_residual(&source, &components[0], j, source_q))
        .collect();
    let residual1: Vec<_> = (0..n)
        .map(|j| centered_component_residual(&source, &components[1], j, source_q))
        .collect();
    let phase1: Vec<_> = (0..n)
        .map(|j| phase1_tropical_carry(&residual0, &residual1, &trits, source_q, j))
        .collect();
    assert!(phase1.iter().all(|(k, _)| k.abs() <= (weight / 2) as i128));

    let encrypted_source = encrypt_polynomial(
        &outer,
        &outer_keys,
        &embedded(
            &trits
                .iter()
                .map(|&s| (s as i64).rem_euclid(PHASE_P as i64) as u64)
                .collect::<Vec<_>>(),
        ),
        &mut rng,
    );
    let q_outer = U512::product_u64s(&outer.config.primes);
    let precharge_v = PHASE_P as u128 * (2 * outer.n + 1) as u128 * outer.config.eta as u128
        + (q_outer.mod_u64(PHASE_P) as u128) * (PHASE_P - 1) as u128;
    let producer = BatchedPhase {
        source: &source,
        outer: &outer,
        clock_n: outer.n,
        encrypted_source,
        precharge_v,
        source_norm: weight,
        coordinate: 99,
        phase_cap: source_q / phase_denominator,
    };
    let chart = producer.apply(&input, input_v);
    let c0 = preprocess_for_clock(&source, &input.c0, 99, outer.n);
    let c1 = preprocess_for_clock(&source, &input.c1, 99, outer.n);

    let base_tray = 2 * outer.n as u64;
    assert_eq!(65_536 % base_tray, 0);
    let chart_scale = 65_536 / base_tray;
    let tray_period = base_tray * chart_scale;
    assert_eq!(tray_period, 65_536);
    let tray_inverse = inverse(tray_period % PHASE_P, PHASE_P) as i64;
    let tray_inverse = if tray_inverse > (PHASE_P / 2) as i64 {
        tray_inverse - PHASE_P as i64
    } else {
        tray_inverse
    };
    assert_eq!(tray_inverse, -1);

    let mut z = vec![0i128; outer.n];
    let mut expected_carry = vec![0; outer.n];
    let mut expected_return = vec![0; outer.n];
    let mut affine_constant = vec![0i64; outer.n];
    let mut affine_weights = vec![0i64; outer.n];
    let mut expected_affine = vec![0; outer.n];
    for j in 0..n {
        let mut value = c0.clock[j] as i128;
        for (i, &s) in trits.iter().enumerate() {
            let k = (j + n - i) % n;
            let sign = if i > j { -1i128 } else { 1i128 };
            value += sign * c1.clock[k] as i128 * s as i128;
        }
        z[2 * j] = value;
        let carry = (99 * value + outer.n as i128).div_euclid((2 * outer.n) as i128);
        assert_eq!(carry, phase1[j].0, "K99=K_phase at coefficient {j}");
        expected_carry[2 * j] = carry.rem_euclid(PHASE_P as i128) as u64;
        expected_return[2 * j] = message[j];
        let a0 = if c0.a[j] > PHASE_P / 2 {
            c0.a[j] as i64 - PHASE_P as i64
        } else {
            c0.a[j] as i64
        };
        let a1 = if c1.a[j] > PHASE_P / 2 {
            c1.a[j] as i64 - PHASE_P as i64
        } else {
            c1.a[j] as i64
        };
        affine_constant[2 * j] = a0;
        affine_weights[2 * j] = a1;
        let affine = a0 as i128
            + trits
                .iter()
                .enumerate()
                .map(|(i, &s)| {
                    let k = (j + n - i) % n;
                    let sign = if i > j { -1i128 } else { 1i128 };
                    let a = if c1.a[k] > PHASE_P / 2 {
                        c1.a[k] as i128 - PHASE_P as i128
                    } else {
                        c1.a[k] as i128
                    };
                    sign * a * s as i128
                })
                .sum::<i128>();
        expected_affine[2 * j] = affine.rem_euclid(PHASE_P as i128) as u64;
        assert_eq!(
            (affine + carry).rem_euclid(PHASE_P as i128) as u64,
            message[j],
            "affine plus tropical carry at coefficient {j}"
        );
    }

    let z_expected: Vec<_> = z
        .iter()
        .map(|&v| v.rem_euclid(PHASE_P as i128) as u64)
        .collect();
    let z_observed = observe_polynomial(&outer, &chart.ciphertext, &outer_keys, &z_expected);
    assert!(z_observed <= chart.bound);
    let x_integer: Vec<_> = z.iter().map(|&v| 99 * chart_scale as i128 * v).collect();
    let x_expected: Vec<_> = x_integer
        .iter()
        .map(|&x| x.rem_euclid(PHASE_P as i128) as u64)
        .collect();
    let x = signed_scale(&outer, &chart.ciphertext, (99 * chart_scale) as i64);
    let x_bound = chart.bound * 99 * chart_scale as u128;
    assert!(words(U512::from_u128(x_bound).mul_u128(2)) < words(q_outer));
    let x_observed = observe_polynomial(&outer, &x, &outer_keys, &x_expected);
    assert!(x_observed <= x_bound);

    // Same-history low-tray producer. Its plaintext is x mod 2^16; because
    // x=2^16*K+e with |e|<2^15, decoding that same RNS ciphertext at p=2^16+1
    // returns the signed residual e. The carry then follows from e-x=K mod p.
    let tray_period = 1u64 << 16;
    let sister_config = nine65::params::FHEConfig {
        t: tray_period,
        ..outer.config.clone()
    };
    let sister = RNSFHEContext::try_new(&sister_config).unwrap();
    let sister_source = encrypt_polynomial(
        &sister,
        &outer_keys,
        &embedded(
            &trits
                .iter()
                .map(|&s| (s as i64).rem_euclid(tray_period as i64) as u64)
                .collect::<Vec<_>>(),
        ),
        &mut rng,
    );
    let sister_precharge_v =
        tray_period as u128 * (2 * sister.n + 1) as u128 * sister.config.eta as u128
            + (q_outer.mod_u64(tray_period) as u128) * (tray_period - 1) as u128;
    let sister_producer = BatchedPhase {
        source: &source,
        outer: &sister,
        clock_n: sister.n,
        encrypted_source: sister_source,
        precharge_v: sister_precharge_v,
        source_norm: weight,
        coordinate: 99,
        phase_cap: source_q / phase_denominator,
    };
    let sister_chart = sister_producer.apply(&input, input_v);
    let sister_x = signed_scale(&sister, &sister_chart.ciphertext, (99 * chart_scale) as i64);
    let sister_x_bound = sister_chart.bound * 99 * chart_scale as u128;
    let mut residual_mod_tray = vec![0; outer.n];
    let mut residual_mod_p = vec![0; outer.n];
    let mut max_residual = 0u128;
    for j in 0..n {
        let e = x_integer[2 * j] - tray_period as i128 * phase1[j].0;
        assert!(e.unsigned_abs() < (tray_period / 2) as u128);
        max_residual = max_residual.max(e.unsigned_abs());
        residual_mod_tray[2 * j] = e.rem_euclid(tray_period as i128) as u64;
        residual_mod_p[2 * j] = e.rem_euclid(PHASE_P as i128) as u64;
    }
    let sister_x_observed = observe_polynomial(&sister, &sister_x, &outer_keys, &residual_mod_tray);
    assert!(sister_x_observed <= sister_x_bound);
    let phase_locked_observed = observe_polynomial(&outer, &sister_x, &outer_keys, &residual_mod_p);
    let phase_lock_bound = q_outer
        .mul_u128(max_residual)
        .add(U512::from_u128(sister_x_observed).mul_u128(PHASE_P as u128))
        .div_u64(tray_period);
    assert_eq!(
        (
            phase_lock_bound.d3,
            phase_lock_bound.d2,
            phase_lock_bound.d1
        ),
        (0, 0, 0)
    );
    assert!(phase_locked_observed <= phase_lock_bound.d0);
    let public_carry = add(&outer, &sister_x, &signed_scale(&outer, &x, -1));
    assert_eq!(
        decrypt_coefficients(&outer, &public_carry, &outer_keys),
        expected_carry,
        "same-history sister tray must recover K without an oracle tray"
    );
    let public_carry_observed =
        observe_polynomial(&outer, &public_carry, &outer_keys, &expected_carry);
    assert!(public_carry_observed <= phase_lock_bound.d0 + x_observed);

    // Oracle p-tray remains a reference consumer ablation.
    // Its root relation is x+2^15 = 2^16*K+r, with |r-2^15|<2^15.
    let half_tray = (tray_period / 2) as i128;
    let tray_plain: Vec<_> = x_integer
        .iter()
        .map(|&x| (x + half_tray).rem_euclid(tray_period as i128) as u64)
        .collect();
    let tray = encrypt_polynomial(&outer, &outer_keys, &tray_plain, &mut rng);
    let tray_observed = observe_polynomial(&outer, &tray, &outer_keys, &tray_plain);
    assert!(tray_observed <= precharge_v);
    let high_x = add(
        &outer,
        &x,
        &public_plain(&outer, &vec![half_tray as i64; outer.n]),
    );
    let carry = signed_scale(
        &outer,
        &add(&outer, &high_x, &signed_scale(&outer, &tray, -1)),
        tray_inverse,
    );
    assert_eq!(
        decrypt_coefficients(&outer, &carry, &outer_keys),
        expected_carry
    );
    let carry_bound = x_bound + precharge_v;
    let carry_observed = observe_polynomial(&outer, &carry, &outer_keys, &expected_carry);
    assert!(carry_observed <= carry_bound);

    let affine = add(
        &outer,
        &multiply_signed_plain(&outer, &producer.encrypted_source, &affine_weights),
        &public_plain(&outer, &affine_constant),
    );
    let affine_l1 = affine_weights
        .iter()
        .map(|v| v.unsigned_abs() as u128)
        .sum::<u128>();
    let affine_b0_max = affine_constant
        .iter()
        .map(|v| v.unsigned_abs() as u128)
        .max()
        .unwrap();
    let affine_bound = precharge_v * affine_l1 + (q_outer.mod_u64(PHASE_P) as u128) * affine_b0_max;
    let affine_observed = observe_polynomial(&outer, &affine, &outer_keys, &expected_affine);
    assert!(affine_observed <= affine_bound);

    // (affine+x)-(x-K)=affine+K: x cancels as the identical ciphertext.
    let corrected = add(&outer, &affine, &x);
    let residual = add(&outer, &x, &signed_scale(&outer, &carry, -1));
    let returned = add(&outer, &corrected, &signed_scale(&outer, &residual, -1));
    assert_eq!(
        decrypt_coefficients(&outer, &returned, &outer_keys),
        expected_return
    );
    let return_bound = affine_bound + carry_bound;
    assert!(words(U512::from_u128(return_bound).mul_u128(2)) < words(q_outer));
    let return_observed = observe_polynomial(&outer, &returned, &outer_keys, &expected_return);
    assert!(return_observed <= return_bound);

    let public_return = add(&outer, &affine, &public_carry);
    assert_eq!(
        decrypt_coefficients(&outer, &public_return, &outer_keys),
        expected_return
    );
    let public_return_observed =
        observe_polynomial(&outer, &public_return, &outer_keys, &expected_return);
    assert!(public_return_observed <= phase_lock_bound.d0 + x_observed + affine_observed);

    let exact = outer.try_exact_evaluator().unwrap();
    let relin = exact.generate_hybrid_gadget_key_with_rng(&outer_keys.secret_key, &mut rng);
    let square = exact.try_mul_exact(&returned, &returned, &relin).unwrap();
    let square_source = multiply_plain_ring(&message, &message, PHASE_P);
    let mut square_expected = vec![0; outer.n];
    for (j, &value) in square_source.iter().enumerate() {
        square_expected[2 * j] = value;
    }
    assert_eq!(
        decrypt_coefficients(&outer, &square, &outer_keys),
        square_expected,
        "the K-Elimination return must support a native-ring square"
    );
    let cube = exact.try_mul_exact(&square, &returned, &relin).unwrap();
    let cube_source = multiply_plain_ring(&square_source, &message, PHASE_P);
    let mut cube_expected = vec![0; outer.n];
    for (j, &value) in cube_source.iter().enumerate() {
        cube_expected[2 * j] = value;
    }
    let cube_matches = decrypt_coefficients(&outer, &cube, &outer_keys) == cube_expected;
    assert!(
        cube_matches,
        "the K-Elimination return must support the next product at this fixture"
    );
    let public_square = exact
        .try_mul_exact(&public_return, &public_return, &relin)
        .unwrap();
    let public_square_matches =
        decrypt_coefficients(&outer, &public_square, &outer_keys) == square_expected;
    let public_cube = exact
        .try_mul_exact(&public_square, &public_return, &relin)
        .unwrap();
    let public_cube_matches =
        decrypt_coefficients(&outer, &public_cube, &outer_keys) == cube_expected;
    eprintln!("power-tray K-Elimination: sourceN{n}/outerN{}, L={chart_scale}, tray=2^16=p-1, inverse={tray_inverse}, K range={:?}, p-chart/carry/affine/oracle-return V bits={}/{}/{}/{}, low-tray t/p/carry/return V bits={}/{}/{}/{}, oracle square/cube exact={}/{}, same-history square/cube exact={}/{}, residual max={}",outer.n,phase1.iter().map(|(k,_)| *k).min().zip(phase1.iter().map(|(k,_)| *k).max()).unwrap(),bits(z_observed),bits(carry_observed),bits(affine_observed),bits(return_observed),bits(sister_x_observed),bits(phase_locked_observed),bits(public_carry_observed),bits(public_return_observed),cube_matches, decrypt_coefficients(&outer, &cube, &outer_keys) == cube_expected, public_square_matches, public_cube_matches, max_residual);
}

#[test]
fn power_of_two_sister_tray_k_elimination_contracts_the_small_return() {
    check_power_tray_return(512, 2, 128);
}

#[test]
#[ignore = "opt-in native N8192 power-of-two sister-tray return and product follow-up"]
fn power_of_two_sister_tray_k_elimination_contracts_the_native_return() {
    check_power_tray_return(8192, 96, 16);
}
