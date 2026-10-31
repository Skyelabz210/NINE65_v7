use super::*;
use crate::entropy::ShadowHarvester;
use crate::params::SecureConfig;

#[test]
fn direct_phase_quotient_bound_covers_signed_lifts_and_native_endpoints() {
    for p in [3, 17, 257] {
        for weight in [2, 4, 16, 96] {
            let value_bound = direct_phase_value_bound(p, weight);
            for residual_radius in [0, 1, p / 2] {
                let bound = direct_phase_quotient_radius(p, weight, residual_radius);
                let mut maximum = 0;
                for x in -(value_bound as i64)..=value_bound as i64 {
                    let residue = x.rem_euclid(p as i64);
                    let rho = if residue <= p as i64 / 2 {
                        residue
                    } else {
                        residue - p as i64
                    };
                    if rho.unsigned_abs() <= residual_radius {
                        let quotient = (x - rho) / p as i64;
                        assert!(quotient.unsigned_abs() <= bound);
                        maximum = maximum.max(quotient.unsigned_abs());
                    }
                }
                assert_eq!(maximum, bound);
            }
        }
    }
    let p = 65537;
    let phase_bound = direct_phase_value_bound(p, 96);
    assert_eq!(phase_bound, 3_178_496);
    assert_eq!(direct_phase_quotient_radius(p, 96, 49), 48);
    // Ninety-six maximal signed terms plus d0=48 attain K=48, rho=0.
    assert_eq!(96 * (p / 2) + 48, 48 * p);
    assert!(49 * p - 49 > phase_bound);
}

fn config(n: usize) -> FHEConfig {
    let mut config = SecureConfig::secure_128().into_config();
    config.n = n;
    config.security_bits = 0;
    config.name = "INSECURE source-preparation correctness fixture";
    config
}

fn setup(
    n: usize,
    source_n: usize,
    weight: usize,
    bits: u32,
    seed: u64,
) -> (
    PublicRefreshSourceClient,
    PublicRefreshSourceEvaluator,
    ShadowHarvester,
) {
    let plan = PublicRefreshSourcePlan::new(&config(n), source_n, 2, weight, bits).unwrap();
    let mut rng = ShadowHarvester::with_seed(seed);
    let (client, evaluator) = plan.generate_with_rng(&mut rng, 128 << 20).unwrap();
    (client, evaluator, rng)
}

fn embedded(values: &[u64], n: usize) -> Vec<u64> {
    let mut out = vec![0; n];
    for (j, &value) in values.iter().enumerate() {
        out[j * (n / values.len())] = value;
    }
    out
}

fn square_oracle(values: &[u64], t: u64) -> Vec<u64> {
    let mut result = vec![0i128; values.len()];
    for (i, &a) in values.iter().enumerate() {
        for (j, &b) in values.iter().enumerate() {
            let sign = if i + j >= values.len() { -1 } else { 1 };
            result[(i + j) % values.len()] += sign * a as i128 * b as i128;
        }
    }
    result
        .into_iter()
        .map(|v| v.rem_euclid(t as i128) as u64)
        .collect()
}

// Independent client observation. Reconstructing Q60 values is confined to
// this oracle; production conversion uses residue-only drops and switching.
fn observe_source(
    client: &PublicRefreshSourceClient,
    input: &PreparedRefreshSource,
    expected: &[u64],
) {
    let ctx = client.source_context();
    assert_eq!(client.decrypt_source(input).unwrap(), expected);
    let a = ordinary(ctx, &input.raw.c0);
    let b = ordinary(ctx, &input.raw.c1);
    let s = ordinary(ctx, &client.source_secret.s);
    let lanes: Vec<_> = ctx
        .config
        .primes
        .iter()
        .enumerate()
        .map(|(i, &q)| {
            ctx.ntt_engines[i]
                .multiply(&b.limbs[i], &s.limbs[i])
                .iter()
                .zip(&a.limbs[i])
                .map(|(&x, &y)| ((x as u128 + y as u128) % q as u128) as u64)
                .collect::<Vec<_>>()
        })
        .collect();
    let q: u128 = ctx.config.primes.iter().map(|&q| q as u128).product();
    let mut max_error = 0;
    for (j, &value) in expected.iter().enumerate() {
        let phase = ctx
            .rns
            .to_int(&lanes.iter().map(|lane| lane[j]).collect::<Vec<_>>());
        let error = (phase * ctx.t as u128).abs_diff(q * value as u128);
        max_error = max_error.max(error.min(q * ctx.t as u128 - error));
    }
    assert!(words(U512::from_u128(max_error)) <= words(input.certificate.source_bound));
}

#[test]
fn source_preparation_tracks_full_polynomial_history_and_ring_embedding() {
    let (client, evaluator, mut rng) = setup(8, 32, 4, 2, 0x534f_5552_4345);
    let t = evaluator.plan().work.t;
    let message = vec![1, 0, t - 1, 2, 7, t / 2, t - 2, 3];
    let first = evaluator.encrypt_with_rng(&message, &mut rng).unwrap();
    let second = evaluator.add(&first, &first).unwrap();
    let product = evaluator.multiply(&first, &first).unwrap();
    let doubled: Vec<_> = message.iter().map(|&v| 2 * v % t).collect();
    let squared = square_oracle(&message, t);
    for (input, expected) in [
        (&first, &message),
        (&second, &doubled),
        (&product, &squared),
    ] {
        assert_eq!(client.decrypt_work(input).unwrap(), *expected);
        let prepared = evaluator.prepare(input).unwrap();
        observe_source(&client, &prepared, &embedded(expected, 32));
        assert_eq!(prepared.certificate.input_lineage(), input.lineage());
        assert!(std::ptr::eq(prepared.certificate().root(), input.root()));
        assert_eq!(prepared.certificate.input_bound(), input.bound);
        assert_eq!(prepared.certificate.embedding_stride(), 4);
        assert_eq!(prepared.certificate.modulus_drop_bounds().len(), 2);
        assert_eq!(prepared.certificate.source_weight(), 4);
    }
    assert_ne!(first.lineage, second.lineage);
    assert_ne!(second.lineage, product.lineage);
    assert!(words(product.bound) > words(first.bound));
}

#[test]
fn source_preparation_rejects_wrong_families_and_invalid_parameters() {
    let (client, eval, mut rng) = setup(8, 32, 4, 2, 0x1111);
    let (_, other, _) = setup(8, 32, 4, 2, 0x2222);
    let input = eval.encrypt_with_rng(&[3; 8], &mut rng).unwrap();
    assert!(matches!(
        other.prepare(&input),
        Err(SourceError::DomainMismatch)
    ));
    assert!(matches!(
        other.add(&input, &input),
        Err(SourceError::DomainMismatch)
    ));
    assert!(matches!(
        other.multiply(&input, &input),
        Err(SourceError::DomainMismatch)
    ));
    assert!(matches!(
        eval.encrypt_with_rng(&[0; 7], &mut rng),
        Err(SourceError::PlaintextRange)
    ));
    assert!(matches!(
        eval.encrypt_with_rng(&[65537; 8], &mut rng),
        Err(SourceError::PlaintextRange)
    ));
    for (n, lanes, weight, bits) in [
        (4, 2, 2, 2),
        (24, 2, 4, 2),
        (32, 5, 4, 2),
        (32, 2, 3, 2),
        (32, 2, 34, 2),
        (32, 2, 4, 0),
    ] {
        assert!(PublicRefreshSourcePlan::new(&config(8), n, lanes, weight, bits).is_err());
    }
    let plan = eval.plan();
    assert!(matches!(
        plan.generate_with_rng(&mut rng, plan.switch_key_bytes() - 1),
        Err(SourceError::ResourceLimit)
    ));
    assert_eq!(client.decrypt_work(&input).unwrap(), vec![3; 8]);
}

#[test]
fn source_preparation_refuses_exhausted_switch_margin_without_resetting_input() {
    let (_, evaluator, mut rng) = setup(8, 32, 4, 2, 0x3333);
    let initial = evaluator.encrypt_with_rng(&[0; 8], &mut rng).unwrap();
    let q: u128 = evaluator
        .plan()
        .work
        .primes
        .iter()
        .map(|&q| q as u128)
        .product();
    let multiplier = (q / 2 - 1) / initial.bound.d0;
    let mut current = initial.clone();
    let top = 127 - multiplier.leading_zeros();
    for bit in (0..top).rev() {
        current = evaluator.add(&current, &current).unwrap();
        if multiplier & (1u128 << bit) != 0 {
            current = evaluator.add(&current, &initial).unwrap();
        }
    }
    let before = current.clone();
    assert!(matches!(
        evaluator.prepare(&current),
        Err(SourceError::NoiseExhausted)
    ));
    assert_eq!(current.bound, before.bound);
    assert_eq!(current.lineage, before.lineage);
    assert_eq!(current.raw.c0.limbs, before.raw.c0.limbs);
    assert_eq!(current.raw.c1.limbs, before.raw.c1.limbs);
}

fn native_case(source_n: usize, weight: usize, base_bits: u32) {
    let (client, evaluator, mut rng) = setup(8192, source_n, weight, base_bits, 0x4e41_5449_5645);
    let t = evaluator.plan().work.t;
    let message: Vec<_> = (0..8192)
        .map(|j| if j % 2 == 0 { 1 } else { t - 1 })
        .collect();
    let encrypted = evaluator.encrypt_with_rng(&message, &mut rng).unwrap();
    let square = evaluator.multiply(&encrypted, &encrypted).unwrap();
    // Independent closed-form negacyclic square of sum_j (-X)^j.
    let expected: Vec<_> = (0..8192)
        .map(|j| {
            let value = 2 * j as i64 + 2 - 8192;
            (if j % 2 == 0 { value } else { -value }).rem_euclid(t as i64) as u64
        })
        .collect();
    assert_eq!(client.decrypt_work(&square).unwrap(), expected);
    let prepared = evaluator.prepare(&square).unwrap();
    let expected = embedded(&expected, source_n);
    observe_source(&client, &prepared, &expected);
    let source = client.source_context();
    let secret = ordinary(source, &client.source_secret.s);
    assert_eq!(
        secret.limbs[0].iter().filter(|&&v| v == 1).count(),
        weight / 2
    );
    assert_eq!(
        secret.limbs[0]
            .iter()
            .filter(|&&v| v == source.config.primes[0] - 1)
            .count(),
        weight / 2
    );
    // Independently check the actual p² expanded-phase radius at every
    // coefficient, including newly inserted zeros, against its certificate.
    let q: u128 = source.config.primes.iter().map(|&q| q as u128).product();
    let p2 = t as u128 * t as u128;
    let expand = |poly: &RNSPolynomial| {
        let poly = ordinary(source, poly);
        (0..source_n)
            .map(|j| {
                let x = source
                    .rns
                    .to_int(&poly.limbs.iter().map(|lane| lane[j]).collect::<Vec<_>>());
                ((p2 * x + q / 2) / q) as i128
            })
            .collect::<Vec<_>>()
    };
    let a0 = expand(&prepared.raw.c0);
    let a1 = expand(&prepared.raw.c1);
    let support: Vec<_> = secret.limbs[0]
        .iter()
        .enumerate()
        .filter(|(_, s)| **s != 0)
        .map(|(j, &s)| (j, if s == 1 { 1i128 } else { -1 }))
        .collect();
    let radius = prepared.certificate.prime_square_residual_radius();
    for (j, &message) in expected.iter().enumerate() {
        let mut phase = a0[j];
        for &(i, sign) in &support {
            phase += sign
                * if i > j {
                    -a1[(j + source_n - i) % source_n]
                } else {
                    a1[j - i]
                };
        }
        let rho = (phase - t as i128 * message as i128).rem_euclid(p2 as i128);
        let rho = if rho > p2 as i128 / 2 {
            rho - p2 as i128
        } else {
            rho
        };
        assert!(
            rho.unsigned_abs() <= radius as u128,
            "coefficient {j}: rho={rho}, radius={radius}"
        );
    }
    eprintln!("public source preparation: denseN8192 -> sparseN{source_n}/H{weight}, base_bits={base_bits}, all {source_n} coefficients and actual expanded radii checked; certified radius={radius}; security/refresh admission remains false");
}

#[test]
fn source_preparation_native_same_ring_h96_checks_all_coefficients() {
    native_case(8192, 96, 3);
}

#[test]
fn source_preparation_native_embedded_h32_checks_all_coefficients_and_zeros() {
    native_case(32768, 32, 2);
}
