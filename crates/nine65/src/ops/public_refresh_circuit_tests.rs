//! Public API conformance. Only the independent client object decrypts.
use super::*;
use crate::entropy::ShadowHarvester;
use crate::ops::public_refresh_source::SourceError;

const P: u64 = 65_537;
const WORK: [u64; 4] = [998244353, 985661441, 754974721, 469762049];
const BOOT: [u64; 13] = [
    998244353,
    985661441,
    754974721,
    469762049,
    576460752301785089,
    576460752301391873,
    576460752300015617,
    576460752298835969,
    576460752298180609,
    576460752293134337,
    576460752291954689,
    576460752290775041,
    575870995836829697,
];
fn config(n: usize, primes: &[u64], t: u64) -> FHEConfig {
    FHEConfig {
        n,
        primes: primes.to_vec(),
        q: primes[0],
        t,
        eta: 3,
        security_bits: 0,
        name: "INSECURE public refresh API conformance fixture",
    }
}
fn source_plan() -> PublicRefreshSourcePlan {
    PublicRefreshSourcePlan::new(&config(8, &WORK, P), 8, 2, 4, 3).unwrap()
}
fn plan() -> PublicRefreshCircuitPlan {
    PublicRefreshCircuitPlan::new(source_plan(), config(32, &BOOT, P * P), 4, 3, 16 << 20).unwrap()
}

#[test]
fn fused_adjacent_restore_covers_every_native_lift_and_rejects_aliases() {
    let cert =
        AdjacentLiftRestorationCertificate::new(P, 48, U1024::from_u64(7), U1024::from_u64(11))
            .unwrap();
    assert_eq!(cert.output_error_bound, U1024::from_u64(18));
    let ctx = RNSFHEContext::try_new(&config(8, &WORK[..2], P)).unwrap();
    let mut rng = ShadowHarvester::with_seed(0x4655_5345_444c_4946);
    let keys = ctx.generate_keys(&mut rng);
    for k in -48i64..=48 {
        let y = (k + 48) as u64;
        let g = y % 36;
        let a = y % 37;
        let sheet = (g + 37 - a) % 37;
        assert_eq!(g + 36 * sheet, y);
        let carry = ctx.encrypt_with_rng(k.rem_euclid(P as i64) as u64, &keys.public_key, &mut rng);
        for m in [0, 1, P / 2, P - 1] {
            let affine_value = (m as i64 - k).rem_euclid(P as i64) as u64;
            let affine = ctx.encrypt_with_rng(affine_value, &keys.public_key, &mut rng);
            let output = cert.apply(&ctx, &affine, &carry);
            assert_eq!(ctx.decrypt(&output, &keys.secret_key), m);
        }
    }
    // The optimizer must prove the declared StarLift interval before using
    // that identity, even though native field addition would still execute.
    assert!(AdjacentLiftRestorationCertificate::new(P, 666, U1024::ZERO, U1024::ZERO).is_err());
    assert!(AdjacentLiftRestorationCertificate::new(97, 49, U1024::ZERO, U1024::ZERO).is_err());
    assert!(
        AdjacentLiftRestorationCertificate::new(P, u64::MAX, U1024::ZERO, U1024::ZERO).is_err()
    );
}

#[test]
fn fused_native_lift_query_funds_slot_return_and_next_refresh() {
    let native = PublicRefreshCircuitPlan::native_research(4 << 30).unwrap();
    let cert = native.certificate();
    assert_eq!(cert.lift_restoration.shift, 48);
    assert_eq!(cert.lift_restoration.shifted_upper_bound, 96);
    assert_eq!(cert.lift_restoration.capacity, 1332);
    assert_eq!(cert.lift_restoration.additional_ciphertext_products, 0);
    let half = U1024::checked_product_u64s(&BOOT)
        .unwrap()
        .div_mod_u64(P)
        .unwrap()
        .0
        .shr1();
    assert!(cert.lift_restoration.output_error_bound < half);
    assert!(cert.restored_error_bound < half);
    assert!(cert.next_square_source_radius <= 49);
    eprintln!(
        "fused lift: {} bits; after slot return: {} bits; half-Delta: {}; next-square radius: {}",
        cert.lift_restoration.output_error_bound.bit_length(),
        cert.restored_error_bound.bit_length(),
        half.bit_length(),
        cert.next_square_source_radius
    );
}

#[test]
fn native_plan_certifies_signed_carry_separately_from_residual_support() {
    let native = PublicRefreshCircuitPlan::native_research(4 << 30).unwrap();
    assert_eq!(native.certificate().carry_radius, 49);
    assert_eq!(native.certificate().phase_value_bound, 3_178_496);
    assert_eq!(native.certificate().signed_carry_radius, 48);
    // Each direct Y mod {11,36,37} lookup on 0..96 has interpolation degree
    // 96 (independent Python proof oracle). Its >=7 product levels cannot be
    // appended to K under the current Noise::multiply ledger and native Q.
    let n = native.certificate().ring_degree as u128;
    let factor = n * ((P - 1) / 2) as u128 + n * P as u128 * (n / 2 + 1);
    let mut lookup_error_floor = native.certificate().carry_error_bound;
    for _ in 0..7 {
        lookup_error_floor = lookup_error_floor.checked_mul_u128(factor).unwrap();
    }
    let half_delta = U1024::checked_product_u64s(&BOOT)
        .unwrap()
        .div_mod_u64(P)
        .unwrap()
        .0
        .shr1();
    assert!(lookup_error_floor >= half_delta);
    eprintln!(
        "signed carry radius=48; direct lookup error floor={} bits; half-Delta={} bits",
        lookup_error_floor.bit_length(),
        half_delta.bit_length()
    );
    let reduced = plan();
    assert_eq!(reduced.certificate().carry_radius, 3);
    assert_eq!(reduced.certificate().signed_carry_radius, 2);
}
fn setup(
    seed: u64,
) -> (
    PublicRefreshSourceClient,
    PublicRefreshCircuit,
    ShadowHarvester,
) {
    let mut rng = ShadowHarvester::with_seed(seed);
    let (client, evaluator) = plan().generate_with_rng(&mut rng).unwrap();
    (client, evaluator, rng)
}

#[test]
fn public_refresh_preserves_plaintext_root_across_representation_changes_and_forks() {
    let (client, mut evaluator, mut rng) = setup(0x524f_4f54_4341_4e4f);
    let a = evaluator.encrypt_with_rng(&[7; 8], &mut rng).unwrap();
    let b = evaluator.encrypt_with_rng(&[7; 8], &mut rng).unwrap();
    assert_ne!(a.root().identity(), b.root().identity());
    let sum = evaluator.add(&a, &b).unwrap();
    assert_ne!(sum.root().identity(), a.root().identity());
    let identity = *sum.root().identity();
    let before = *sum.lineage();
    let next = evaluator.refresh(&sum).unwrap();
    assert_eq!(next.root().identity(), &identity);
    assert!(std::ptr::eq(next.root(), sum.root()));
    assert_ne!(next.lineage(), &before);
    assert_eq!(client.decrypt_work(&next).unwrap(), vec![14; 8]);
    let fork = evaluator.refresh(&sum).unwrap();
    assert!(std::ptr::eq(fork.root(), sum.root()));
    let successor = evaluator.refresh(&next).unwrap();
    assert_eq!(successor.root().identity(), &identity);
    assert_eq!(client.decrypt_work(&successor).unwrap(), vec![14; 8]);
    let product = evaluator.multiply(&successor, &fork).unwrap();
    assert_ne!(product.root().identity(), &identity);
    assert_eq!(product.root().plaintext_modulus(), P);
    assert_eq!(
        product.root().logical_moduli(),
        &[2, 3, 5, 7, 11, 13, 17, 19]
    );
    assert_eq!(product.root().coefficient_upper_bound(), P - 1);
    assert_eq!(evaluator.real_refreshes(), 3);
}
// Plaintext oracle uses independent schoolbook negacyclic arithmetic.
fn multiply(a: &[u64], b: &[u64]) -> Vec<u64> {
    assert_eq!(a.len(), b.len());
    let mut values = vec![0i128; a.len()];
    for (i, &x) in a.iter().enumerate() {
        for (j, &y) in b.iter().enumerate() {
            let term = x as i128 * y as i128;
            if i + j < a.len() {
                values[i + j] += term;
            } else {
                values[i + j - a.len()] -= term;
            }
        }
    }
    values
        .into_iter()
        .map(|v| v.rem_euclid(P as i128) as u64)
        .collect()
}
#[track_caller]
fn assert_bootstrap_refusal<T>(result: Nine65Result<T>) {
    match result {
        Err(Nine65Error::BootstrapFailed { .. }) => {}
        Err(error) => panic!("expected BootstrapFailed, received {error:?}"),
        Ok(_) => panic!("expected BootstrapFailed, operation unexpectedly succeeded"),
    }
}
fn check_refreshed_square(
    client: &PublicRefreshSourceClient,
    evaluator: &mut PublicRefreshCircuit,
    input: &SourceWorkCiphertext,
    expected: &[u64],
) {
    let before = evaluator.real_refreshes();
    let returned = evaluator.refresh(input).unwrap();
    assert_eq!(evaluator.real_refreshes(), before + 1);
    assert_eq!(client.decrypt_work(&returned).unwrap(), expected);
    assert_eq!(
        returned.scaled_error_bound(),
        evaluator.certificate().returned_scaled_error_bound
    );
    assert_ne!(returned.lineage(), input.lineage());
    let squared = evaluator.multiply(&returned, &returned).unwrap();
    assert_eq!(
        client.decrypt_work(&squared).unwrap(),
        multiply(expected, expected)
    );
    // Refresh preserves the original immutable input and its client identity.
    assert_eq!(client.decrypt_work(input).unwrap(), expected);
}

#[test]
fn public_refresh_conforms_on_full_polynomials_histories_and_forks_across_seeds() {
    for seed in [0x434f_4e46_0001, 0x434f_4e46_0002, 0x434f_4e46_0003] {
        let (client, mut evaluator, mut rng) = setup(seed);
        let random: Vec<_> = (0..8).map(|_| rng.uniform(P)).collect();
        let messages = vec![
            vec![0; 8],
            vec![1; 8],
            vec![P - 1; 8],
            vec![0, 1, P - 1, P / 2, P / 2 + 1, P / 2 - 1, P / 2 + 2, 2],
            vec![0, 0, P - 1, 0, 0, 0, 17, 0],
            vec![1, 7, 31, 127, 511, 2047, 8191, 32767],
            random.clone(),
        ];
        for (index, message) in messages.iter().enumerate() {
            let fresh = evaluator.encrypt_with_rng(message, &mut rng).unwrap();
            let (input, expected) = match index % 3 {
                0 => (fresh, message.clone()),
                1 => {
                    let doubled = evaluator.add(&fresh, &fresh).unwrap();
                    (doubled, message.iter().map(|v| 2 * v % P).collect())
                }
                _ => {
                    let squared = evaluator.multiply(&fresh, &fresh).unwrap();
                    let fourth = evaluator.multiply(&squared, &squared).unwrap();
                    let squared_plain = multiply(message, message);
                    (fourth, multiply(&squared_plain, &squared_plain))
                }
            };
            check_refreshed_square(&client, &mut evaluator, &input, &expected);
        }
        let original = evaluator.encrypt_with_rng(&random, &mut rng).unwrap();
        let first = original.clone();
        let second = original.clone();
        assert_eq!(first.lineage(), second.lineage());
        let multiplied = evaluator.multiply(&first, &second).unwrap();
        let added = evaluator.add(&first, &second).unwrap();
        assert_ne!(multiplied.lineage(), added.lineage());
        check_refreshed_square(
            &client,
            &mut evaluator,
            &multiplied,
            &multiply(&random, &random),
        );
        check_refreshed_square(
            &client,
            &mut evaluator,
            &added,
            &random.iter().map(|v| 2 * v % P).collect::<Vec<_>>(),
        );
        assert_eq!(client.decrypt_work(&original).unwrap(), random);
        assert_eq!(evaluator.real_refreshes(), 9);
    }
}

#[test]
fn public_refresh_refuses_wrong_families_and_exhausted_history_without_counting() {
    let (client, mut evaluator, mut rng) = setup(0x444f_4d41_494e_0001);
    let (other_client, other, mut other_rng) = setup(0x444f_4d41_494e_0002);
    let message = [0, 1, P - 1, P / 2, P / 2 + 1, 17, 0, 7];
    let own = evaluator.encrypt_with_rng(&message, &mut rng).unwrap();
    let foreign = other.encrypt_with_rng(&message, &mut other_rng).unwrap();
    assert_bootstrap_refusal(evaluator.add(&own, &foreign));
    assert_bootstrap_refusal(evaluator.multiply(&own, &foreign));
    assert_bootstrap_refusal(evaluator.refresh(&foreign));
    assert_eq!(evaluator.real_refreshes(), 0);
    assert!(matches!(
        client.decrypt_work(&foreign),
        Err(SourceError::DomainMismatch)
    ));
    assert!(matches!(
        other_client.decrypt_work(&own),
        Err(SourceError::DomainMismatch)
    ));
    assert_bootstrap_refusal(evaluator.encrypt_with_rng(&[0; 7], &mut rng));
    assert_bootstrap_refusal(evaluator.encrypt_with_rng(&[P; 8], &mut rng));

    // Refusing another multiplication does not imply this ciphertext cannot
    // be refreshed: the operation has its own prospective growth bound.
    let mut exhausted = own;
    let mut refused = false;
    for _ in 0..8 {
        match evaluator.multiply(&exhausted, &exhausted) {
            Ok(next) => exhausted = next,
            Err(Nine65Error::BootstrapFailed { .. }) => {
                refused = true;
                break;
            }
            Err(error) => panic!("unexpected multiplication refusal: {error}"),
        }
    }
    assert!(
        refused,
        "working multiplication history must have a finite certified budget"
    );
    // Additive history can approach the working decoder's boundary. At the
    // last accepted doubling its bound is at least Q_work/4, far beyond the
    // source's planned radius-three margin after modulus contraction.
    let mut addition_refused = false;
    for _ in 0..128 {
        match evaluator.add(&exhausted, &exhausted) {
            Ok(next) => exhausted = next,
            Err(Nine65Error::BootstrapFailed { .. }) => {
                addition_refused = true;
                break;
            }
            Err(error) => panic!("unexpected addition refusal: {error}"),
        }
    }
    assert!(
        addition_refused,
        "working additive history must have a finite budget"
    );
    assert_bootstrap_refusal(evaluator.refresh(&exhausted));
    assert_eq!(evaluator.real_refreshes(), 0);
}

#[test]
fn public_refresh_plan_refuses_invalid_geometry_scale_support_basis_and_resources() {
    let high = config(32, &BOOT, P * P);
    for (baby, radius, budget) in [
        (0, 3, 16 << 20),
        (3, 3, 16 << 20),
        (16, 3, 16 << 20),
        (4, 0, 16 << 20),
        (4, 129, 16 << 20),
        (4, 3, 0),
    ] {
        assert_bootstrap_refusal(PublicRefreshCircuitPlan::new(
            source_plan(),
            high.clone(),
            baby,
            radius,
            budget,
        ));
    }
    let mut wrong_geometry = high.clone();
    wrong_geometry.n = 64;
    assert_bootstrap_refusal(PublicRefreshCircuitPlan::new(
        source_plan(),
        wrong_geometry,
        4,
        3,
        16 << 20,
    ));
    let mut wrong_scale = high.clone();
    wrong_scale.t = P;
    assert_bootstrap_refusal(PublicRefreshCircuitPlan::new(
        source_plan(),
        wrong_scale,
        4,
        3,
        16 << 20,
    ));
    let mut wrong_remainder = high.clone();
    wrong_remainder.primes[12] = 576460752290119681;
    assert_bootstrap_refusal(PublicRefreshCircuitPlan::new(
        source_plan(),
        wrong_remainder,
        4,
        3,
        16 << 20,
    ));
    let mut wrong_prefix = high;
    wrong_prefix.primes.swap(0, 1);
    assert_bootstrap_refusal(PublicRefreshCircuitPlan::new(
        source_plan(),
        wrong_prefix,
        4,
        3,
        16 << 20,
    ));
    assert!(matches!(
        PublicRefreshSourcePlan::new(&config(8, &WORK, P), 8, 2, 3, 3),
        Err(SourceError::Parameters(_))
    ));
    assert!(matches!(
        source_plan().generate_with_rng(&mut ShadowHarvester::with_seed(7), 0),
        Err(SourceError::ResourceLimit)
    ));
}
