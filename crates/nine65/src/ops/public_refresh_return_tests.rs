use super::*;
use crate::entropy::ShadowHarvester;
use crate::ops::public_refresh_source::{
    PublicRefreshSourceEvaluator, PublicRefreshSourcePlan, SourceError,
};
use crate::params::SecureConfig;

struct Fixture {
    client: PublicRefreshSourceClient,
    evaluator: PublicRefreshSourceEvaluator,
    source: PreparedRefreshSource,
    return_stage: PublicRefreshReturn,
    boot: RNSFHEContext,
    embedded: RNSCiphertext,
    ideal_error: U1024,
    expected: Vec<u64>,
    rng: ShadowHarvester,
}

#[test]
fn public_return_noise_plan_is_key_free_and_checks_geometry() {
    let work = SecureConfig::secure_128().into_config();
    let mut boot = work.clone();
    boot.n = 32768;
    boot.primes.extend([167772161, 1224736769]);
    // Construct and admit the full native-size bound using public configs
    // alone: no RNS context, secret, ciphertext or key generator is invoked.
    let plan = ReturnNoisePlan::new(&work, &boot, 3).unwrap();
    let mut expected = 123456789u128 * work.t as u128;
    for &prime in boot.primes[work.primes.len()..].iter().rev() {
        expected =
            expected.div_ceil(prime as u128) + (work.t as u128 * (boot.n + 1) as u128).div_ceil(2);
    }
    let digits: usize = work
        .primes
        .iter()
        .map(|q| (64 - q.leading_zeros()).div_ceil(3) as usize)
        .sum();
    expected += work.t as u128 * boot.n as u128 * work.eta as u128 * 7 * digits as u128;
    assert_eq!(
        plan.output_bound(U1024::from_u64(123456789)).unwrap(),
        U512::from_u128(expected)
    );
    assert_eq!(
        plan.switch_key_bytes(),
        digits * 2 * work.primes.len() * boot.n * 8
    );
    let source_plan = PublicRefreshSourcePlan::new(&work, work.n, 2, 96, 3).unwrap();
    // Independent Python integer calculation of the full-polynomial square,
    // both dense-key drops and the base-8 source switch gives radius 48.
    assert_eq!(
        source_plan
            .next_square_source_radius(U512::from_u128(expected))
            .unwrap(),
        48
    );
    assert!(matches!(
        source_plan.next_square_source_radius(U512 {
            d0: u128::MAX,
            d1: u128::MAX,
            d2: u128::MAX,
            d3: u128::MAX,
        }),
        Err(SourceError::NoiseExhausted)
    ));
    assert!(ReturnNoisePlan::new(&work, &boot, 0).is_err());
    let mut invalid = boot.clone();
    invalid.n = 6;
    assert!(ReturnNoisePlan::new(&work, &invalid, 3).is_err());
    invalid = boot.clone();
    invalid.primes.swap(0, 1);
    assert!(ReturnNoisePlan::new(&work, &invalid, 3).is_err());
    invalid = boot;
    invalid.t += 2;
    assert!(ReturnNoisePlan::new(&work, &invalid, 3).is_err());
}

impl Fixture {
    fn new(seed: u64) -> Self {
        let mut work = SecureConfig::secure_128().into_config();
        work.n = 8;
        work.security_bits = 0;
        work.name = "INSECURE return boundary fixture";
        let plan = PublicRefreshSourcePlan::new(&work, 8, 2, 4, 2).unwrap();
        let mut rng = ShadowHarvester::with_seed(seed);
        let (client, evaluator) = plan.generate_with_rng(&mut rng, 1 << 20).unwrap();
        let expected = vec![0, 1, work.t - 1, 7, work.t / 2, 0, 9, work.t - 2];
        let input = evaluator.encrypt_with_rng(&expected, &mut rng).unwrap();
        let source = evaluator.prepare(&input).unwrap();

        let mut boot_config = work;
        boot_config.n = 32;
        boot_config.primes.extend([167772161, 1224736769]);
        let boot = RNSFHEContext::try_new(&boot_config).unwrap();
        let keys = boot.generate_keys_with_rng(&mut rng);
        let return_stage =
            PublicRefreshReturn::generate_with_rng(&client, &boot, &keys.secret_key, 2, &mut rng)
                .unwrap();
        // This fixture exercises only public return: its input is a real
        // fresh encryption of the expected embedded polynomial, not a claim
        // that the digit circuit produced it. Complete refresh has its own
        // separate integration harness.
        let mut embedded = boot.encrypt_with_rng(0, &keys.public_key, &mut rng);
        for (lane, (&q, &delta)) in boot.config.primes.iter().zip(&boot.delta_rns).enumerate() {
            let mont = &boot.rns.mont_contexts[lane];
            for (j, &message) in expected.iter().enumerate() {
                let addition =
                    mont.to_montgomery((delta as u128 * message as u128 % q as u128) as u64);
                embedded.c0.limbs[lane][4 * j] = ((embedded.c0.limbs[lane][4 * j] as u128
                    + addition as u128)
                    % q as u128) as u64;
            }
        }
        let ideal_error = U1024::from_u128(
            (2 * boot.n as u128 + 1) * boot.config.eta as u128 + boot.t as u128 - 1,
        );
        Self {
            client,
            evaluator,
            source,
            return_stage,
            boot,
            embedded,
            ideal_error,
            expected,
            rng,
        }
    }

    fn proof(&self) -> ReturnedWorkProof {
        self.return_stage
            .evaluate(&self.boot, &self.source, &self.embedded, self.ideal_error)
            .unwrap()
    }
}

#[test]
fn public_return_restores_dense_work_and_preserves_history() {
    let fixture = Fixture::new(0x5245_5455_524e);
    let proof = fixture.proof();
    let mut expected_bound = fixture.ideal_error.limbs[0] as u128 * fixture.boot.t as u128;
    for &prime in fixture.boot.config.primes[4..].iter().rev() {
        expected_bound = expected_bound.div_ceil(prime as u128)
            + (fixture.boot.t as u128 * (fixture.boot.n + 1) as u128).div_ceil(2);
    }
    let digits: u128 = fixture
        .client
        .work_context()
        .config
        .primes
        .iter()
        .map(|q| (64 - q.leading_zeros()).div_ceil(2) as u128)
        .sum();
    expected_bound += fixture.boot.t as u128
        * fixture.boot.n as u128
        * fixture.boot.config.eta as u128
        * 3
        * digits;
    assert_eq!(proof.bound, U512::from_u128(expected_bound));

    let restored = fixture
        .evaluator
        .accept_refresh(&fixture.source, proof)
        .unwrap();
    assert_eq!(
        fixture.client.decrypt_work(&restored).unwrap(),
        fixture.expected
    );
    assert_ne!(
        restored.lineage(),
        fixture.source.certificate().input_lineage()
    );
    let squared = fixture.evaluator.multiply(&restored, &restored).unwrap();
    let mut expected = vec![0i128; fixture.expected.len()];
    for (i, &a) in fixture.expected.iter().enumerate() {
        for (j, &b) in fixture.expected.iter().enumerate() {
            let sign = if i + j >= expected.len() { -1 } else { 1 };
            let slot = (i + j) % expected.len();
            expected[slot] += sign * a as i128 * b as i128;
        }
    }
    let expected: Vec<_> = expected
        .into_iter()
        .map(|v| v.rem_euclid(fixture.boot.t as i128) as u64)
        .collect();
    assert_eq!(fixture.client.decrypt_work(&squared).unwrap(), expected);
    assert_eq!(
        fixture
            .evaluator
            .prepare(&squared)
            .unwrap()
            .certificate()
            .input_lineage(),
        squared.lineage()
    );
}

#[test]
fn public_return_rejects_foreign_family_and_stale_source_lineage() {
    let mut fixture = Fixture::new(0x5245_5455_0001);
    let mut foreign_family = fixture.proof();
    foreign_family.family[0] ^= 1;
    assert!(matches!(
        fixture
            .evaluator
            .accept_refresh(&fixture.source, foreign_family),
        Err(SourceError::DomainMismatch)
    ));

    let mut false_lineage = fixture.proof();
    false_lineage.source_lineage[0] ^= 1;
    assert!(matches!(
        fixture
            .evaluator
            .accept_refresh(&fixture.source, false_lineage),
        Err(SourceError::DomainMismatch)
    ));

    let second_work = fixture
        .evaluator
        .encrypt_with_rng(&fixture.expected, &mut fixture.rng)
        .unwrap();
    let second_source = fixture.evaluator.prepare(&second_work).unwrap();
    let mut false_root = fixture.proof();
    false_root.root = second_source.certificate().root_capability();
    // Family and representation lineage still match the original source.
    // A root from another value occurrence must not authorize this return.
    assert!(matches!(
        fixture
            .evaluator
            .accept_refresh(&fixture.source, false_root),
        Err(SourceError::DomainMismatch)
    ));
    assert!(matches!(
        fixture
            .evaluator
            .accept_refresh(&second_source, fixture.proof()),
        Err(SourceError::DomainMismatch)
    ));

    let other = Fixture::new(0x5245_5455_0002);
    assert!(matches!(
        other
            .evaluator
            .accept_refresh(&fixture.source, fixture.proof()),
        Err(SourceError::DomainMismatch)
    ));
    assert!(fixture
        .return_stage
        .evaluate(
            &fixture.boot,
            &other.source,
            &fixture.embedded,
            fixture.ideal_error
        )
        .is_err());
}

#[test]
fn public_return_rejects_malformed_outputs_and_exhausted_bounds() {
    let fixture = Fixture::new(0x5245_5455_0003);
    let mut wrong_count = fixture.proof();
    wrong_count.raw.num_primes = 0;
    assert!(matches!(
        fixture
            .evaluator
            .accept_refresh(&fixture.source, wrong_count),
        Err(SourceError::Native(_))
    ));
    let mut wrong_shape = fixture.proof();
    wrong_shape.raw.c0.limbs[0].pop();
    assert!(matches!(
        fixture
            .evaluator
            .accept_refresh(&fixture.source, wrong_shape),
        Err(SourceError::Native(_))
    ));
    let mut noncanonical = fixture.proof();
    noncanonical.raw.c1.limbs[0][0] = fixture.client.work_context().config.primes[0];
    assert!(matches!(
        fixture
            .evaluator
            .accept_refresh(&fixture.source, noncanonical),
        Err(SourceError::Native(_))
    ));

    let q = U512::product_u64s(&fixture.client.work_context().config.primes);
    for bound in [
        q.div_u64(2).add(U512::from_u64(1)),
        U512 {
            d0: u128::MAX,
            d1: u128::MAX,
            d2: u128::MAX,
            d3: u128::MAX,
        },
    ] {
        let mut exhausted = fixture.proof();
        exhausted.bound = bound;
        assert!(matches!(
            fixture.evaluator.accept_refresh(&fixture.source, exhausted),
            Err(SourceError::NoiseExhausted)
        ));
    }
    assert!(fixture.return_stage.output_bound(U1024::MAX).is_err());
    let boot_q = U1024::checked_product_u64s(&fixture.boot.config.primes).unwrap();
    assert!(fixture.return_stage.output_bound(boot_q.shr1()).is_err());
    assert_eq!(
        fixture.client.decrypt_source(&fixture.source).unwrap(),
        fixture.expected
    );
}
