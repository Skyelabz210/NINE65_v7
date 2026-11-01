//! Single-modulus arithmetic must never spend unused RNS-prime capacity.
use nine65::arithmetic::NTTEngine;
use nine65::entropy::ShadowHarvester;
use nine65::keys::KeySet;
use nine65::ops::Ciphertext;
use nine65::ops::{BFVDecryptor, BFVEncoder, BFVEncryptor, BFVEvaluator, TrackedEvaluator};
use nine65::params::FHEConfig;
use nine65::ring::RingPolynomial;

#[test]
fn unused_rns_primes_cannot_fund_single_modulus_scalar_multiplication() {
    let config = FHEConfig::for_depth(1, 4096, 0).unwrap();
    let ntt = NTTEngine::new(config.q, config.n);
    let encoder = BFVEncoder::new(&config);
    let mut rng = ShadowHarvester::with_seed(42);
    let keys = KeySet::generate(&config, &ntt, &mut rng);
    let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
    let ct = encryptor.encrypt(65_292, &mut rng);
    let mut tracked = TrackedEvaluator::new(BFVEvaluator::new(&ntt, &encoder, None), &config);
    let before = tracked.budget().remaining_millibits();
    assert!(tracked.try_mul_plain(&ct, 65_530).is_err());
    assert_eq!(tracked.budget().remaining_millibits(), before);

    let mut single = config.clone();
    single.primes = vec![config.q];
    let other = TrackedEvaluator::new(BFVEvaluator::new(&ntt, &encoder, None), &single);
    assert_eq!(before, other.budget().remaining_millibits());

    // A deterministic phase witness, independent of a fuzz seed. Error 1000
    // is inside this q's original decoding interval, but scaling by 65530
    // moves it outside. Extra primes in config cannot alter either result.
    let mut phase = encoder.encode(65_292);
    phase.coeffs[0] = (phase.coeffs[0] + 1000) % config.q;
    let noisy = Ciphertext {
        c0: phase,
        c1: RingPolynomial::zero(config.n, config.q),
    };
    let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
    assert_eq!(decryptor.decrypt(&noisy), 65_292);
    let evaluator = BFVEvaluator::new(&ntt, &encoder, None);
    assert_ne!(
        decryptor.decrypt(&evaluator.mul_plain(&noisy, 65_530)),
        1715
    );
    assert!(tracked.try_mul_plain(&noisy, 65_530).is_err());
}

#[test]
fn scalar_preflight_uses_the_requested_scalar_and_retired_mul_has_no_depth() {
    let config = FHEConfig::for_depth(1, 4096, 0).unwrap();
    let ntt = NTTEngine::new(config.q, config.n);
    let encoder = BFVEncoder::new(&config);
    let tracked =
        TrackedEvaluator::with_budget(BFVEvaluator::new(&ntt, &encoder, None), &config, 8);
    assert!(tracked.can_mul_plain_scalar(3));
    assert!(!tracked.can_mul_plain_scalar(65_530));
    assert!(!tracked.can_mul_plain());
    assert!(!tracked.can_mul());
    assert_eq!(tracked.remaining_depth(), 0);
}

#[test]
fn funded_single_modulus_preserves_full_plaintext_scalar_domain() {
    // Prime 2^60 - 2^14 + 1, congruent to 1 modulo 2N. Arithmetic fixture,
    // not a security profile. Unlike for_depth's first prime, q itself funds
    // every scalar below t, even under the worst-case encryption-noise bound.
    let q = 1_152_921_504_606_830_593;
    let config = FHEConfig {
        n: 4096,
        primes: vec![q],
        q,
        t: 65_537,
        eta: 3,
        security_bits: 0,
        name: "single_modulus_arithmetic_fixture",
    };
    let ntt = NTTEngine::new(q, config.n);
    let encoder = BFVEncoder::new(&config);
    let mut rng = ShadowHarvester::with_seed(42);
    let keys = KeySet::generate(&config, &ntt, &mut rng);
    let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
    let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
    for (a, scalar) in [
        (0, 0),
        (1, 65_536),
        (65_536, 65_536),
        (65_292, 65_530),
        (65_527, 255),
    ] {
        let ct = encryptor.encrypt(a, &mut rng);
        let mut tracked = TrackedEvaluator::new(BFVEvaluator::new(&ntt, &encoder, None), &config);
        let scaled = tracked.try_mul_plain(&ct, scalar).unwrap();
        assert_eq!(decryptor.decrypt(&scaled), a * scalar % config.t);
    }
}
