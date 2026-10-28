#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use nine65::prelude::*;

#[derive(Arbitrary, Debug)]
struct HomomorphicInput {
    a: u64,
    b: u64,
    scalar: u64,
    seed: u64,
}

// Fuzz homomorphic operations using BFV API
// This verifies that homomorphic operations produce correct results:
// - add(E(a), E(b)) decrypts to (a + b) mod t
// - sub(E(a), E(b)) decrypts to (a - b) mod t
// - mul_plain(E(a), c) decrypts to (a * c) mod t
fuzz_target!(|input: HomomorphicInput| {
    // This is the single-modulus API: a depth-sized RNS vector cannot fund
    // arithmetic performed only modulo its first prime. Use an NTT prime
    // whose actual q covers all plaintext scalars and worst-case fresh noise.
    // This is an arithmetic fixture, not a security claim.
    let q = 1_152_921_504_606_830_593; // prime 2^60 - 2^14 + 1
    let config = FHEConfig {
        n: 4096,
        primes: vec![q],
        q,
        t: 65_537,
        eta: 3,
        security_bits: 0,
        name: "single_modulus_fuzz",
    };
    let t = config.t;

    // Bound inputs to valid range
    let a = input.a % t;
    let b = input.b % t;
    let scalar = input.scalar % t;

    let ntt = NTTEngine::new(config.q, config.n);
    let mut rng = ShadowHarvester::with_seed(input.seed);

    let keys = KeySet::generate(&config, &ntt, &mut rng);

    let encoder = BFVEncoder::new(&config);
    let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
    let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
    let evaluator = BFVEvaluator::new(&ntt, &encoder, Some(&keys.eval_key));
    let tracked =
        nine65::ops::TrackedEvaluator::new(BFVEvaluator::new(&ntt, &encoder, None), &config);
    assert!(
        tracked.can_mul_plain(),
        "fixture must fund every scalar below t"
    );

    let ct_a = encryptor.encrypt(a, &mut rng);
    let ct_b = encryptor.encrypt(b, &mut rng);

    // Test addition
    let ct_sum = evaluator.add(&ct_a, &ct_b);
    let sum = decryptor.decrypt(&ct_sum);
    let expected_sum = (a + b) % t;
    assert_eq!(
        sum, expected_sum,
        "Add failed: {} + {} = {} (expected {})",
        a, b, sum, expected_sum
    );

    // Test subtraction
    let ct_diff = evaluator.sub(&ct_a, &ct_b);
    let diff = decryptor.decrypt(&ct_diff);
    let expected_diff = (a + t - b) % t; // Handle underflow
    assert_eq!(
        diff, expected_diff,
        "Sub failed: {} - {} = {} (expected {})",
        a, b, diff, expected_diff
    );

    // Test scalar multiplication
    if scalar > 0 {
        let ct_scaled = evaluator.mul_plain(&ct_a, scalar);
        let scaled = decryptor.decrypt(&ct_scaled);
        let expected_scaled = (a * scalar) % t;
        assert_eq!(
            scaled, expected_scaled,
            "Mul plain failed: {} * {} = {} (expected {})",
            a, scalar, scaled, expected_scaled
        );
    }
});
