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
    let config = FHEConfig::for_depth(1, 4096, 0).expect("depth-one fuzz configuration");
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

    // Test scalar multiplication.
    //
    // The oracle must only assert what is mathematically guaranteed. This
    // legacy single-prime config has Delta = q/t ~ 15k and q mod t > Delta/2,
    // so a multiply that wraps the plaintext (a*scalar >= t) adds q mod t of
    // error per wrap and can never decrypt reliably, and a large scalar scales
    // the noise past Delta/2. When a*scalar < t there is no wrap, the noise
    // becomes exactly scalar * e, and the result must decrypt correctly
    // whenever that stays under Delta/2. Measure e from the raw decryption.
    if scalar > 0 && (a as u128) * (scalar as u128) < t as u128 {
        let delta = (config.q / t) as i128;
        let q = config.q as i128;
        let raw = decryptor.decrypt_raw(&ct_a);
        let mut e_max: i128 = 0;
        for (i, &c) in raw.coeffs.iter().enumerate() {
            let m_i = if i == 0 { a as i128 } else { 0 };
            let mut e = (c as i128 - delta * m_i).rem_euclid(q);
            if e > q / 2 {
                e -= q;
            }
            e_max = e_max.max(e.abs());
        }
        if (scalar as i128) * e_max < delta / 2 {
            let ct_scaled = evaluator.mul_plain(&ct_a, scalar);
            let scaled = decryptor.decrypt(&ct_scaled);
            let expected_scaled = (a * scalar) % t;
            assert_eq!(
                scaled, expected_scaled,
                "Mul plain failed: {} * {} = {} (expected {}), measured noise {}",
                a, scalar, scaled, expected_scaled, e_max
            );
        }
    }
});
