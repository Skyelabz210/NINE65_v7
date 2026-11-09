//! Native public-evaluator integer division with encrypted zero status.
//! cargo run --release -p nine65 --example encrypted_integer_division

use nine65::ops::cram_public::CramPublicEvaluator;
use nine65::params::SecureConfig;
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Explicit tuple: secure_128's N/Q/eta, plaintext modulus 3 for bits.
    // Integer values are represented by four encrypted bits, not reduced mod 3.
    let mut config = SecureConfig::secure_128().into_config();
    config.t = 3;
    config.name = "native_integer_words_t3";
    let mut public = CramPublicEvaluator::new(&config);
    let (keys, client) = public.integer_keygen()?;
    println!(
        "N={}, primes={:?}, t={}, eta={}, width=4",
        config.n, config.primes, config.t, config.eta
    );
    for (n, d) in [(15, 3), (14, 3), (2, 3), (15, 0)] {
        let numerator = keys.encrypt_uint(n, 4)?;
        let denominator = keys.encrypt_uint(d, 4)?;
        let plan = keys.plan_integer_division(&numerator, &denominator)?;
        let start = Instant::now();
        let result = public.divide_integer(&numerator, &denominator, &keys)?;
        let elapsed = start.elapsed().as_nanos();
        // Only the client decrypts. Evaluator calls above receive no client key.
        let decoded = client.decrypt_division(&result)?;
        let expected = if d == 0 {
            (0, n, true)
        } else {
            (n / d, n % d, false)
        };
        assert_eq!(
            (decoded.quotient, decoded.remainder, decoded.divide_by_zero),
            expected
        );
        println!("{n}/{d}: q={}, r={}, zero={} [verified], products={}, gates={}, output_budget_millibits={}, evaluation_ns={elapsed}", decoded.quotient, decoded.remainder, decoded.divide_by_zero, plan.multiplications(), plan.gates(), plan.output_budget_millibits());
    }
    println!("Divisor 3 shares the plaintext modulus; the encrypted Boolean circuit requires no divisor inverse.");
    println!("{}", public.ledger().report());
    Ok(())
}
