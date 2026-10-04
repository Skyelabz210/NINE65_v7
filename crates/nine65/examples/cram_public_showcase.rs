//! A runnable, correctness-checked tour of the public CRAM evaluator.
//!
//! Run from the repository root:
//! cargo run --offline -p nine65 --example cram_public_showcase

use nine65::entropy::ShadowHarvester;
use nine65::ops::cram_public::CramPublicEvaluator;
use nine65::params::secure_configs::SecureConfig;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = SecureConfig::secure_128_deep();
    let mut evaluator = CramPublicEvaluator::new(&config.config);
    let mut rng = ShadowHarvester::with_seed(42);
    let (public_keys, client_keys) = evaluator.keygen_with_rng(&mut rng);

    let a = evaluator.encrypt_with_rng(6, &client_keys.public_key, &mut rng);
    let b = evaluator.encrypt_with_rng(7, &client_keys.public_key, &mut rng);

    println!("NINE65 CRAM public evaluator");
    println!(
        "Config: secure_128_deep, N={}",
        evaluator.context().config.n
    );

    let sum = evaluator.add(&a, &b);
    let product = evaluator.mul(&a, &b, &public_keys)?;
    let scaled = evaluator.mul_plain(&a, 97);
    let restored = evaluator.exact_divide(&scaled, 97)?;

    for (label, ciphertext, expected) in [
        ("encrypted 6 + 7", &sum, 13),
        ("encrypted 6 × 7", &product, 42),
        ("encrypted (6 × 97) ÷ 97", &restored, 6),
    ] {
        let actual = evaluator.decrypt(ciphertext, &client_keys);
        if actual != expected {
            return Err(format!("{label}: expected {expected}, got {actual}").into());
        }
        println!("{label} = {actual} [verified by client decryption]");
    }

    let non_unit = evaluator.context().config.primes[0];
    if evaluator.exact_divide(&a, non_unit).is_ok() {
        return Err("non-unit divisor was accepted".into());
    }
    println!("division by a non-unit lane divisor was refused [verified]");
    println!("{}", evaluator.ledger().report());
    println!("Public refresh: not demonstrated; native refresh remains disabled.");

    Ok(())
}
