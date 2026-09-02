//! Key Generation Benchmark for NINE65 v7.
//! Measures latency and estimates key sizes across all security tiers.

use nine65::ops::rns_fhe::RNSFHEContext;
use nine65::prelude::*;
use std::time::Instant;

fn main() {
    println!("NINE65 v7 Key Generation Benchmark");
    println!("==================================");

    let tiers = vec![
        ("secure_128", SecureConfig::secure_128()),
        ("secure_192", SecureConfig::secure_192()),
        ("secure_256", SecureConfig::secure_256()),
    ];

    println!("Tier | Ring Dim (N) | Primes | KeyGen Latency | Est. EvalKey Size");
    println!("-----|--------------|--------|----------------|------------------");

    for (name, secure_config) in tiers {
        let config = secure_config.into_config();
        let mut rng = ShadowHarvester::with_seed(1234);
        let ctx = RNSFHEContext::new(&config);

        let start = Instant::now();
        let dual_keys = ctx.generate_keys_dual_full(&mut rng);
        let latency = start.elapsed();

        // Estimate Evaluation Key Size
        // EvalKey contains relinearization and rotation keys.
        // Each key is a vector of ciphertexts.
        // For secure_256, N=16384, 6 primes.
        // A ciphertext is 2 polynomials, each N * primes * u64.
        let poly_size = config.n * config.primes.len() * 8;
        let ct_size = 2 * poly_size;

        // KeySet structure:
        // public_key: 1 ciphertext
        // eval_key: relin_key (vector of ciphertexts) + rotation_keys (map of ciphertexts)
        // For this benchmark, we'll estimate based on the relin_key size.
        let relin_key_size = dual_keys.eval_key.rlk.len() * ct_size;
        let total_eval_size_mb = relin_key_size as f64 / (1024.0 * 1024.0);

        println!(
            "{:<10} | {:<12} | {:<6} | {:<14?} | {:.2} MB",
            name,
            config.n,
            config.primes.len(),
            latency,
            total_eval_size_mb
        );
    }
    println!("==================================");
}
