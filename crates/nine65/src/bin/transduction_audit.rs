//! Transduction & Auto-Refresh Audit for NINE65 v7.
//! Verifies Clockwork Bootstrap (transduction) stability under heavy load.

use nine65::ops::bootstrap::ClockworkBootstrap;
use nine65::ops::rns_fhe::RNSFHEContext;
use nine65::prelude::*;
use std::time::Instant;

fn main() {
    println!("NINE65 v7 Transduction & Auto-Refresh Audit");
    println!("==========================================");

    let secure_config = SecureConfig::secure_256();
    let config = secure_config.into_config();
    println!(
        "Config: secure_256 (N={}, Primes={})",
        config.n,
        config.primes.len()
    );

    let mut rng = ShadowHarvester::with_seed(888);
    let ctx = RNSFHEContext::new(&config);
    let dual_keys = ctx.generate_keys_dual_full(&mut rng);

    // Setup Clockwork Bootstrap
    let bootstrap = ClockworkBootstrap::new(&config).expect("Bootstrap init failed");
    let bootstrap_keys = bootstrap
        .generate_keys(&dual_keys.secret_key, &mut rng)
        .expect("Bootstrap keygen");

    let test_val: u64 = 7;
    let mut ct = ctx.encrypt_dual(test_val % config.t, &dual_keys.public_key, &mut rng);
    let mut expected = test_val % config.t;
    let mut budget = NoiseBudget::from_config(&config);

    let ops_to_run = 100; // Heavy load for 256-bit
    let mut bootstrap_count = 0;

    println!(
        "Running {} ops with low bootstrap threshold (forced transduction)...",
        ops_to_run
    );

    let start = Instant::now();
    for i in 1..=ops_to_run {
        // Force bootstrap if budget < 30%
        if budget.remaining_millibits() < (budget.initial_millibits() * 3 / 10) {
            println!(
                "  [Step {}] Transduction Triggered (Budget: {} mb)",
                i,
                budget.remaining_millibits()
            );
            let boot_start = Instant::now();
            ct = bootstrap
                .bootstrap(&ct, &bootstrap_keys.bsk, &bootstrap_keys.ksk)
                .expect("Bootstrap failed");
            budget.reset_after_bootstrap(&config);
            bootstrap_count += 1;
            println!(
                "  [Step {}] Transduction Complete in {} ms",
                i,
                boot_start.elapsed().as_millis()
            );
        }

        // Perform multiplication
        ct = ctx.mul_plain_dual(&ct, 2);
        expected = (expected * 2) % config.t;
        budget
            .consume(
                NoiseOpType::MulPlain,
                NoiseBudget::mul_plain_cost(2, &config),
            )
            .ok();

        // Verify correctness at every step
        let dec = ctx.decrypt_dual(&ct, &dual_keys.secret_key);
        if dec != expected {
            panic!(
                "CORRECTNESS FAILURE at step {}: expected {}, got {}",
                i, expected, dec
            );
        }
    }

    println!("------------------------------------------");
    println!("Audit Result: PASS");
    println!("Total Operations: {}", ops_to_run);
    println!("Total Transductions: {}", bootstrap_count);
    println!("Total Time: {} ms", start.elapsed().as_millis());
    println!("Final Budget: {} mb", budget.remaining_millibits());
    println!("------------------------------------------");
}
