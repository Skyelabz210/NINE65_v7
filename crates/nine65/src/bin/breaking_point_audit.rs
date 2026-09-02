//! Breaking Point Audit for NINE65 v7.
//! Iteratively increases stress until the system fails or correctness suffers.

use nine65::noise::budget::{NoiseBudget, NoiseOpType};
use nine65::ops::rns_fhe::RNSFHEContext;
use nine65::prelude::*;
use std::time::Instant;

fn main() {
    println!("NINE65 v7 Ultimate Breaking Point Audit");
    println!("=======================================");

    let secure_config = SecureConfig::secure_256();
    let config = secure_config.into_config();

    let mut rng = ShadowHarvester::with_seed(5555);
    let ctx = RNSFHEContext::new(&config);
    let dual_keys = ctx.generate_keys_dual_full(&mut rng);

    println!("\n[Vector 1] Noise Exhaustion Threshold");
    let mut plaintext: u64 = 2;
    let mut ct = ctx.encrypt_dual(plaintext, &dual_keys.public_key, &mut rng);
    let mut budget = NoiseBudget::from_config(&config);
    let mut depth = 0;

    while budget.remaining_millibits() > 0 {
        ct = ctx.mul_plain_dual(&ct, 2);
        plaintext = (plaintext * 2) % config.t;
        let _ = budget.consume(
            NoiseOpType::MulPlain,
            NoiseBudget::mul_plain_cost(2, &config),
        );
        depth += 1;

        let decrypted = ctx.decrypt_dual(&ct, &dual_keys.secret_key);
        if decrypted != plaintext {
            println!("  SYSTEM COLLAPSE: Correctness failed at depth {}", depth);
            println!("  Final Budget: {} millibits", budget.remaining_millibits());
            break;
        }
    }
    println!("  Noise Breaking Point: {} operations", depth);

    println!("\n[Vector 2] Substrate Saturation (Fault Tolerance)");
    let base_ct = ctx.encrypt_dual(10, &dual_keys.public_key, &mut rng);

    for corrupted_lanes in 1..=6 {
        let mut perturbed_ct = base_ct.clone();
        for i in 0..corrupted_lanes {
            perturbed_ct.c0.main[i][0] = perturbed_ct.c0.main[i][0].wrapping_add(1);
        }

        let decrypted = ctx.decrypt_dual(&perturbed_ct, &dual_keys.secret_key);
        let success = decrypted == 10;

        println!(
            "  Fault Load: {}/6 Lanes | Correctness: {}",
            corrupted_lanes,
            if success { "STABLE" } else { "BROKEN" }
        );

        if !success {
            println!("  Substrate Breaking Point: {}/6 lanes", corrupted_lanes);
            break;
        }
    }

    println!("\n[Vector 3] Transduction Floor Collapse");
    // Force repeated bootstraps without operations to see if the noise floor rises
    let mut floor_ct = ctx.encrypt_dual(42, &dual_keys.public_key, &mut rng);
    let bootstrap = nine65::ops::bootstrap::ClockworkBootstrap::new(&config).unwrap();
    let bsk_ksk = bootstrap
        .generate_keys(&dual_keys.secret_key, &mut rng)
        .unwrap();

    let mut floor_correct = true;
    for i in 1..=50 {
        floor_ct = bootstrap
            .bootstrap(&floor_ct, &bsk_ksk.bsk, &bsk_ksk.ksk)
            .unwrap();
        let decrypted = ctx.decrypt_dual(&floor_ct, &dual_keys.secret_key);
        if decrypted != 42 {
            println!(
                "  TRANSUDCTION FAILURE: Noise floor collapsed at iteration {}",
                i
            );
            floor_correct = false;
            break;
        }
    }
    if floor_correct {
        println!("  Transduction Stability: 50+ iterations (Ground State maintained)");
    }

    println!("\n=======================================");
    println!("Audit Complete: NINE65 v7 limits identified.");
}
