//! Correctness-checked Depth-50 test for NINE65 v7.
//! Verifies that the depth-50 claim is backed by actual decryption success.

use nine65::prelude::*;
use nine65::ops::rns_fhe::RNSFHEContext;
use nine65::ops::bootstrap::ClockworkBootstrap;
use nine65::ops::auto_bootstrap::AutoBootstrapEvaluator;
use std::time::Instant;

fn main() {
    println!("NINE65 v7 Depth-50 Correctness & Transduction Audit");
    println!("===================================================");

    let secure_config = SecureConfig::secure_128();
    let config = secure_config.into_config();
    
    println!("Target: secure_128 (N=8192, Primes=3)");
    println!("Goal: Execute 50 multiplications with auto-bootstrap and verify correctness.");

    let mut rng = ShadowHarvester::with_seed(42);
    let ctx = RNSFHEContext::new(&config);
    let bootstrap = ClockworkBootstrap::new(&config).unwrap();
    
    let keys = ctx.generate_keys_dual_full(&mut rng);
    let bsk_ksk = bootstrap.generate_keys(&keys.secret_key, &mut rng).unwrap();

    let mut evaluator = AutoBootstrapEvaluator::new(
        &ctx,
        &bootstrap,
        &bsk_ksk.bsk,
        &bsk_ksk.ksk,
        &keys.eval_key,
        &config,
    );

    let factor: u64 = 2;
    let mut expected_plaintext: u64 = 1;
    let mut ct = ctx.encrypt_dual(expected_plaintext, &keys.public_key, &mut rng);

    let start = Instant::now();
    for d in 1..=50 {
        println!("  Testing Depth {}...", d);
        ct = evaluator.mul_auto(&ct, &ctx.encrypt_dual(factor, &keys.public_key, &mut rng)).unwrap();
        expected_plaintext = (expected_plaintext * factor) % config.t;
        
        // Decrypt and verify every 10 depths to ensure no silent failure
        if d % 10 == 0 {
            let decrypted = ctx.decrypt_dual(&ct, &keys.secret_key);
            if decrypted == expected_plaintext {
                println!("  Depth {:>2}: SUCCESS (Correctness Verified)", d);
            } else {
                println!("  Depth {:>2}: FAILED (Decryption Error!)", d);
                println!("    Expected: {}, Actual: {}", expected_plaintext, decrypted);
                panic!("Depth-50 Correctness Audit FAILED at depth {}", d);
            }
        }
    }
    let duration = start.elapsed();

    println!("\n[Audit Result]");
    println!("  Total Depth: 50 Multiplications");
    println!("  Auto-Refreshes: {}", evaluator.bootstrap_count);
    println!("  Total Time: {:?}", duration);
    println!("  Final Correctness: VERIFIED");
    
    println!("\nVERDICT: THE DEPTH-50 CLAIM IS PROVEN AND CORRECTNESS-CHECKED.");
    println!("===================================================");
}
