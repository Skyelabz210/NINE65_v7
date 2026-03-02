// Depth-aware modulus switching test
// Run with: cargo run -p nine65 --example test_mod_switch

use nine65::entropy::ShadowHarvester;
use nine65::ops::rns_fhe::RNSFHEContext;
use nine65::params::FHEConfig;

fn main() {
    println!("=== DEPTH-AWARE MODULUS SWITCHING TEST ===\n");

    // Test 1: Standard 3-prime config (depth-1 only)
    println!("--- Test 1: standard_128 (3 primes, max depth-1) ---");
    test_depth(&FHEConfig::standard_128_insecure(), 1);

    // Test 2: New 4-prime config (depth-2)
    println!("\n--- Test 2: depth2_128 (4 primes, max depth-2) ---");
    test_depth(&FHEConfig::depth2_128_insecure(), 2);

    // Test 3: Note on depth-3+ limitation
    // depth3_128 has 5 primes (~150 bits total), exceeding u128 capacity.
    // Depth-3+ requires either smaller primes or big-integer Q handling.
    println!("\n--- Test 3: depth3_128 limitation ---");
    println!("NOTE: depth3_128 (5 × 30-bit primes = ~150 bits) exceeds u128 capacity.");
    println!("Depth-3+ would require ~25-bit primes or big-integer Q handling.");

    // Test 4: Verify max_mod_switch_depth API
    println!("\n--- Test 4: max_mod_switch_depth API ---");
    println!(
        "  standard_128: max depth = {}",
        FHEConfig::standard_128_insecure().max_mod_switch_depth()
    );
    println!(
        "  depth2_128: max depth = {}",
        FHEConfig::depth2_128_insecure().max_mod_switch_depth()
    );
    println!(
        "  depth3_128: max depth = {}",
        FHEConfig::depth3_128_insecure().max_mod_switch_depth()
    );
    println!(
        "  deep_circuit: max depth = {}",
        FHEConfig::deep_circuit_insecure().max_mod_switch_depth()
    );
}

fn test_depth(config: &FHEConfig, target_depth: usize) {
    println!(
        "Config: {} ({} primes, max_depth={})",
        config.name,
        config.primes.len(),
        config.max_mod_switch_depth()
    );

    let ctx = RNSFHEContext::new(config);
    let mut rng = ShadowHarvester::with_seed(42);
    let keys = ctx.generate_keys_dual_full(&mut rng);

    // Depth-1: 2 * 3 = 6
    let ct2 = ctx.encrypt_dual(2, &keys.public_key, &mut rng);
    let ct3 = ctx.encrypt_dual(3, &keys.public_key, &mut rng);
    let ct6 = ctx.mul_dual_public(&ct2, &ct3, &keys.eval_key).unwrap();
    let dec6 = ctx.decrypt_dual(&ct6, &keys.secret_key);
    let d1_ok = dec6 == 6;
    println!(
        "  Depth-1: 2*3 = {} (expected 6) {} [level: {} primes]",
        dec6,
        if d1_ok { "OK" } else { "FAIL" },
        ct6.c0.main.len()
    );

    if target_depth >= 2 {
        // Depth-2: 6 * 20 = 120
        let ct4 = ctx.encrypt_dual(4, &keys.public_key, &mut rng);
        let ct5 = ctx.encrypt_dual(5, &keys.public_key, &mut rng);
        let ct20 = ctx.mul_dual_public(&ct4, &ct5, &keys.eval_key).unwrap();

        let ct120 = ctx.mul_dual_public(&ct6, &ct20, &keys.eval_key).unwrap();
        let dec120 = ctx.decrypt_dual(&ct120, &keys.secret_key);
        let d2_ok = dec120 == 120;
        println!(
            "  Depth-2: 6*20 = {} (expected 120) {} [level: {} primes]",
            dec120,
            if d2_ok { "OK" } else { "FAIL" },
            ct120.c0.main.len()
        );

        if d2_ok {
            println!("  SUCCESS: Depth-2 with mod-switch WORKS!");
        }
    }
}
