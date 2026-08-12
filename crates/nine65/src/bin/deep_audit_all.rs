//! Deep Correctness Audit for NINE65 v7.
//! Checks all security levels (128, 192, 256) and modes (Symmetric, Public, Dual).

use nine65::prelude::*;
use nine65::ops::rns_fhe::RNSFHEContext;
use nine65::ops::bootstrap::ClockworkBootstrap;

fn audit_config(config_name: &str, secure_config: SecureConfig) {
    let config = secure_config.into_config();
    println!("\n=== Auditing Config: {} ===", config_name);
    println!("N={}, lanes={}, q0={}, t={}", config.n, config.primes.len(), config.q, config.t);

    let ntt = NTTEngine::new(config.q, config.n);
    let mut rng = ShadowHarvester::with_seed(42);
    let keys = KeySet::generate(&config, &ntt, &mut rng);
    let ctx = RNSFHEContext::new(&config);
    let dual_keys = ctx.generate_keys_dual_full(&mut rng);

    // Setup Bootstrap for secure_256
    let mut bootstrap = ClockworkBootstrap::new(&config).ok();
    let bootstrap_keys = bootstrap.as_ref().map(|engine| {
        engine.generate_keys(&dual_keys.secret_key, &mut rng).expect("Bootstrap keygen")
    });

    let test_val_a: u64 = 42;
    let test_val_b: u64 = 13;

    // 1. Public Mode Check (using public key)
    print!("  Public Mode (Public Key Enc): ");
    let ct_pub = ctx.encrypt_dual(test_val_a % config.t, &dual_keys.public_key, &mut rng);
    let dec_pub = ctx.decrypt_dual(&ct_pub, &dual_keys.secret_key);
    if dec_pub == test_val_a % config.t {
        println!("PASS");
    } else {
        println!("FAIL (Expected {}, got {})", test_val_a % config.t, dec_pub);
    }

    // 2. Symmetric Mode Check (using secret key for multiplication)
    print!("  Symmetric Mode (SK-aided Mul): ");
    let ct_a = ctx.encrypt_dual(test_val_a % config.t, &dual_keys.public_key, &mut rng);
    let ct_b = ctx.encrypt_dual(test_val_b % config.t, &dual_keys.public_key, &mut rng);
    let ct_prod = ctx.mul_dual_symmetric(&ct_a, &ct_b, &dual_keys.secret_key);
    let dec_prod = ctx.decrypt_dual(&ct_prod, &dual_keys.secret_key);
    let expected_prod = (test_val_a * test_val_b) % config.t;
    if dec_prod == expected_prod {
        println!("PASS");
    } else {
        println!("FAIL (Expected {}, got {})", expected_prod, dec_prod);
    }

    // 3. Dual Mode Check (standard Dual-RNS path)
    print!("  Dual Mode (Standard Path): ");
    let ct_dual = ctx.encrypt_dual(test_val_a % config.t, &dual_keys.public_key, &mut rng);
    let dec_dual = ctx.decrypt_dual(&ct_dual, &dual_keys.secret_key);
    if dec_dual == test_val_a % config.t {
        println!("PASS");
    } else {
        println!("FAIL (Expected {}, got {})", test_val_a % config.t, dec_dual);
    }

    // 4. Deep Circuit Correctness (Iterative Addition/Multiplication)
    print!("  Deep Circuit (20 ops): ");
    let mut curr_ct = ctx.encrypt_dual(test_val_a % config.t, &dual_keys.public_key, &mut rng);
    let mut expected = test_val_a % config.t;
    let mut budget = NoiseBudget::from_config(&config);
    let mut success = true;
    for i in 0..20 {
        let op_val = (i + 1) as u64;
        let (op_type, cost) = if i % 2 == 0 {
            ("ADD", NoiseBudget::add_plain_cost())
        } else {
            ("MUL", NoiseBudget::mul_plain_cost(3, &config))
        };

        // Bootstrap if budget low
        if budget.remaining_millibits() < cost {
            if let (Some(ref engine), Some(ref b_keys)) = (bootstrap.as_ref(), bootstrap_keys.as_ref()) {
                curr_ct = engine.bootstrap(&curr_ct, &b_keys.bsk, &b_keys.ksk).expect("Bootstrap failed");
                budget.reset_after_bootstrap(&config);
            }
        }

        if i % 2 == 0 {
            curr_ct = ctx.add_plain_dual(&curr_ct, op_val % config.t);
            expected = (expected + op_val) % config.t;
            budget.consume(NoiseOpType::AddPlain, cost).ok();
        } else {
            let ct_const = ctx.encrypt_dual(2 % config.t, &dual_keys.public_key, &mut rng);
            curr_ct = ctx.mul_dual_symmetric(&curr_ct, &ct_const, &dual_keys.secret_key);
            expected = (expected * 2) % config.t;
            budget.consume(NoiseOpType::MulPlain, cost).ok();
        }
        
        let dec = ctx.decrypt_dual(&curr_ct, &dual_keys.secret_key);
        if dec != expected {
            println!("FAIL at step {} (Expected {}, got {})", i, expected, dec);
            success = false;
            break;
        }
    }
    if success {
        println!("PASS");
    }
}

fn main() {
    println!("NINE65 v7 Deep Correctness Audit");
    println!("================================");

    audit_config("secure_128", SecureConfig::secure_128());
    audit_config("secure_128_deep", SecureConfig::secure_128_deep());
    audit_config("secure_192", SecureConfig::secure_192());
    audit_config("secure_256", SecureConfig::secure_256());
}
