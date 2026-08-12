use nine65::prelude::*;
use nine65::ops::rns_fhe::RNSFHEContext;

fn main() {
    let secure_config = SecureConfig::secure_256();
    let config = secure_config.into_config();
    println!("Debugging secure_256 failure...");
    println!("N={}, lanes={}, q0={}, t={}", config.n, config.primes.len(), config.q, config.t);

    let ntt = NTTEngine::new(config.q, config.n);
    let mut rng = ShadowHarvester::with_seed(42);
    let ctx = RNSFHEContext::new(&config);
    let dual_keys = ctx.generate_keys_dual_full(&mut rng);

    let test_val_a: u64 = 42;
    let mut curr_ct = ctx.encrypt_dual(test_val_a % config.t, &dual_keys.public_key, &mut rng);
    let mut expected = test_val_a % config.t;

    for i in 0..10 {
        let op_val = (i + 1) as u64;
        let prev_expected = expected;
        let op_type;
        if i % 2 == 0 {
            op_type = "ADD";
            curr_ct = ctx.add_plain_dual(&curr_ct, op_val % config.t);
            expected = (expected + op_val) % config.t;
        } else {
            op_type = "MUL";
            let ct_const = ctx.encrypt_dual(2 % config.t, &dual_keys.public_key, &mut rng);
            curr_ct = ctx.mul_dual_symmetric(&curr_ct, &ct_const, &dual_keys.secret_key);
            expected = (expected * 2) % config.t;
        }
        
        let dec = ctx.decrypt_dual(&curr_ct, &dual_keys.secret_key);
        println!("Step {}: type={}, prev={}, op={}, expected={}, got={}", i, op_type, prev_expected, if i % 2 == 0 { op_val } else { 2 }, expected, dec);
        
        if dec != expected {
            println!("FAILURE DETECTED at step {}", i);
            break;
        }
    }
}
