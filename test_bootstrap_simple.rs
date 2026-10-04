// Simple test to check if bootstrap works after our fix
use nine65::ops::bootstrap::ClockworkBootstrap;
use nine65::ops::rns_fhe::RNSFHEContext;
use nine65::params::secure_configs::SecureConfig;
use nine65::entropy::ShadowHarvester;

fn main() {
    println!("Testing Clockwork Bootstrap after Phase 1 fix...");

    let config = SecureConfig::secure_128().into_config();
    println!("Config: N={}, t={}, primes={:?}", config.n, config.t, config.primes);

    let ctx = RNSFHEContext::try_new(&config).expect("Failed to create context");
    let mut rng = ShadowHarvester::with_seed(42);

    let keys = ctx.generate_keys_dual_full(&mut rng);
    println!("Keys generated");

    let boot = ClockworkBootstrap::new(&config).expect("Failed to create bootstrap");
    println!("Bootstrap context created");

    let boot_keys = boot.generate_keys(&keys.secret_key, &mut rng)
        .expect("Failed to generate bootstrap keys");
    println!("Bootstrap keys generated");

    // Encrypt a test message
    let test_msg = 7u64;
    let ct = ctx.encrypt_dual(test_msg, &keys.public_key, &mut rng);
    println!("Ciphertext encrypted: msg={}", test_msg);

    // Try to bootstrap
    println!("\nAttempting bootstrap...");
    match boot.bootstrap(&ct, &boot_keys.bsk, &boot_keys.ksk) {
        Ok(refreshed) => {
            println!("Bootstrap succeeded!");
            let decrypted = ctx.decrypt_dual(&refreshed, &keys.secret_key);
            println!("Decrypted: {}", decrypted);
            if decrypted == test_msg {
                println!("SUCCESS: Bootstrap works correctly!");
            } else {
                println!("FAIL: Expected {}, got {}", test_msg, decrypted);
            }
        }
        Err(e) => {
            println!("Bootstrap failed: {}", e);
        }
    }
}
