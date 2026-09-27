// Diagnostic: exits unsuccessfully until public Phase 1 is implemented.
use nine65::prelude::*;

fn main() {
    println!("Testing Phase 1 fix...\n");

    // Use a simple config for faster testing
    let config = SecureConfig::secure_128().into_config();
    println!("Using secure_128 config");
    println!("N = {}, t = {}", config.n, config.t);

    let ctx = RNSFHEContext::try_new(&config).expect("Failed to create context");
    let mut rng = ShadowHarvester::with_seed(42);

    // Generate keys
    println!("Generating keys...");
    let keys = ctx.generate_keys_dual_full(&mut rng);

    // Create bootstrap
    println!("Creating bootstrap context...");
    use nine65::ops::bootstrap::ClockworkBootstrap;
    let boot = ClockworkBootstrap::new(&config).expect("Failed to create bootstrap");

    // Generate bootstrap keys
    println!("Generating bootstrap keys...");
    let boot_keys = boot
        .generate_keys(&keys.secret_key, &mut rng)
        .expect("Failed to generate bootstrap keys");

    // Encrypt a message
    let msg = 7u64;
    println!("\nEncrypting message: {}", msg);
    let ct = ctx.encrypt_dual(msg, &keys.public_key, &mut rng);

    // Try bootstrap
    println!("Attempting bootstrap...");
    match boot.bootstrap(&ct, &boot_keys.bsk, &boot_keys.ksk) {
        Ok(refreshed) => {
            println!("✓ Bootstrap succeeded!");
            let decrypted = ctx.decrypt_dual(&refreshed, &keys.secret_key);
            println!("Decrypted: {}", decrypted);

            if decrypted == msg {
                println!("\n✓✓✓ SUCCESS: Bootstrap works correctly! ✓✓✓");
            } else {
                eprintln!("FAIL: Expected {}, got {}", msg, decrypted);
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Bootstrap unavailable: {:?}", e);
            std::process::exit(1);
        }
    }
}
