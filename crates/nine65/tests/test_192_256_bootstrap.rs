use nine65::entropy::ShadowHarvester;
use nine65::ops::bootstrap::ClockworkBootstrap;
use nine65::ops::rns_fhe::RNSFHEContext;
use nine65::params::secure_configs::SecureConfig;

#[test]
fn test_bootstrap_secure_192_roundtrip() {
    println!("\n=== Testing secure_192 bootstrap ===");
    let config = SecureConfig::secure_192().into_config();
    println!("Config: n={}, primes={:?}", config.n, config.primes.len());
    
    let work_ctx = RNSFHEContext::try_new(&config).expect("Work context");
    let bootstrap = ClockworkBootstrap::new(&config).expect("Bootstrap creation");
    println!("Bootstrap created: {} boot primes", bootstrap.boot_config.primes.len());
    
    let mut rng = ShadowHarvester::with_seed(42);
    let work_keys = work_ctx.generate_keys_dual_full(&mut rng);
    let boot_keys = bootstrap.generate_keys(&work_keys.secret_key, &mut rng)
        .expect("Bootstrap key generation");
    
    let ct = work_ctx.encrypt_dual(42, &work_keys.public_key, &mut rng);
    let ct_fresh = bootstrap.bootstrap(&ct, &boot_keys.bsk, &boot_keys.ksk)
        .expect("Bootstrap failed");
    let dec = work_ctx.decrypt_dual(&ct_fresh, &work_keys.secret_key);
    println!("Roundtrip: encrypted 42, decrypted {}", dec);
    assert_eq!(dec, 42, "Roundtrip failed for secure_192");
}

#[test]
fn test_bootstrap_secure_256_roundtrip() {
    println!("\n=== Testing secure_256 bootstrap ===");
    let config = SecureConfig::secure_256().into_config();
    println!("Config: n={}, primes={:?}", config.n, config.primes.len());
    
    let work_ctx = RNSFHEContext::try_new(&config).expect("Work context");
    let bootstrap = ClockworkBootstrap::new(&config).expect("Bootstrap creation");
    println!("Bootstrap created: {} boot primes", bootstrap.boot_config.primes.len());
    
    let mut rng = ShadowHarvester::with_seed(42);
    let work_keys = work_ctx.generate_keys_dual_full(&mut rng);
    let boot_keys = bootstrap.generate_keys(&work_keys.secret_key, &mut rng)
        .expect("Bootstrap key generation");
    
    let ct = work_ctx.encrypt_dual(42, &work_keys.public_key, &mut rng);
    let ct_fresh = bootstrap.bootstrap(&ct, &boot_keys.bsk, &boot_keys.ksk)
        .expect("Bootstrap failed");
    let dec = work_ctx.decrypt_dual(&ct_fresh, &work_keys.secret_key);
    println!("Roundtrip: encrypted 42, decrypted {}", dec);
    assert_eq!(dec, 42, "Roundtrip failed for secure_256");
}
