use nine65::entropy::ShadowHarvester;
use nine65::ops::bootstrap::ClockworkBootstrap;
use nine65::ops::rns_fhe::RNSFHEContext;
use nine65::params::secure_configs::SecureConfig;

#[test]
fn test_bootstrap_secure_192_roundtrip() {
    println!("\n=== Testing secure_192 bootstrap (U256 CRT path) ===");
    let config = SecureConfig::secure_192().into_config();
    println!("Config: n={}, primes={}", config.n, config.primes.len());

    let work_ctx = RNSFHEContext::try_new(&config).expect("Work context");
    let bootstrap = ClockworkBootstrap::new(&config).expect("Bootstrap creation");
    println!("Bootstrap created: {} boot primes", bootstrap.boot_config.primes.len());

    let mut rng = ShadowHarvester::with_seed(42);
    let work_keys = work_ctx.generate_keys_dual_full(&mut rng);
    let boot_keys = bootstrap.generate_keys(&work_keys.secret_key, &mut rng)
        .expect("Bootstrap key generation");

    for &m in &[0u64, 1, 42, 1000, config.t - 1] {
        let ct = work_ctx.encrypt_dual(m, &work_keys.public_key, &mut rng);
        let ct_fresh = bootstrap.bootstrap(&ct, &boot_keys.bsk, &boot_keys.ksk)
            .unwrap_or_else(|e| panic!("Bootstrap failed for m={}: {}", m, e));
        let dec = work_ctx.decrypt_dual(&ct_fresh, &work_keys.secret_key);
        println!("Roundtrip: encrypted {}, decrypted {}", m, dec);
        assert_eq!(dec, m, "Roundtrip failed for secure_192: m={} got={}", m, dec);
    }
}

/// secure_256 bootstrap roundtrip requires `allow_insecure` feature
/// because the security estimator rejects the current parameter set
/// (226 hybrid bits < 230 minimum for 256-bit claim) outside of
/// unit test builds.
#[test]
#[cfg(feature = "allow_insecure")]
fn test_bootstrap_secure_256_roundtrip() {
    println!("\n=== Testing secure_256 bootstrap (U256 CRT path) ===");
    let config = SecureConfig::secure_256().into_config();
    println!("Config: n={}, primes={}", config.n, config.primes.len());

    let work_ctx = RNSFHEContext::try_new(&config).expect("Work context");
    let bootstrap = ClockworkBootstrap::new(&config).expect("Bootstrap creation");
    println!("Bootstrap created: {} boot primes", bootstrap.boot_config.primes.len());

    let mut rng = ShadowHarvester::with_seed(42);
    let work_keys = work_ctx.generate_keys_dual_full(&mut rng);
    let boot_keys = bootstrap.generate_keys(&work_keys.secret_key, &mut rng)
        .expect("Bootstrap key generation");

    for &m in &[0u64, 1, 42, 1000, config.t - 1] {
        let ct = work_ctx.encrypt_dual(m, &work_keys.public_key, &mut rng);
        let ct_fresh = bootstrap.bootstrap(&ct, &boot_keys.bsk, &boot_keys.ksk)
            .unwrap_or_else(|e| panic!("Bootstrap failed for m={}: {}", m, e));
        let dec = work_ctx.decrypt_dual(&ct_fresh, &work_keys.secret_key);
        println!("Roundtrip: encrypted {}, decrypted {}", m, dec);
        assert_eq!(dec, m, "Roundtrip failed for secure_256: m={} got={}", m, dec);
    }
}
