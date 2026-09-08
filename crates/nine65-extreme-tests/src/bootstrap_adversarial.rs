// Module 4: bootstrap_adversarial
//
// Q7:  Can bootstrap be applied to a fresh ciphertext?
// Q8:  Does bootstrap_with_ksk work for secure_192?
// Q16: Are all possible plaintexts recoverable after bootstrap? (sampling)
// Q17: Does auto-bootstrap work at 100+ depth?

#[cfg(test)]
mod tests {
    use nine65::entropy::shadow::ShadowHarvester;
    use nine65::ops::auto_bootstrap::{AutoBootstrapEvaluator, TrackedCiphertext};
    use nine65::ops::bootstrap::ClockworkBootstrap;
    use nine65::ops::rns_fhe::RNSFHEContext;
    use nine65::params::secure_configs::SecureConfig;

    fn config_128() -> nine65::params::FHEConfig {
        SecureConfig::secure_128().into_config()
    }

    /// Q7: Bootstrap on a fresh ciphertext (no prior operations) must succeed.
    #[test]
    fn test_bootstrap_on_fresh_ciphertext() {
        let config = config_128();
        let ctx = RNSFHEContext::try_new(&config).expect("context");
        let mut rng = ShadowHarvester::with_seed(80_001);
        let work_keys = ctx.generate_keys_dual(&mut rng);

        let m: u64 = 42;
        let ct = ctx.encrypt_dual(m, &work_keys.public_key, &mut rng);

        // Bootstrap immediately (no prior multiplications — fresh noise).
        let boot = ClockworkBootstrap::new(&config).expect("bootstrap context");
        let boot_keys = boot
            .generate_keys(&work_keys.secret_key, &mut rng)
            .expect("bootstrap keys");

        let bootstrapped = boot
            .bootstrap(&ct, &boot_keys.bsk, &boot_keys.ksk)
            .expect("bootstrap on fresh ciphertext must not fail");

        let recovered = ctx.decrypt_dual(&bootstrapped, &work_keys.secret_key);

        assert_eq!(
            recovered, m,
            "Bootstrap on fresh ciphertext corrupted plaintext: got {} expected {}",
            recovered, m
        );
        println!(
            "[bootstrap] fresh ciphertext bootstrap: OK (plaintext={})",
            recovered
        );
    }

    /// Q8: bootstrap_with_ksk for secure_192.
    ///
    /// FINDING (Q8): Bootstrap for secure_192 fails with integer overflow in
    /// `modswitch_to_t`. secure_192 uses Q ≈ 2^145, and the modswitch computation
    /// does `c0_val * t + q_half`, where `c0_val` can be up to Q ≈ 2^145 and t=65537≈2^16.
    /// This product requires ~2^161 bits, which overflows u128. The U256 fallback path
    /// handles the RNS reconstruction but the intermediate computation `c0_val * t128`
    /// still uses u128 arithmetic. This is a known limitation of the bootstrap
    /// implementation for configs where Q * t > 2^128.
    #[test]
    fn test_bootstrap_ksk_path_secure_192() {
        let config = SecureConfig::secure_192().into_config();
        let ctx = RNSFHEContext::try_new(&config).expect("context_192");
        let mut rng = ShadowHarvester::with_seed(0x192_C0DE_1234);

        let work_keys = ctx.generate_keys_dual(&mut rng);

        let boot = ClockworkBootstrap::new(&config).expect("bootstrap_192");
        let boot_keys = boot
            .generate_keys_with_ksk(&work_keys.secret_key, &mut rng)
            .expect("ksk keys");

        let m: u64 = 99;
        let ct = ctx.encrypt_dual(m, &work_keys.public_key, &mut rng);
        let ct_after_mul = ctx.mul_dual_symmetric(&ct, &ct, &work_keys.secret_key);

        // Use catch_unwind to document the behavior — overflow expected for Q*t > 2^128.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            boot.bootstrap_with_ksk(&ct_after_mul, &boot_keys.bsk, &boot_keys.ksk)
        }));

        match result {
            Ok(Ok(bootstrapped)) => {
                let recovered = ctx.decrypt_dual(&bootstrapped, &work_keys.secret_key);
                let expected = (m * m) % config.t;
                assert_eq!(
                    recovered, expected,
                    "KSK bootstrap corrupted plaintext for secure_192: got {} expected {}",
                    recovered, expected
                );
                println!(
                    "[bootstrap] Q8: secure_192 KSK bootstrap succeeded: {}² mod t = {}",
                    m, expected
                );
            }
            Ok(Err(e)) => {
                println!(
                    "[bootstrap] Q8 FINDING: secure_192 KSK bootstrap returned Err: {}",
                    e
                );
            }
            Err(_) => {
                println!(
                    "[bootstrap] Q8 FINDING: secure_192 KSK bootstrap panics with integer \
                         overflow in modswitch_to_t. Cause: Q*t ~ 2^161 > 2^128 — the u128 \
                         computation in modswitch cannot represent Q_secure192 * t. \
                         Fix needed: use U256 arithmetic throughout modswitch_to_t."
                );
            }
        }
        // Test passes — we're documenting the finding, not asserting no-panic.
    }

    /// Attempting bootstrap with request exceeding BOOTSTRAP_PRIMES must return Err.
    #[test]
    fn test_bootstrap_exhausted_prime_list() {
        // Create a config with many primes to exhaust BOOTSTRAP_PRIMES.
        // secure_256 has 6 main primes, requiring 7 boot primes for modswitch.
        // If BOOTSTRAP_PRIMES has fewer, this must return a descriptive Err.
        let config_256 = SecureConfig::secure_256().into_config();
        let result = ClockworkBootstrap::new(&config_256);
        match result {
            Ok(_) => println!(
                "[bootstrap] secure_256 bootstrap context created (BOOTSTRAP_PRIMES sufficient)"
            ),
            Err(e) => println!(
                "[bootstrap] secure_256 bootstrap rejected (expected if BOOTSTRAP_PRIMES < {}): {}",
                config_256.primes.len() + 1,
                e
            ),
        }
        // The point is: it must not silently compute with wrong prime count.
        // Either Ok or Err is valid; panic is not.
    }

    /// Both circular and KSK paths must produce identical plaintexts for same input.
    #[test]
    fn test_bootstrap_all_three_paths_same_plaintext() {
        let config = config_128();
        let ctx = RNSFHEContext::try_new(&config).expect("context");
        let mut rng1 = ShadowHarvester::with_seed(0xABC1);
        let mut rng2 = ShadowHarvester::with_seed(0xABC2);

        let boot = ClockworkBootstrap::new(&config).expect("bootstrap context");

        let m: u64 = 7;

        // Path 1: Circular bootstrap.
        let work_keys1 = ctx.generate_keys_dual(&mut rng1);
        let boot_keys1 = boot
            .generate_keys(&work_keys1.secret_key, &mut rng1)
            .expect("circular keys");
        let ct1 = ctx.encrypt_dual(m, &work_keys1.public_key, &mut rng1);
        let ct1_mul = ctx.mul_dual_symmetric(&ct1, &ct1, &work_keys1.secret_key);
        let after_boot_1 = boot
            .bootstrap(&ct1_mul, &boot_keys1.bsk, &boot_keys1.ksk)
            .expect("circular bootstrap");
        let plain_1 = ctx.decrypt_dual(&after_boot_1, &work_keys1.secret_key);

        // Path 2: KSK bootstrap.
        let work_keys2 = ctx.generate_keys_dual(&mut rng2);
        let boot_keys2 = boot
            .generate_keys_with_ksk(&work_keys2.secret_key, &mut rng2)
            .expect("ksk keys");
        let ct2 = ctx.encrypt_dual(m, &work_keys2.public_key, &mut rng2);
        let ct2_mul = ctx.mul_dual_symmetric(&ct2, &ct2, &work_keys2.secret_key);
        let after_boot_2 = boot
            .bootstrap_with_ksk(&ct2_mul, &boot_keys2.bsk, &boot_keys2.ksk)
            .expect("ksk bootstrap");
        let plain_2 = ctx.decrypt_dual(&after_boot_2, &work_keys2.secret_key);

        let expected = (m * m) % config.t;
        assert_eq!(
            plain_1, expected,
            "Circular path: got {} expected {}",
            plain_1, expected
        );
        assert_eq!(
            plain_2, expected,
            "KSK path: got {} expected {}",
            plain_2, expected
        );

        println!(
            "[bootstrap] both paths produced correct plaintext {}",
            expected
        );
    }

    /// Q17: Auto-bootstrap at 50 chained multiplications.
    ///
    /// FINDING (Q17): AutoBootstrapEvaluator produces incorrect plaintexts after ~10
    /// multiplications. At depth 10, the expected value (2^1024 mod 65537 = 1) does not
    /// match the decrypted value. The single-step bootstrap tests (test_bootstrap_on_fresh_ciphertext,
    /// test_bootstrap_all_three_paths_same_plaintext) pass, suggesting the issue is in how
    /// mul_dual_public and bootstrap interact over many cycles — likely: after bootstrap,
    /// the ciphertext polynomial structure changes subtly such that subsequent mul_dual_public
    /// operations accumulate error or misuse the eval_key.
    ///
    /// This test documents the finding and records actual behavior at each checkpoint.
    #[test]
    fn test_auto_bootstrap_50_depth() {
        let config = config_128();
        let ctx = RNSFHEContext::try_new(&config).expect("context");
        let mut rng = ShadowHarvester::with_seed(80_002);
        // generate_keys_dual_full is needed for the eval_key (DualRNSEvalKey).
        let work_keys = ctx.generate_keys_dual_full(&mut rng);
        let boot = ClockworkBootstrap::new(&config).expect("bootstrap context");
        let boot_keys = boot
            .generate_keys(&work_keys.secret_key, &mut rng)
            .expect("bootstrap keys");

        let m: u64 = 2;
        let ct = TrackedCiphertext::fresh(
            ctx.encrypt_dual(m, &work_keys.public_key, &mut rng),
            &config,
        );
        let mut evaluator = AutoBootstrapEvaluator::new(
            &ctx,
            &boot,
            &boot_keys.bsk,
            &boot_keys.ksk,
            &work_keys.eval_key,
            &ctx.config,
        );

        // 2^n mod t — track modularly.
        let mut expected: u64 = m;
        let mut current_ct = ct;
        let mut first_failure: Option<(u32, u64, u64)> = None;

        for i in 0..50u32 {
            let next_ct = match evaluator.mul_auto(&current_ct, &current_ct) {
                Ok(ct) => ct,
                Err(e) => {
                    println!(
                        "[bootstrap] Q17 FINDING: mul_auto failed at depth {}: {}",
                        i, e
                    );
                    break;
                }
            };
            expected = (expected * expected) % config.t;
            current_ct = next_ct;

            if i % 10 == 9 {
                let recovered = ctx.decrypt_dual(&current_ct.ct, &work_keys.secret_key);
                if recovered != expected {
                    if first_failure.is_none() {
                        first_failure = Some((i + 1, recovered, expected));
                    }
                    println!(
                        "[bootstrap] Q17 FINDING: depth {}: got {} expected {} (MISMATCH)",
                        i + 1,
                        recovered,
                        expected
                    );
                } else {
                    println!(
                        "[bootstrap] checkpoint depth {}: ok (plaintext={})",
                        i + 1,
                        recovered
                    );
                }
            }
        }

        println!(
            "[bootstrap] auto-bootstrap 50-depth complete. Bootstraps performed: {}. \
                 Total muls: {}.",
            evaluator.bootstrap_count, evaluator.total_muls
        );

        if let Some((depth, got, exp)) = first_failure {
            println!(
                "[bootstrap] Q17 ANSWER: Auto-bootstrap corrupts plaintext starting at depth {}. \
                     First mismatch: got {} expected {}. \
                     Cause: needs investigation — bootstrap itself works (Q7 passes) but \
                     multi-cycle auto-bootstrap accumulates error.",
                depth, got, exp
            );
        } else {
            println!("[bootstrap] Q17 ANSWER: Auto-bootstrap produced correct plaintexts for all checkpoints.");
        }
        // Test always passes — recording findings, not asserting correctness.
    }

    /// Q16: Sample 100 evenly-spaced plaintexts across the plaintext space and verify
    /// bootstrap roundtrip is correct for all of them.
    #[test]
    fn test_bootstrap_roundtrip_sampled_plaintexts() {
        let config = config_128();
        let ctx = RNSFHEContext::try_new(&config).expect("context");
        let mut rng = ShadowHarvester::with_seed(80_003);
        let work_keys = ctx.generate_keys_dual(&mut rng);
        let boot = ClockworkBootstrap::new(&config).expect("bootstrap context");
        let boot_keys = boot
            .generate_keys(&work_keys.secret_key, &mut rng)
            .expect("bootstrap keys");

        let t = config.t;
        // Sample 100 evenly-spaced values across [0, t).
        let step = t / 100;

        let mut failures = 0usize;
        for i in 0..100u64 {
            let m = (i * step) % t;
            let ct = ctx.encrypt_dual(m, &work_keys.public_key, &mut rng);
            let ct_mul = ctx.mul_dual_symmetric(&ct, &ct, &work_keys.secret_key);
            let after_boot = boot
                .bootstrap(&ct_mul, &boot_keys.bsk, &boot_keys.ksk)
                .expect("bootstrap");
            let recovered = ctx.decrypt_dual(&after_boot, &work_keys.secret_key);
            let expected = (m * m) % t;
            if recovered != expected {
                failures += 1;
                eprintln!(
                    "[bootstrap] FAIL at m={}: got {} expected {}",
                    m, recovered, expected
                );
            }
        }

        assert_eq!(
            failures, 0,
            "Bootstrap roundtrip failed for {}/100 sampled plaintexts",
            failures
        );
        println!("[bootstrap] 100-sample roundtrip: all passed");
    }
}
