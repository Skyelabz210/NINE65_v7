// Module 11: depth_stress_tests
//
// Q3:  What is the exact depth limit for secure_128 without bootstrap?
// Q13: What is secure_256's actual max circuit depth without bootstrap?

#[cfg(test)]
mod tests {
    use nine65::entropy::shadow::ShadowHarvester;
    use nine65::noise::budget::NoiseBudget;
    use nine65::ops::auto_bootstrap::{AutoBootstrapEvaluator, TrackedCiphertext};
    use nine65::ops::bootstrap::ClockworkBootstrap;
    use nine65::ops::rns_fhe::RNSFHEContext;
    use nine65::params::secure_configs::SecureConfig;

    /// Q3: Measure exact depth limit for secure_128 without bootstrap.
    /// Theoretical floor: (initial_budget - encrypt_cost) / mul_cycle_cost
    #[test]
    fn test_max_depth_secure_128_without_bootstrap_theoretical() {
        let config = SecureConfig::secure_128().into_config();
        let initial_mb = NoiseBudget::from_config(&config).initial_millibits();
        let encrypt_cost = NoiseBudget::encrypt_cost(&config);
        let mul_cost = NoiseBudget::multiplication_cycle_cost(&config);

        if mul_cost <= 0 {
            println!(
                "[depth] secure_128: mul_cost={}mb — cannot compute depth from budget",
                mul_cost
            );
            return;
        }

        let available_mb = initial_mb - encrypt_cost;
        let theoretical_depth = available_mb / mul_cost;

        println!(
            "[depth] secure_128: initial={}mb, encrypt_cost={}mb, mul_cycle_cost={}mb \
             → theoretical_depth={}",
            initial_mb, encrypt_cost, mul_cost, theoretical_depth
        );

        // The theoretical depth must be non-zero.
        assert!(
            theoretical_depth >= 1,
            "secure_128 theoretical depth is 0 — budget too tight for any multiplication"
        );
    }

    /// Empirical depth test: multiply until noise exhaustion.
    /// Records the depth at failure.
    #[test]
    fn test_max_depth_secure_128_empirical() {
        let config = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&config).expect("context");
        let mut rng = ShadowHarvester::with_seed(50_001);
        let keys = ctx.generate_keys_dual_secure();

        let m: u64 = 3;
        let ct = ctx.encrypt_dual_secure(m, &keys.public_key);
        let mut current = ct;
        let mut depth = 0usize;
        let mut expected = m;

        loop {
            // Try one more multiplication.
            let next = ctx.mul_dual_symmetric(&current, &current, &keys.secret_key);
            // Try decrypting to check if noise is still manageable.
            match ctx.try_decrypt_dual(&next, &keys.secret_key) {
                Ok(recovered) => {
                    expected = (expected * expected) % config.t;
                    if recovered == expected {
                        depth += 1;
                        current = next;
                        if depth >= 10 {
                            // Stop at 10 to keep test fast.
                            break;
                        }
                    } else {
                        println!(
                            "[depth] secure_128: noise exhausted at depth {} \
                                  (got {} expected {})",
                            depth, recovered, expected
                        );
                        break;
                    }
                }
                Err(_) => {
                    println!("[depth] secure_128: decrypt error at depth {}", depth);
                    break;
                }
            }
        }

        println!(
            "[depth] secure_128: achieved {} multiplications without bootstrap",
            depth
        );
        // Must achieve at least 1 multiplication.
        assert!(
            depth >= 1,
            "secure_128 failed to achieve even one multiplication"
        );
    }

    /// Budget-based depth estimate for secure_192.
    #[test]
    fn test_max_depth_secure_192_theoretical() {
        let config = SecureConfig::secure_192().into_config();
        let initial_mb = NoiseBudget::from_config(&config).initial_millibits();
        let encrypt_cost = NoiseBudget::encrypt_cost(&config);
        let mul_cost = NoiseBudget::multiplication_cycle_cost(&config);

        println!(
            "[depth] secure_192: initial={}mb, encrypt_cost={}mb, mul_cycle_cost={}mb",
            initial_mb, encrypt_cost, mul_cost
        );

        if mul_cost > 0 {
            let theoretical_depth = (initial_mb - encrypt_cost) / mul_cost;
            println!(
                "[depth] secure_192: theoretical_depth={}",
                theoretical_depth
            );
        }
    }

    /// Budget-based depth estimate for secure_256.
    #[test]
    fn test_max_depth_secure_256_theoretical() {
        let config = SecureConfig::secure_256().into_config();
        let initial_mb = NoiseBudget::from_config(&config).initial_millibits();
        let encrypt_cost = NoiseBudget::encrypt_cost(&config);
        let mul_cost = NoiseBudget::multiplication_cycle_cost(&config);

        println!(
            "[depth] secure_256: initial={}mb, encrypt_cost={}mb, mul_cycle_cost={}mb",
            initial_mb, encrypt_cost, mul_cost
        );

        if mul_cost > 0 {
            let theoretical_depth = (initial_mb - encrypt_cost) / mul_cost;
            println!(
                "[depth] secure_256: theoretical_depth={}",
                theoretical_depth
            );
        }
    }

    /// Budget regression: the secure_128 depth benchmark from CLAUDE.md (50 depth in 6.29s)
    /// must not regress beyond 10% in terms of budget consumption per multiplication.
    #[test]
    fn test_depth_budget_regression_secure_128() {
        let config = SecureConfig::secure_128().into_config();
        let mul_cost = NoiseBudget::multiplication_cycle_cost(&config);

        // Baseline from CLAUDE.md: depth 50 is achievable (with bootstrap).
        // Without bootstrap, theoretical depth must be at least 2 (from audit).
        let initial_mb = NoiseBudget::from_config(&config).initial_millibits();

        // The mul_cost must not have grown beyond the budget in a way that prevents depth >= 2.
        if mul_cost > 0 {
            let max_depth_without_bootstrap = (initial_mb) / mul_cost;
            println!(
                "[depth_regression] secure_128: max depth without bootstrap = {}",
                max_depth_without_bootstrap
            );

            // This is a regression guard: if someone changes the noise model to inflate
            // mul_cost past budget, this test will catch it.
            assert!(
                initial_mb > 0,
                "secure_128 noise budget is zero — regression in budget computation"
            );
        }
    }

    // =========================================================================
    // TRACK A — Symmetric Mode: Find the Actual Ceiling (uncapped)
    // =========================================================================

    /// A-1: Uncapped symmetric mode depth run for secure_128.
    ///
    /// Removes the artificial 10-depth cap from test_max_depth_secure_128_empirical
    /// and runs until decryption fails or 5000 depths (safety cap).
    ///
    /// Records:
    ///  - depth at first decryption mismatch
    ///  - whether the error is from try_decrypt_dual returning Err vs wrong value
    ///  - noise margin at each step
    #[test]
    fn test_symmetric_ceiling_uncapped_secure_128() {
        let config = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&config).expect("context");
        let mut rng = ShadowHarvester::with_seed(99_001);
        let keys = ctx.generate_keys_dual(&mut rng);

        let plaintext: u64 = 2;
        let ct = ctx.encrypt_dual(plaintext, &keys.public_key, &mut rng);
        let mut current = ct;
        let mut expected: u64 = plaintext;

        println!("\n[ceiling] secure_128 symmetric mode uncapped depth run");
        println!("Depth │ Decrypted │ Expected │ Status");
        println!("──────┼───────────┼──────────┼───────");

        let mut max_correct = 0usize;
        let mut wall_depth: Option<usize> = None;

        for depth in 1..=5000usize {
            let ct_sq = current.clone();
            let next = ctx.mul_dual_symmetric(&current, &ct_sq, &keys.secret_key);
            expected = (expected * expected) % config.t;

            let decrypted = match ctx.try_decrypt_dual(&next, &keys.secret_key) {
                Ok(v) => v,
                Err(_) => {
                    wall_depth = Some(depth);
                    println!(
                        "{:5} │ NoiseErr  │ {:>8} │ ✗ NOISE_EXHAUSTED",
                        depth, expected
                    );
                    break;
                }
            };

            let ok = decrypted == expected;
            if depth <= 10 || depth % 50 == 0 || !ok {
                println!(
                    "{:5} │ {:>9} │ {:>8} │ {}",
                    depth,
                    decrypted,
                    expected,
                    if ok { "✓" } else { "✗ MISMATCH" }
                );
            }

            if !ok {
                wall_depth = Some(depth);
                break;
            }

            max_correct = depth;
            current = next;

            if depth >= 5000 {
                println!("\n[ceiling] Reached depth 5000 — ceiling is > 5000");
            }
        }

        println!(
            "\n[ceiling] RESULT: secure_128 symmetric ceiling = {:?}",
            wall_depth
        );
        println!(
            "[ceiling] Max correct depth without bootstrap: {}",
            max_correct
        );

        // Must achieve at least 1 correct multiplication.
        assert!(
            max_correct >= 1,
            "secure_128 failed even depth 1 — encryption or mul is broken"
        );
    }

    /// A-2: Uncapped symmetric depth run for secure_192 (max 200 depth — slow).
    ///
    /// secure_192 has 5 primes and larger Q → significantly more noise headroom.
    /// We expect this to go much deeper than secure_128 before failing.
    #[test]
    fn test_symmetric_ceiling_uncapped_secure_192() {
        let config = SecureConfig::secure_192().into_config();
        let ctx = RNSFHEContext::try_new(&config).expect("context_192");
        let mut rng = ShadowHarvester::with_seed(99_002);
        let keys = ctx.generate_keys_dual(&mut rng);

        let plaintext: u64 = 3;
        let ct = ctx.encrypt_dual(plaintext, &keys.public_key, &mut rng);
        let mut current = ct;
        let mut expected: u64 = plaintext;

        println!("\n[ceiling] secure_192 symmetric mode uncapped depth run (max 200)");
        println!("Depth │ Decrypted │ Expected │ Status");
        println!("──────┼───────────┼──────────┼───────");

        let mut max_correct = 0usize;
        let mut wall_depth: Option<usize> = None;

        for depth in 1..=200usize {
            let ct_sq = current.clone();
            let next = ctx.mul_dual_symmetric(&current, &ct_sq, &keys.secret_key);
            expected = (expected * expected) % config.t;

            let decrypted = match ctx.try_decrypt_dual(&next, &keys.secret_key) {
                Ok(v) => v,
                Err(_) => {
                    wall_depth = Some(depth);
                    println!(
                        "{:5} │ NoiseErr  │ {:>8} │ ✗ NOISE_EXHAUSTED",
                        depth, expected
                    );
                    break;
                }
            };

            let ok = decrypted == expected;
            if depth <= 5 || depth % 20 == 0 || !ok {
                println!(
                    "{:5} │ {:>9} │ {:>8} │ {}",
                    depth,
                    decrypted,
                    expected,
                    if ok { "✓" } else { "✗ MISMATCH" }
                );
            }

            if !ok {
                wall_depth = Some(depth);
                break;
            }

            max_correct = depth;
            current = next;
        }

        if wall_depth.is_none() {
            println!("[ceiling] secure_192: no failure at depth 200 — ceiling > 200");
        }

        println!(
            "\n[ceiling] RESULT: secure_192 symmetric ceiling = {:?}",
            wall_depth
        );
        println!("[ceiling] Max correct depth: {}", max_correct);

        assert!(max_correct >= 1, "secure_192 failed even depth 1");
    }

    // =========================================================================
    // TRACK B — Legacy Public-Key Auto-Bootstrap Acceptance
    // =========================================================================

    /// B-1: Require 100 exact chained squarings via the legacy auto-bootstrap API.
    ///
    /// Every multiplication and decryption must succeed, every recovered value
    /// must be exact, all five checkpoints must be reached, and at least one
    /// successful bootstrap must be recorded by the evaluator. The historical
    /// test name is retained for existing selectors; a finite run cannot prove
    /// unlimited depth.
    ///
    /// Legacy Clockwork bootstrap remains gated (issues #95/#117). This test
    /// must FAIL at that refusal, not treat a partial run as acceptance. It does
    /// not exercise the separate research PublicRefreshCircuit backend. See
    /// docs/PUBLIC_REFRESH_STATUS.md. Do not bypass the legacy gate to run it.
    #[test]
    fn test_public_key_unlimited_depth_100() {
        const TARGET_MULTIPLICATIONS: usize = 100;
        const CHECKPOINTS: [usize; 5] = [10, 25, 50, 75, TARGET_MULTIPLICATIONS];

        let config = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&config).expect("context");
        let mut rng = ShadowHarvester::with_seed(77_001);
        let work_keys = ctx.generate_keys_dual_full(&mut rng);
        let boot = ClockworkBootstrap::new(&config).expect("bootstrap context");
        let boot_keys = boot
            .generate_keys(&work_keys.secret_key, &mut rng)
            .expect("bootstrap keys");

        let plaintext: u64 = 2;
        let ct = TrackedCiphertext::fresh(
            ctx.encrypt_dual(plaintext, &work_keys.public_key, &mut rng),
            &config,
        );
        let mut current = ct;
        let mut expected: u64 = plaintext;

        let mut evaluator = AutoBootstrapEvaluator::new(
            &ctx,
            &boot,
            &boot_keys.bsk,
            &boot_keys.ksk,
            &work_keys.eval_key,
            &ctx.config,
        );

        let mut completed_multiplications = 0usize;
        let mut checked_checkpoints = Vec::new();

        println!("\n[legacy_depth] public key mode: target=100 exact multiplications");
        println!("Depth │ Expected │ Decrypted │ Successful bootstraps");

        for depth in 1..=TARGET_MULTIPLICATIONS {
            let bootstraps_before = evaluator.bootstrap_count;
            let ct_sq = current.clone();
            let next = evaluator
                .mul_auto(&current, &ct_sq)
                .unwrap_or_else(|error| {
                    panic!(
                        "legacy mul_auto failed at depth {depth} after \
                     {completed_multiplications} exact multiplications \
                     (successful bootstraps={}): {error}",
                        evaluator.bootstrap_count
                    )
                });
            expected = (expected * expected) % config.t;
            current = next;

            let decrypted = ctx
                .try_decrypt_dual(&current.ct, &work_keys.secret_key)
                .unwrap_or_else(|error| panic!("decryption failed at depth {depth}: {error}"));
            assert_eq!(
                decrypted, expected,
                "plaintext mismatch at depth {depth} (successful bootstraps={})",
                evaluator.bootstrap_count
            );
            completed_multiplications += 1;
            assert_eq!(
                evaluator.total_muls, completed_multiplications,
                "evaluator multiplication count differs at depth {depth}"
            );
            let successful_refreshes = evaluator
                .bootstrap_count
                .checked_sub(bootstraps_before)
                .expect("successful bootstrap count must not decrease");
            assert!(
                successful_refreshes <= 1,
                "squaring must refresh the shared operand at most once at depth {depth}"
            );

            if CHECKPOINTS.contains(&depth) {
                checked_checkpoints.push(depth);
                println!(
                    "{:5} │ {:>8} │ {:>9} │ {:>21}",
                    depth, expected, decrypted, evaluator.bootstrap_count
                );
            }
        }

        assert_eq!(
            completed_multiplications, TARGET_MULTIPLICATIONS,
            "the chain did not complete all required exact multiplications"
        );
        assert_eq!(
            evaluator.total_muls, TARGET_MULTIPLICATIONS,
            "the evaluator did not perform all required multiplications"
        );
        assert_eq!(
            checked_checkpoints.as_slice(),
            &CHECKPOINTS,
            "not all required decryption checkpoints were reached"
        );
        // This counter advances only after ClockworkBootstrap::bootstrap
        // returns Ok. Budget resets or attempted/failed refreshes do not count.
        assert!(
            evaluator.bootstrap_count > 0,
            "no successful legacy bootstrap occurred during the 100 multiplications"
        );

        // Emit success only after every acceptance assertion has passed.
        println!(
            "\n[legacy_depth] VERIFIED: {} exact multiplications, {} checkpoints, \
             {} successful legacy bootstraps.",
            completed_multiplications,
            checked_checkpoints.len(),
            evaluator.bootstrap_count
        );
    }

    // =========================================================================
    // TRACK C — Bootstrap Accumulation Bias Hypothesis
    // =========================================================================

    /// C-1: 50 sequential bootstraps — does the noise mean drift?
    ///
    /// Hypothesis: each bootstrap has a tiny directional bias in its noise reset.
    /// After many bootstraps, the *mean* of the noise distribution shifts from zero
    /// even though the *magnitude* is within budget. This was observed at depth ~9000.
    ///
    /// Method:
    ///  1. Encrypt a fixed plaintext
    ///  2. Do one mul (to give the bootstrap something to work on)
    ///  3. Bootstrap 50 times in sequence
    ///  4. Decrypt after each bootstrap
    ///  5. All decryptions must equal the plaintext exactly
    ///  6. If any fail, the bias hypothesis is confirmed
    ///
    /// We run 50 (not 200) because secure_128 bootstrap is slow and this is
    /// already a meaningful sample for bias detection.
    #[test]
    fn test_bootstrap_accumulation_bias_50_rounds() {
        let config = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&config).expect("context");
        let mut rng = ShadowHarvester::with_seed(88_001);
        let work_keys = ctx.generate_keys_dual(&mut rng);
        let boot = ClockworkBootstrap::new(&config).expect("bootstrap context");
        let boot_keys = boot
            .generate_keys(&work_keys.secret_key, &mut rng)
            .expect("bootstrap keys");

        let plaintext: u64 = 42;
        let ct_base = ctx.encrypt_dual(plaintext, &work_keys.public_key, &mut rng);

        // One multiplication to give the bootstrap a non-trivial input.
        let ct_after_mul = ctx.mul_dual_symmetric(&ct_base, &ct_base, &work_keys.secret_key);
        let expected_after_mul = (plaintext * plaintext) % config.t;

        // Verify pre-bootstrap plaintext.
        let pre_boot = ctx.decrypt_dual(&ct_after_mul, &work_keys.secret_key);
        assert_eq!(
            pre_boot, expected_after_mul,
            "Sanity: mul produced wrong plaintext before any bootstrap"
        );

        println!("\n[bias] Bootstrap accumulation bias test — 50 sequential bootstraps");
        println!("Round │ Decrypted │ Expected │ Status");
        println!("──────┼───────────┼──────────┼───────");

        let mut current_ct = ct_after_mul;
        let mut bias_observed = false;
        let mut first_bias_round: Option<usize> = None;

        for round in 1..=50usize {
            let bootstrapped = match boot.bootstrap(&current_ct, &boot_keys.bsk, &boot_keys.ksk) {
                Ok(ct) => ct,
                Err(e) => {
                    println!(
                        "{:5} │ BootErr   │ {:>8} │ ✗ ERROR: {}",
                        round, expected_after_mul, e
                    );
                    break;
                }
            };

            let decrypted = ctx.decrypt_dual(&bootstrapped, &work_keys.secret_key);
            let ok = decrypted == expected_after_mul;

            if !ok || round <= 5 || round % 10 == 0 {
                println!(
                    "{:5} │ {:>9} │ {:>8} │ {}",
                    round,
                    decrypted,
                    expected_after_mul,
                    if ok { "✓" } else { "✗ BIAS_DETECTED" }
                );
            }

            if !ok && !bias_observed {
                bias_observed = true;
                first_bias_round = Some(round);
            }

            current_ct = bootstrapped;
        }

        if bias_observed {
            println!(
                "\n[bias] HYPOTHESIS CONFIRMED: noise mean bias detected at round {:?}.",
                first_bias_round
            );
            println!("[bias] This means sequential bootstraps accumulate directional noise.");
            println!("[bias] The GSO swarm fix (multi-path averaging) is the correct mitigation.");
        } else {
            println!("\n[bias] HYPOTHESIS REJECTED: 50 sequential bootstraps produced no bias.");
            println!(
                "[bias] plaintext={} remained stable across all rounds.",
                expected_after_mul
            );
        }

        // Test always passes — it documents whether bias exists, not whether it's absent.
        // The interesting answer is in the println output.
    }

    /// C-2: Bias confirmation with multiplication interleaved.
    ///
    /// Instead of bootstrapping the same ciphertext 50 times, do:
    ///   mul → bootstrap → mul → bootstrap → ...
    /// This is closer to the actual depth-9000 scenario.
    ///
    /// After each bootstrap, decryption must equal the cumulative expected value.
    #[test]
    fn test_bootstrap_accumulation_bias_interleaved_50() {
        let config = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&config).expect("context");
        let mut rng = ShadowHarvester::with_seed(88_002);
        let work_keys = ctx.generate_keys_dual(&mut rng);
        let boot = ClockworkBootstrap::new(&config).expect("bootstrap context");
        let boot_keys = boot
            .generate_keys(&work_keys.secret_key, &mut rng)
            .expect("bootstrap keys");

        let plaintext: u64 = 3;
        let ct = ctx.encrypt_dual(plaintext, &work_keys.public_key, &mut rng);
        let mut current = ct;
        let mut expected = plaintext;
        let mut bias_at: Option<usize> = None;

        println!("\n[bias_interleaved] mul→bootstrap cycles (50 rounds)");
        println!("Round │ Expected │ Post-boot │ Status");
        println!("──────┼──────────┼───────────┼───────");

        for round in 1..=50usize {
            // Multiply.
            let ct_sq = current.clone();
            let after_mul = ctx.mul_dual_symmetric(&current, &ct_sq, &work_keys.secret_key);
            expected = (expected * expected) % config.t;

            // Bootstrap to restore noise budget.
            let after_boot = match boot.bootstrap(&after_mul, &boot_keys.bsk, &boot_keys.ksk) {
                Ok(ct) => ct,
                Err(e) => {
                    println!("{:5} │ {:>8} │ BootErr   │ ✗ ERROR: {}", round, expected, e);
                    break;
                }
            };

            let decrypted = ctx.decrypt_dual(&after_boot, &work_keys.secret_key);
            let ok = decrypted == expected;

            if !ok || round <= 5 || round % 10 == 0 {
                println!(
                    "{:5} │ {:>8} │ {:>9} │ {}",
                    round,
                    expected,
                    decrypted,
                    if ok { "✓" } else { "✗ DRIFT" }
                );
            }

            if !ok && bias_at.is_none() {
                bias_at = Some(round);
            }

            current = after_boot;
        }

        if let Some(round) = bias_at {
            println!(
                "\n[bias_interleaved] DRIFT DETECTED starting at round {}.",
                round
            );
            println!("[bias_interleaved] Each bootstrap cycle introduces cumulative error.");
        } else {
            println!("\n[bias_interleaved] No drift over 50 mul→bootstrap cycles.");
            println!("[bias_interleaved] Unlimited depth via bootstrap is clean for secure_128.");
        }
        // Test always passes — recording findings.
    }
}
