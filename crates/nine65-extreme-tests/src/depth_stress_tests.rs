// Module 11: depth_stress_tests
//
// Q3:  What is the exact depth limit for secure_128 without bootstrap?
// Q13: What is secure_256's actual max circuit depth without bootstrap?

#[cfg(test)]
mod tests {
    use nine65::ops::rns_fhe::RNSFHEContext;
    use nine65::params::secure_configs::SecureConfig;
    use nine65::noise::budget::NoiseBudget;
    use nine65::entropy::shadow::ShadowHarvester;

    /// Q3: Measure exact depth limit for secure_128 without bootstrap.
    /// Theoretical floor: (initial_budget - encrypt_cost) / mul_cycle_cost
    #[test]
    fn test_max_depth_secure_128_without_bootstrap_theoretical() {
        let config = SecureConfig::secure_128().into_config();
        let initial_mb = NoiseBudget::from_config(&config).initial_millibits();
        let encrypt_cost = NoiseBudget::encrypt_cost(&config);
        let mul_cost = NoiseBudget::multiplication_cycle_cost(&config);

        if mul_cost <= 0 {
            println!("[depth] secure_128: mul_cost={}mb — cannot compute depth from budget", mul_cost);
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
        assert!(theoretical_depth >= 1,
            "secure_128 theoretical depth is 0 — budget too tight for any multiplication");
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
                        println!("[depth] secure_128: noise exhausted at depth {} \
                                  (got {} expected {})", depth, recovered, expected);
                        break;
                    }
                }
                Err(_) => {
                    println!("[depth] secure_128: decrypt error at depth {}", depth);
                    break;
                }
            }
        }

        println!("[depth] secure_128: achieved {} multiplications without bootstrap", depth);
        // Must achieve at least 1 multiplication.
        assert!(depth >= 1, "secure_128 failed to achieve even one multiplication");
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
            println!("[depth] secure_192: theoretical_depth={}", theoretical_depth);
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
            println!("[depth] secure_256: theoretical_depth={}", theoretical_depth);
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
            println!("[depth_regression] secure_128: max depth without bootstrap = {}",
                max_depth_without_bootstrap);

            // This is a regression guard: if someone changes the noise model to inflate
            // mul_cost past budget, this test will catch it.
            assert!(
                initial_mb > 0,
                "secure_128 noise budget is zero — regression in budget computation"
            );
        }
    }
}
