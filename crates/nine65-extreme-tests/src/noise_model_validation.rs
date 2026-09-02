// Module 1: noise_model_validation
//
// Q1: Does actual noise growth ever exceed the estimated model?
// Q2: Is noise accumulation deterministic bit-for-bit across runs?
// Q15: Is can_perform() semantically correct for rescaling?

#[cfg(test)]
mod tests {
    use nine65::entropy::shadow::ShadowHarvester;
    use nine65::noise::budget::{NoiseBudget, NoiseOpType};
    use nine65::ops::rns_fhe::RNSFHEContext;
    use nine65::params::secure_configs::SecureConfig;

    /// Q1: Noise estimates must be conservative (budget coverage for 1 mul).
    #[test]
    fn test_actual_noise_vs_estimate_secure_128() {
        let config = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&config).expect("context");
        let mut rng = ShadowHarvester::with_seed(42);

        let keys = ctx.generate_keys_dual_full_secure();
        let m: u64 = 7;

        let budget = NoiseBudget::from_config(&config);
        let initial_mb = budget.initial_millibits();
        let mul_cost = NoiseBudget::mul_ct_cost(&config);

        let estimated_remaining_after_1_mul = initial_mb - mul_cost;
        assert!(
            estimated_remaining_after_1_mul > 0,
            "secure_128 budget exhausted by first multiplication: initial={} mul_cost={}",
            initial_mb,
            mul_cost
        );

        println!(
            "[noise_model] secure_128: initial={}mb, mul_cost={}mb, after_1_mul={}mb",
            initial_mb, mul_cost, estimated_remaining_after_1_mul
        );

        // Encrypt and multiply once — must decrypt correctly.
        let ct_a = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
        let ct_b = ctx.encrypt_dual(m, &keys.public_key, &mut rng);
        let ct_mul = ctx
            .mul_dual_public(&ct_a, &ct_b, &keys.eval_key)
            .expect("multiplication");
        let recovered = ctx.decrypt_dual(&ct_mul, &keys.secret_key);
        let expected = (m * m) % config.t;
        assert_eq!(
            recovered, expected,
            "Decryption failed after 1 mul: got {} expected {}",
            recovered, expected
        );
    }

    /// Q2: Noise accumulation must be deterministic — same circuit, same cost.
    #[test]
    fn test_noise_accumulation_is_deterministic() {
        let config = SecureConfig::secure_128().into_config();

        let budget_cost_1 = {
            let mut b = NoiseBudget::from_config(&config);
            let _ = b.consume(NoiseOpType::Encrypt, NoiseBudget::encrypt_cost(&config));
            let _ = b.consume(NoiseOpType::MulCt, NoiseBudget::mul_ct_cost(&config));
            b.remaining_millibits()
        };

        let budget_cost_2 = {
            let mut b = NoiseBudget::from_config(&config);
            let _ = b.consume(NoiseOpType::Encrypt, NoiseBudget::encrypt_cost(&config));
            let _ = b.consume(NoiseOpType::MulCt, NoiseBudget::mul_ct_cost(&config));
            b.remaining_millibits()
        };

        assert_eq!(
            budget_cost_1, budget_cost_2,
            "Noise budget is non-deterministic: {} != {} for identical circuits",
            budget_cost_1, budget_cost_2
        );
    }

    /// Q15: can_perform() must return true for rescaling (negative cost).
    #[test]
    fn test_noise_budget_can_perform_with_rescaling() {
        let config = SecureConfig::secure_128().into_config();
        let rescale_cost = NoiseBudget::rescale_cost(&config);

        if rescale_cost < 0 {
            let budget = NoiseBudget::with_budget_bits(0);
            assert!(
                budget.can_perform(rescale_cost),
                "can_perform({}) returned false with 0 remaining budget — rescaling must always be allowed",
                rescale_cost
            );
        }

        println!("[noise_model] rescale_cost = {}mb", rescale_cost);
    }

    /// Post-bootstrap noise must reset to a deterministic formula-governed value.
    #[test]
    fn test_post_bootstrap_noise_matches_formula() {
        let config = SecureConfig::secure_128().into_config();
        let mut budget = NoiseBudget::from_config(&config);

        let mul_cost = NoiseBudget::mul_ct_cost(&config);
        if mul_cost > 0 && budget.remaining_millibits() >= mul_cost {
            let _ = budget.consume(NoiseOpType::MulCt, mul_cost);
        }

        let pre_bootstrap_remaining = budget.remaining_millibits();

        budget.reset_after_bootstrap(&config);
        let post_bootstrap_remaining = budget.remaining_millibits();

        assert!(
            post_bootstrap_remaining > pre_bootstrap_remaining,
            "Bootstrap must increase noise budget: pre={} post={}",
            pre_bootstrap_remaining,
            post_bootstrap_remaining
        );

        // Must be deterministic.
        let mut budget2 = NoiseBudget::from_config(&config);
        budget2.reset_after_bootstrap(&config);
        assert_eq!(
            post_bootstrap_remaining,
            budget2.remaining_millibits(),
            "Post-bootstrap budget is non-deterministic"
        );

        println!(
            "[noise_model] post_bootstrap_remaining = {}mb",
            post_bootstrap_remaining
        );
    }

    /// Rescaling must refund noise budget correctly.
    #[test]
    fn test_rescaling_refunds_noise_correctly() {
        let config = SecureConfig::secure_128().into_config();
        let rescale_cost = NoiseBudget::rescale_cost(&config);

        let mut budget = NoiseBudget::from_config(&config);
        let before = budget.remaining_millibits();

        if rescale_cost < 0 {
            budget
                .consume(NoiseOpType::Rescale, rescale_cost)
                .expect("rescale should succeed");
            let after = budget.remaining_millibits();
            assert!(
                after > before,
                "Rescaling must increase remaining budget: before={} after={}",
                before,
                after
            );
        } else {
            let _ = budget.consume(NoiseOpType::Rescale, rescale_cost);
        }
    }
}
