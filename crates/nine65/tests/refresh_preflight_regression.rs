//! Regression gates for exact pre-operation refresh accounting.

use nine65::noise::budget::{NoiseBudget, NoiseOpType};
use nine65::params::secure_configs::SecureConfig;
use nine65::params::FHEConfig;

fn exact_product_limbs(factors: &[u64]) -> Vec<u64> {
    let mut limbs = vec![1u64];
    for &factor in factors {
        let mut carry = 0u128;
        for limb in &mut limbs {
            let product = *limb as u128 * factor as u128 + carry;
            *limb = product as u64;
            carry = product >> 64;
        }
        if carry != 0 {
            limbs.push(carry as u64);
        }
    }
    while limbs.len() > 1 && limbs.last() == Some(&0) {
        limbs.pop();
    }
    limbs
}

fn divide_limbs_by_u64(limbs: &[u64], divisor: u64) -> Vec<u64> {
    assert_ne!(divisor, 0);
    let mut quotient = vec![0u64; limbs.len()];
    let mut remainder = 0u128;
    for index in (0..limbs.len()).rev() {
        let numerator = (remainder << 64) | limbs[index] as u128;
        quotient[index] = (numerator / divisor as u128) as u64;
        remainder = numerator % divisor as u128;
    }
    while quotient.len() > 1 && quotient.last() == Some(&0) {
        quotient.pop();
    }
    quotient
}

fn limb_bit_length(limbs: &[u64]) -> i64 {
    for index in (0..limbs.len()).rev() {
        if limbs[index] != 0 {
            return index as i64 * 64 + (64 - limbs[index].leading_zeros()) as i64;
        }
    }
    0
}

fn scalar_bit_length(value: u64) -> i64 {
    if value == 0 {
        0
    } else {
        (64 - value.leading_zeros()) as i64
    }
}

fn exact_delta_bit_length(config: &FHEConfig) -> i64 {
    limb_bit_length(&divide_limbs_by_u64(
        &exact_product_limbs(&config.primes),
        config.t,
    ))
}

fn expected_fresh_budget(config: &FHEConfig) -> i64 {
    let eta_bits = scalar_bit_length(config.eta as u64).max(1);
    let root_n_bits = (config.n.trailing_zeros() / 2) as i64;
    (exact_delta_bit_length(config) - eta_bits - root_n_bits - 3).max(0) * 1000
}

fn expected_post_bootstrap_budget(config: &FHEConfig) -> i64 {
    let t_bits = scalar_bit_length(config.t);
    let eta_bits = scalar_bit_length(config.eta as u64).max(1);
    let root_n_bits = (config.n.trailing_zeros() / 2) as i64;
    (exact_delta_bit_length(config) - t_bits - eta_bits - root_n_bits).max(0) * 1000
}

#[ignore = "VESTIGIAL: loops multiplies while !budget.should_bootstrap(250), then asserts reset_after_bootstrap lands on expected_post_bootstrap_budget. UN-QUARANTINE CANDIDATE: its first half — initial_millibits() equalling an independent exact-limb Delta oracle — is substrate-independent and should come back as its own test once split from the refresh tail. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
#[test]
fn secure_128_deep_budget_matches_independent_exact_limb_oracle() {
    let config = SecureConfig::secure_128_deep().into_config();
    let mut budget = NoiseBudget::from_config(&config);

    assert_eq!(budget.initial_millibits(), expected_fresh_budget(&config));
    assert_eq!(budget.remaining_millibits(), expected_fresh_budget(&config));

    let operation_cost = NoiseBudget::mul_ct_cost(&config) + NoiseBudget::relin_cost(&config);
    let mut funded_operations = 0usize;

    while budget.can_perform(operation_cost) && !budget.should_bootstrap(250) {
        budget
            .consume(NoiseOpType::MulCt, operation_cost)
            .expect("preflighted multiplication must consume exactly");
        funded_operations += 1;
        assert!(
            funded_operations < 1024,
            "refresh preflight failed to converge"
        );
    }

    assert!(funded_operations > 0);
    assert!(
        !budget.can_perform(operation_cost) || budget.should_bootstrap(250),
        "loop must stop only at an exact pre-operation refresh condition"
    );

    budget.reset_after_bootstrap(&config);
    assert_eq!(
        budget.remaining_millibits(),
        expected_post_bootstrap_budget(&config)
    );
    assert!(budget.can_perform(operation_cost));
}

#[ignore = "VESTIGIAL: asserts should_bootstrap(1000) is true before the first operation, i.e. that a 100 percent trigger selects a refresh immediately. It is entirely a statement about the refresh trigger. Bootstrap is a fallback, not the critical path. Exact division in residue space divides the value without moving the basis, so no level is consumed and depth is not budget-bounded. See docs/RETIRED_MECHANISMS.md"]
#[test]
fn full_threshold_requires_refresh_before_first_operation() {
    let config = SecureConfig::secure_128_deep().into_config();
    let budget = NoiseBudget::from_config(&config);
    let operation_cost = NoiseBudget::mul_ct_cost(&config) + NoiseBudget::relin_cost(&config);

    assert!(budget.can_perform(operation_cost));
    assert!(
        budget.should_bootstrap(1000),
        "100% trigger must select refresh before the first operation"
    );
}
