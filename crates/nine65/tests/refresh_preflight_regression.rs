//! Regression gates for exact pre-operation refresh accounting.

use nine65::noise::budget::{NoiseBudget, NoiseOpType};
use nine65::params::secure_configs::SecureConfig;

#[test]
fn secure_128_deep_requires_refresh_before_third_tracked_multiplication() {
    let config = SecureConfig::secure_128_deep().into_config();
    let mut budget = NoiseBudget::from_config(&config);
    let operation_cost =
        NoiseBudget::mul_ct_cost(&config) + NoiseBudget::relin_cost(&config);

    assert_eq!(budget.initial_millibits(), 92_000);
    assert_eq!(operation_cost, 45_000);
    assert!(budget.can_perform(operation_cost));

    budget
        .consume(NoiseOpType::MulCt, operation_cost)
        .expect("first multiplication must be funded");
    assert_eq!(budget.remaining_millibits(), 47_000);
    assert!(budget.can_perform(operation_cost));

    budget
        .consume(NoiseOpType::MulCt, operation_cost)
        .expect("second multiplication must be funded");
    assert_eq!(budget.remaining_millibits(), 2_000);
    assert!(!budget.can_perform(operation_cost));
    assert!(budget.should_bootstrap(250));

    budget.reset_after_bootstrap(&config);
    assert_eq!(budget.remaining_millibits(), 78_000);
    assert!(budget.can_perform(operation_cost));
}

#[test]
fn threshold_crossing_is_checked_before_operation() {
    let config = SecureConfig::secure_128_deep().into_config();
    let mut budget = NoiseBudget::from_config(&config);
    let operation_cost =
        NoiseBudget::mul_ct_cost(&config) + NoiseBudget::relin_cost(&config);

    budget
        .consume(NoiseOpType::MulCt, operation_cost)
        .expect("first multiplication must be funded");
    assert!(!budget.should_bootstrap(250));

    budget
        .consume(NoiseOpType::MulCt, operation_cost)
        .expect("second multiplication must be funded");
    assert!(budget.should_bootstrap(250));
    assert!(!budget.can_perform(operation_cost));
}
