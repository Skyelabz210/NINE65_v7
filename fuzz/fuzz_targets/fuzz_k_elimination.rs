#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use nine65::arithmetic::k_elimination::{KElimination, KElimConfig};

#[derive(Arbitrary, Debug)]
struct KElimInput {
    // Values in the dual-codex representation
    v_alpha: u64,
    v_beta: u64,
    divisor: u64,
    config_choice: u8,
}

// Fuzz K-Elimination exact division
// This verifies that:
// - No panics on any input combination
// - Result is mathematically correct when divisor divides the full value
fuzz_target!(|input: KElimInput| {
    // Select configuration based on fuzzer input
    let config = match input.config_choice % 4 {
        0 => KElimConfig::Minimal,
        1 => KElimConfig::Standard,
        2 => KElimConfig::Extended,
        _ => KElimConfig::Maximum,
    };

    let ke = KElimination::from_config(config);

    // Get the capacity limits (these are public fields)
    let alpha_cap = ke.alpha_cap;
    let beta_cap = ke.beta_cap;

    // Reduce inputs to valid range
    let v_alpha = (input.v_alpha as u128) % alpha_cap;
    let v_beta = (input.v_beta as u128) % beta_cap;

    // Ensure divisor is non-zero and reasonable
    let divisor = if input.divisor == 0 { 1 } else { input.divisor };

    // Compute k = (v_beta - v_alpha) * alpha_inv_beta mod beta_cap
    // Then full_value = v_alpha + k * alpha_cap
    let k = if v_beta >= v_alpha {
        ((v_beta - v_alpha) * ke.alpha_inv_beta) % beta_cap
    } else {
        ((beta_cap + v_beta - v_alpha) * ke.alpha_inv_beta) % beta_cap
    };
    let full_value = v_alpha + k * alpha_cap;

    // Only test exact division when divisor actually divides the value
    if full_value % (divisor as u128) == 0 && divisor > 0 {
        // Test exact division - should not panic
        let result = ke.exact_divide(v_alpha, v_beta, divisor);

        // Verify correctness
        let expected = full_value / (divisor as u128);
        assert_eq!(
            result, expected,
            "K-elimination exact_divide failed: {} / {} = {} (expected {})",
            full_value, divisor, result, expected
        );

        // Also test that checked version returns Some
        let checked_result = ke.exact_divide_checked(v_alpha, v_beta, divisor);
        assert!(checked_result.is_some(), "exact_divide_checked returned None for valid division");
        assert_eq!(checked_result.unwrap(), expected);
    }
});
