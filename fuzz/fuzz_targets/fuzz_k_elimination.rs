#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use nine65::arithmetic::k_elimination::{KElimConfig, KElimination};

#[derive(Arbitrary, Debug)]
struct KElimInput {
    // Values in the dual-codex representation
    v_alpha: u64,
    v_beta: u64,
    divisor: u64,
    config_choice: u8,
}

fn add_mod(a: u128, b: u128, modulus: u128) -> u128 {
    debug_assert!(a < modulus && b < modulus);
    if a >= modulus - b {
        a - (modulus - b)
    } else {
        a + b
    }
}

fn mul_mod(mut a: u128, mut b: u128, modulus: u128) -> u128 {
    debug_assert!(modulus > 0);
    a %= modulus;
    let mut result = 0;
    while b > 0 {
        if b & 1 == 1 {
            result = add_mod(result, a, modulus);
        }
        b >>= 1;
        if b > 0 {
            a = add_mod(a, a, modulus);
        }
    }
    result
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

    // Independently compute the winding with overflow-safe modular
    // multiplication, then keep the scalar oracle within u128. Some
    // configurations have a combined alpha/beta capacity wider than u128,
    // so overflow is a checked refusal.
    let alpha_mod_beta = v_alpha % beta_cap;
    let diff = if v_beta >= alpha_mod_beta {
        v_beta - alpha_mod_beta
    } else {
        beta_cap - (alpha_mod_beta - v_beta)
    };
    let k = mul_mod(diff, ke.alpha_inv_beta, beta_cap);
    let full_value = k
        .checked_mul(alpha_cap)
        .and_then(|lift| v_alpha.checked_add(lift));

    if let Some(full_value) = full_value {
        let validated = ke.exact_divide_validated(v_alpha, v_beta, divisor);
        let checked = ke.exact_divide_checked(v_alpha, v_beta, divisor);
        if full_value % divisor as u128 == 0 {
            let expected = full_value / divisor as u128;
            assert_eq!(validated.unwrap(), expected);
            assert_eq!(checked, Some(expected));
        } else {
            assert!(validated.is_err());
            assert_eq!(checked, None);
        }
    } else {
        assert!(ke.exact_divide_validated(v_alpha, v_beta, divisor).is_err());
        assert_eq!(ke.exact_divide_checked(v_alpha, v_beta, divisor), None);
    }
});
