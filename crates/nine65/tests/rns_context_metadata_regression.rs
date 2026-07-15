//! Compile-time and runtime contract for exact RNS context metadata.

use nine65::ops::rns_fhe::{MulRoute, RNSFHEContext};
use nine65::params::secure_configs::SecureConfig;
use nine65::params::FHEConfig;

#[test]
fn context_uses_exact_product_bit_length_not_lane_width_sum() {
    // Both moduli are NTT-compatible for N=8192. Their individual widths sum
    // to 58, while the exact product has bit length 57.
    let config = FHEConfig {
        n: 8192,
        primes: vec![754_974_721, 167_772_161],
        q: 754_974_721,
        t: 65_537,
        eta: 3,
        security_bits: 0,
        name: "exact_q_bits_regression",
    };
    let lane_width_sum: usize = config
        .primes
        .iter()
        .map(|prime| (64 - prime.leading_zeros()) as usize)
        .sum();
    assert_eq!(lane_width_sum, 58);
    assert_eq!(config.rns_product_bit_length(), 57);

    let context = RNSFHEContext::try_new(&config).expect("valid exact RNS context");
    assert_eq!(context.q_bits, 57);
    assert_ne!(context.q_bits, lane_width_sum);
    assert_eq!(context.q_product_checked, config.try_rns_product());
    assert_eq!(context.q_product_limbs, config.rns_product_limbs());
}

#[test]
fn context_represents_large_q_without_zero_sentinel() {
    let config = SecureConfig::secure_256().into_config();
    assert!(config.try_rns_product().is_none());
    assert!(config.rns_product_bit_length() > 128);

    let context = RNSFHEContext::try_new(&config).expect("large exact RNS context");
    assert_eq!(context.q_product_checked, None);
    assert_eq!(context.q_product_limbs, config.rns_product_limbs());
    assert_eq!(
        context.q_bits,
        config.rns_product_bit_length() as usize
    );
    assert_ne!(context.q_product_limbs, vec![0]);
    assert_eq!(context.mul_route(), MulRoute::KElimDual);
}

#[test]
fn fitting_scalar_projection_matches_exact_limbs() {
    let config = SecureConfig::secure_128().into_config();
    let expected = config
        .try_rns_product()
        .expect("secure_128 product must fit in u128");
    let context = RNSFHEContext::try_new(&config).expect("valid exact RNS context");

    assert_eq!(context.q_product_checked, Some(expected));
    assert_eq!(context.q_product_limbs, config.rns_product_limbs());
    assert_eq!(context.q_bits, config.rns_product_bit_length() as usize);
}
