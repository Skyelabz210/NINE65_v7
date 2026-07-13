//! Contract for exact main/anchor product metadata in `DualRNSContext`.

use nine65::arithmetic::DualRNSContext;
use nine65::params::secure_configs::SecureConfig;

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

fn bit_length(limbs: &[u64]) -> u32 {
    for index in (0..limbs.len()).rev() {
        if limbs[index] != 0 {
            return index as u32 * 64 + (64 - limbs[index].leading_zeros());
        }
    }
    0
}

fn checked_product(factors: &[u64]) -> Option<u128> {
    factors
        .iter()
        .try_fold(1u128, |product, &factor| product.checked_mul(factor as u128))
}

#[test]
fn canonical_anchor_family_has_exact_non_sentinel_metadata() {
    let config = SecureConfig::secure_128_deep().into_config();
    let anchors = DualRNSContext::canonical_anchor_primes_for_n(config.n);
    let context = DualRNSContext::new(config.primes.clone(), anchors.clone(), config.n);

    let expected_anchor_limbs = exact_product_limbs(&anchors);
    assert!(checked_product(&anchors).is_none());
    assert!(bit_length(&expected_anchor_limbs) > 128);

    assert_eq!(context.anchor_product_checked, None);
    assert_eq!(context.anchor_product_limbs, expected_anchor_limbs);
    assert_eq!(
        context.anchor_product_bit_length,
        bit_length(&context.anchor_product_limbs)
    );
    assert_ne!(context.anchor_product_limbs, vec![0]);
}

#[test]
fn secure_256_main_family_has_exact_non_sentinel_metadata() {
    let config = SecureConfig::secure_256().into_config();
    let anchors = DualRNSContext::canonical_anchor_primes_for_n(config.n);
    let context = DualRNSContext::new(config.primes.clone(), anchors, config.n);

    let expected_main_limbs = exact_product_limbs(&config.primes);
    assert!(checked_product(&config.primes).is_none());
    assert!(bit_length(&expected_main_limbs) > 128);

    assert_eq!(context.main_product_checked, None);
    assert_eq!(context.main_product_limbs, expected_main_limbs);
    assert_eq!(
        context.main_product_bit_length,
        bit_length(&context.main_product_limbs)
    );
    assert_ne!(context.main_product_limbs, vec![0]);
}

#[test]
fn fitting_main_family_matches_checked_scalar_projection() {
    let config = SecureConfig::secure_128().into_config();
    let anchors = DualRNSContext::canonical_anchor_primes_for_n(config.n);
    let context = DualRNSContext::new(config.primes.clone(), anchors, config.n);

    let expected = checked_product(&config.primes).expect("three-lane product must fit");
    assert_eq!(context.main_product_checked, Some(expected));
    assert_eq!(context.main_product_limbs, exact_product_limbs(&config.primes));
    assert_eq!(
        context.main_product_bit_length,
        bit_length(&context.main_product_limbs)
    );
}
