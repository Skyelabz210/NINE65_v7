use nine65::arithmetic::DualRNSContext;
use nine65::entropy::ShadowHarvester;
use nine65::noise::boundary::rns_product_bit_length;
use nine65::ops::rns_fhe::RNSFHEContext;
use nine65::params::secure_configs::SecureConfig;

/// With the 10-prime anchor basis for n=16384 (A ≈ 315 bits), secure_256
/// ct×ct multiplication has capacity M×A ≈ 490 bits > N×Q² ≈ 364 bits (74%
/// utilization, below the 80% strict gate) and must succeed with exact
/// plaintext recovery. Under the previous 5-prime basis (A ≈ 157 bits,
/// M×A ≈ 332 bits) this same operation returned a loud capacity-drift error —
/// that arithmetic is pinned by
/// `test_five_anchor_basis_would_still_be_insufficient_for_secure_256` below.
#[test]
fn test_secure_256_mul_succeeds_with_10_anchor_basis() {
    let config = SecureConfig::secure_256().into_config();
    let mut ctx = RNSFHEContext::try_new(&config).expect("Context");
    ctx.set_diagnostics(true);

    let mut rng = ShadowHarvester::with_seed(42);
    let full_keys = ctx.generate_keys_dual_full(&mut rng);

    let ct1 = ctx.encrypt_dual(2, &full_keys.public_key, &mut rng);
    let ct2 = ctx.encrypt_dual(3, &full_keys.public_key, &mut rng);

    let result = ctx.mul_dual_public(&ct1, &ct2, &full_keys.eval_key);
    assert!(
        result.is_ok(),
        "secure_256 mul must succeed with the 10-anchor basis: {:?}",
        result.err()
    );

    let decrypted = ctx.decrypt_dual(&result.unwrap(), &full_keys.secret_key);
    assert_eq!(decrypted, 6, "secure_256 ct×ct mul must decrypt exactly");
}

/// Regression pin for the capacity arithmetic itself: the first 5 canonical
/// anchors do NOT provide enough capacity for secure_256's tensor product,
/// while the full 7-anchor set does. If either side of this inequality ever
/// flips silently (config change, anchor change), this fails loudly.
#[test]
fn test_five_anchor_basis_would_still_be_insufficient_for_secure_256() {
    let sc = SecureConfig::secure_256();
    let n = sc.config.n;
    let log2_n = (usize::BITS - n.leading_zeros() - 1) as u32;
    let q_bits = rns_product_bit_length(&sc.config.primes);
    let required_bits = log2_n + 2 * q_bits;

    let anchors = DualRNSContext::canonical_anchor_primes_for_n(n);
    assert_eq!(
        anchors.len(),
        10,
        "n=16384 canonical basis must have 10 anchors"
    );

    let a5_bits = rns_product_bit_length(&anchors[..5]);
    let a_full_bits = rns_product_bit_length(&anchors);

    assert!(
        q_bits + a5_bits < required_bits,
        "5-anchor capacity ({} bits) unexpectedly covers secure_256 ({} bits required)",
        q_bits + a5_bits,
        required_bits
    );
    // Must not just fit, but stay below the 80% strict gate that public-mode
    // multiplication enforces (`to_result(true)` errors on the >= 80% warning
    // tier, not just the >= 90% critical tier — a 7-anchor basis at 92% and
    // an 8-anchor basis at 85% both still fail public mode).
    assert!(
        (required_bits * 100) / (q_bits + a_full_bits) < 80,
        "10-anchor capacity ({} bits) must keep secure_256 ({} bits required) below \
         80% utilization",
        q_bits + a_full_bits,
        required_bits
    );
}

#[test]
fn test_anchor_capacity_safe_secure_128() {
    let config = SecureConfig::secure_128().into_config();
    let mut ctx = RNSFHEContext::try_new(&config).expect("Context");
    ctx.set_diagnostics(true);

    let mut rng = ShadowHarvester::with_seed(42);
    let full_keys = ctx.generate_keys_dual_full(&mut rng);

    let ct1 = ctx.encrypt_dual(2, &full_keys.public_key, &mut rng);
    let ct2 = ctx.encrypt_dual(3, &full_keys.public_key, &mut rng);

    let result = ctx.mul_dual_public(&ct1, &ct2, &full_keys.eval_key);
    assert!(
        result.is_ok(),
        "secure_128 should be safe from anchor drift: {:?}",
        result.err()
    );

    let decrypted = ctx.decrypt_dual(&result.unwrap(), &full_keys.secret_key);
    assert_eq!(decrypted, 6);
}
