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

/// Pin a real consequence of the `secure_128` re-cut rather than let it
/// disappear silently: the four-prime chain (M ~= 119 bits) leaves only
/// ~25 bits of margin against the 5-anchor basis's ~276-bit capacity for a
/// single depth-1 `mul_dual_public` (log2(N) + 2*log2(M) ~= 251 bits
/// required), which the strict diagnostics-mode "approaching capacity" gate
/// (>=90%) reports as critical. This is deterministic -- not a seed-unlucky
/// draw -- because the bound this gate checks is a function of the chain
/// lengths alone, not of the sampled coefficients; a 16-seed sweep
/// (1,2,3,7,11,17,23,42,55,100,123,255,555,777,1000,9999) hits it on every
/// seed.
///
/// This is not a correctness regression: `mul_dual_public`'s unconditional
/// gate is the actual overflow tier (>=100%), which this chain clears with
/// room to spare, and the plain (non-diagnostics) path this test's sibling
/// `residue_space_ciphertext.rs` exercises on `secure_128` continues to pass
/// and decrypt exactly. What changed is that `secure_128` now shares
/// `secure_128_deep`'s pre-existing, already-documented thin safety margin
/// (see `docs/LADDER_REMOVAL.md` and the depth2_isolation.rs /
/// `test_mul_dual_symmetric_depth2_secure_128_deep` diagnostics) instead of
/// the wide margin its retired three-prime chain had. If this ever starts
/// passing, the anchor basis or the gate's threshold changed underneath it
/// and that is worth knowing, not something to relax quietly.
#[test]
fn secure_128_now_shares_secure_128_deeps_anchor_capacity_ceiling() {
    let config = SecureConfig::secure_128().into_config();
    let deep_config = SecureConfig::secure_128_deep().into_config();
    assert_eq!(
        config.primes, deep_config.primes,
        "this test's premise is that secure_128 and secure_128_deep are the \
         same chain post-recut; if they diverge, re-measure rather than \
         trusting this pin"
    );

    let mut ctx = RNSFHEContext::try_new(&config).expect("Context");
    ctx.set_diagnostics(true);

    let mut rng = ShadowHarvester::with_seed(42);
    let full_keys = ctx.generate_keys_dual_full(&mut rng);
    let ct1 = ctx.encrypt_dual(2, &full_keys.public_key, &mut rng);
    let ct2 = ctx.encrypt_dual(3, &full_keys.public_key, &mut rng);

    let result = ctx.mul_dual_public(&ct1, &ct2, &full_keys.eval_key);
    assert!(
        result.is_err(),
        "secure_128 unexpectedly cleared the strict anchor-capacity gate; \
         re-measure the margin before trusting this test again"
    );
    let message = result.unwrap_err().to_string();
    assert!(
        message.contains("Capacity utilization"),
        "expected the strict capacity gate's message, got: {message}"
    );
}
