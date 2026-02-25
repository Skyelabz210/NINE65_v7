use nine65::params::secure_configs::SecureConfig;
use nine65::ops::rns_fhe::RNSFHEContext;
use nine65::entropy::ShadowHarvester;

#[test]
fn test_anchor_capacity_drift_secure_256() {
    // secure_256 has large N and Q, which should trigger the anchor drift diagnostic
    let config = SecureConfig::secure_256().into_config();
    let mut ctx = RNSFHEContext::try_new(&config).expect("Context");
    ctx.set_diagnostics(true);

    let mut rng = ShadowHarvester::with_seed(42);
    // Use symmetric key generation for speed
    let keys = ctx.generate_keys_dual(&mut rng);

    let ct1 = ctx.encrypt_dual(2, &keys.public_key, &mut rng);
    let ct2 = ctx.encrypt_dual(3, &keys.public_key, &mut rng);

    // This SHOULD trigger a diagnostic warning if A is too small for Q^2 * N
    // For secure_256: log2(N) + 2*log2(Q) = 14 + 2*(203) ≈ 420 bits (roughly, using SecureConfig values)
    // M * A capacity: 203 + 158 = 361 bits.
    // 420 > 361.

    // In public mode it would return Err.
    // Let's use public mode to confirm the error.
    let full_keys = ctx.generate_keys_dual_full(&mut rng);
    let result = ctx.mul_dual_public(&ct1, &ct2, &full_keys.eval_key);

    assert!(result.is_err(), "secure_256 must trigger capacity drift error in public mode");
    println!("Caught expected drift error: {:?}", result.err());
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
    assert!(result.is_ok(), "secure_128 should be safe from anchor drift: {:?}", result.err());

    let decrypted = ctx.decrypt_dual(&result.unwrap(), &full_keys.secret_key);
    assert_eq!(decrypted, 6);
}
