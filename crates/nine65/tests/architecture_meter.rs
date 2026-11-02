#![cfg(feature = "architecture-meter")]
use nine65::entropy::ShadowHarvester;
use nine65::ops::rns_fhe::RNSFHEContext;
use nine65::params::SecureConfig;

#[test]
fn actual_public_product_and_decode_record_permitted_reconstruction() {
    let mut config = SecureConfig::secure_128().into_config();
    config.n = 8;
    config.security_bits = 0;
    let ctx = RNSFHEContext::try_new(&config).unwrap();
    let mut rng = ShadowHarvester::with_seed(0x41324d45544552);
    let keys = ctx.generate_keys(&mut rng);
    let ct = ctx.encrypt(3, &keys.public_key, &mut rng);
    let exact = ctx.try_exact_evaluator().unwrap();
    let key = exact.generate_hybrid_gadget_key_with_rng(&keys.secret_key, &mut rng);
    let product = exact.try_mul_exact(&ct, &ct, &key).unwrap();
    let before = ctx.architecture_snapshot();
    assert_eq!(ctx.decrypt(&product, &keys.secret_key), 9);
    let after = ctx.architecture_snapshot();
    assert_eq!(after.user_io_projections, before.user_io_projections + 1);
    assert!(after.crt_reconstructions > before.crt_reconstructions);
    assert!(ctx.assert_no_synthetic_emissions().is_ok());
    let dual_keys = ctx.generate_keys_dual_full(&mut rng);
    let dual = ctx.encrypt_dual(7, &dual_keys.public_key, &mut rng);
    let before = ctx.architecture_snapshot();
    assert_eq!(ctx.decrypt_dual(&dual, &dual_keys.secret_key), 7);
    assert_eq!(
        ctx.architecture_snapshot().user_io_projections,
        before.user_io_projections + 1
    );
    let before = ctx.architecture_snapshot();
    let residues: Vec<_> = ctx.dual_rns.anchor.primes[..2]
        .iter()
        .map(|&p| 5 % p)
        .collect();
    assert_eq!(ctx.dual_rns.anchor.to_int_level(&residues, 2), 5);
    assert_eq!(
        ctx.architecture_snapshot().crt_reconstructions,
        before.crt_reconstructions + 1
    );
    let other = RNSFHEContext::try_new(&config).unwrap();
    assert_eq!(other.architecture_snapshot().crt_reconstructions, 0);
}
