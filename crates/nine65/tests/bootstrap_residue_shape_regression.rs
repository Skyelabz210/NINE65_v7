//! Legacy Clockwork refusal must preserve its input plaintext and residue shape.
//! The separate working research backend is described in docs/PUBLIC_REFRESH_STATUS.md.

use nine65::entropy::ShadowHarvester;
use nine65::ops::bootstrap::ClockworkBootstrap;
use nine65::ops::rns_fhe::{DualRNSCiphertext, RNSFHEContext};
use nine65::params::secure_configs::SecureConfig;

fn assert_ciphertext_shape(
    ciphertext: &DualRNSCiphertext,
    n: usize,
    main_lanes: usize,
    anchor_lanes: usize,
) {
    assert_eq!(ciphertext.c0.n, n);
    assert_eq!(ciphertext.c1.n, n);
    assert_eq!(ciphertext.c0.main.len(), main_lanes);
    assert_eq!(ciphertext.c1.main.len(), main_lanes);
    assert_eq!(ciphertext.c0.anchor.len(), anchor_lanes);
    assert_eq!(ciphertext.c1.anchor.len(), anchor_lanes);

    for lane in ciphertext.c0.main.iter().chain(&ciphertext.c1.main) {
        assert_eq!(lane.len(), n);
    }
    for lane in ciphertext.c0.anchor.iter().chain(&ciphertext.c1.anchor) {
        assert_eq!(lane.len(), n);
    }
}

#[ignore = "Historical legacy Clockwork success claim; its component-rounding path remains fail-closed. See docs/PUBLIC_REFRESH_STATUS.md"]
#[test]
fn circular_bootstrap_preserves_plaintext_and_dual_rns_shape() {
    let config = SecureConfig::secure_128_deep().into_config();
    let context = RNSFHEContext::try_new(&config).expect("valid work context");
    let bootstrap = ClockworkBootstrap::new(&config).expect("valid bootstrap context");
    let mut rng = ShadowHarvester::with_seed(0xC12A_0001);
    let keys = context.generate_keys_dual_full(&mut rng);
    let bootstrap_keys = bootstrap
        .generate_keys(&keys.secret_key, &mut rng)
        .expect("bootstrap key generation");

    let message = 37u64;
    let ciphertext = context.encrypt_dual(message, &keys.public_key, &mut rng);
    let anchor_lanes = context.dual_rns.anchor.primes.len();

    assert_ciphertext_shape(&ciphertext, config.n, config.primes.len(), anchor_lanes);
    assert_eq!(context.decrypt_dual(&ciphertext, &keys.secret_key), message);

    let refreshed = bootstrap
        .bootstrap(&ciphertext, &bootstrap_keys.bsk, &bootstrap_keys.ksk)
        .expect("circular bootstrap must succeed");

    assert_ciphertext_shape(&refreshed, config.n, config.primes.len(), anchor_lanes);
    assert_eq!(refreshed.level, config.primes.len());
    assert_eq!(context.decrypt_dual(&refreshed, &keys.secret_key), message);
}

#[ignore = "Historical legacy Clockwork success claim; its component-rounding path remains fail-closed. See docs/PUBLIC_REFRESH_STATUS.md"]
#[test]
fn bootstrap_preserves_zero_and_plaintext_boundary_values() {
    let config = SecureConfig::secure_128_deep().into_config();
    let context = RNSFHEContext::try_new(&config).expect("valid work context");
    let bootstrap = ClockworkBootstrap::new(&config).expect("valid bootstrap context");
    let mut rng = ShadowHarvester::with_seed(0xC12A_0002);
    let keys = context.generate_keys_dual_full(&mut rng);
    let bootstrap_keys = bootstrap
        .generate_keys(&keys.secret_key, &mut rng)
        .expect("bootstrap key generation");

    for message in [0u64, 1, config.t - 1] {
        let ciphertext = context.encrypt_dual(message, &keys.public_key, &mut rng);
        let refreshed = bootstrap
            .bootstrap(&ciphertext, &bootstrap_keys.bsk, &bootstrap_keys.ksk)
            .expect("bootstrap must succeed on public boundary vectors");
        assert_eq!(context.decrypt_dual(&refreshed, &keys.secret_key), message);
    }
}

#[test]
fn legacy_refresh_refuses_without_changing_input_plaintext_or_residue_shape() {
    let config = SecureConfig::secure_128_deep().into_config();
    let context = RNSFHEContext::try_new(&config).unwrap();
    let bootstrap = ClockworkBootstrap::new(&config).unwrap();
    let mut rng = ShadowHarvester::with_seed(0xC12A_0003);
    let keys = context.generate_keys_dual(&mut rng);
    let refresh_keys = bootstrap.generate_keys(&keys.secret_key, &mut rng).unwrap();
    let ciphertext = context.encrypt_dual(37, &keys.public_key, &mut rng);
    let original = ciphertext.clone();
    let result = bootstrap.bootstrap(&ciphertext, &refresh_keys.bsk, &refresh_keys.ksk);
    assert!(matches!(result,
        Err(nine65::errors::Nine65Error::BootstrapFailed { reason })
        if reason.contains("legacy Clockwork")
    ));
    assert_ciphertext_shape(
        &ciphertext,
        config.n,
        config.primes.len(),
        context.dual_rns.anchor.primes.len(),
    );
    assert_eq!(ciphertext.level, original.level);
    assert_eq!(ciphertext.c0.main, original.c0.main);
    assert_eq!(ciphertext.c0.anchor, original.c0.anchor);
    assert_eq!(ciphertext.c1.main, original.c1.main);
    assert_eq!(ciphertext.c1.anchor, original.c1.anchor);
    assert_eq!(context.decrypt_dual(&ciphertext, &keys.secret_key), 37);
}
