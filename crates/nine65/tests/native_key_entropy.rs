//! Exercise the native single-modulus key API through a separately linked
//! library. A `--lib` unit test cannot check the release RNG guard: `cfg(test)`
//! deliberately permits deterministic entropy inside that library build.

use nine65::arithmetic::NTTEngine;
use nine65::entropy::ShadowHarvester;
use nine65::errors::Nine65Error;
use nine65::keys::{EvaluationKey, KeySet, PublicKey, SecretKey};
use nine65::ops::{BFVDecryptor, BFVEncoder, BFVEncryptor};
use nine65::params::secure_configs::SecureConfig;
use nine65::params::FHEConfig;

#[cfg(not(debug_assertions))]
fn assert_refused_before_sampling<T>(
    operation: &str,
    generate: impl FnOnce(&mut ShadowHarvester) -> T,
) {
    let mut rng = ShadowHarvester::with_seed(42);
    let mut unchanged = ShadowHarvester::with_seed(42);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| generate(&mut rng)));
    let panic = match result {
        Ok(_) => panic!("{operation} accepted deterministic cryptographic entropy"),
        Err(panic) => panic,
    };
    let message = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .expect("security refusal must explain the rejected operation");
    assert!(message.contains("SECURITY ERROR"), "{message}");
    assert!(message.contains(operation), "{message}");
    assert_eq!(rng.next_u64(), unchanged.next_u64());
}

#[cfg(not(debug_assertions))]
fn assert_error_before_sampling<T>(
    operation: &str,
    generate: impl FnOnce(&mut ShadowHarvester) -> nine65::errors::Nine65Result<T>,
) {
    let mut rng = ShadowHarvester::with_seed(42);
    let mut unchanged = ShadowHarvester::with_seed(42);
    match generate(&mut rng) {
        Err(Nine65Error::ConfigError { message }) => {
            assert!(message.contains("SECURITY ERROR"), "{message}");
            assert!(message.contains(operation), "{message}");
        }
        Err(error) => panic!("wrong refusal for {operation}: {error}"),
        Ok(_) => panic!("{operation} accepted deterministic cryptographic entropy"),
    }
    assert_eq!(rng.next_u64(), unchanged.next_u64());
}

#[cfg(not(debug_assertions))]
#[test]
fn release_secret_key_refuses_shadow_before_sampling() {
    let config = SecureConfig::secure_128().into_config();
    assert_refused_before_sampling("SecretKey::generate", |rng| {
        SecretKey::generate(&config, rng)
    });
}

#[cfg(not(debug_assertions))]
#[test]
fn release_keyset_refuses_shadow_before_sampling() {
    let config = SecureConfig::secure_128().into_config();
    let ntt = NTTEngine::new(config.q, config.n);
    assert_refused_before_sampling("KeySet::generate", |rng| {
        KeySet::generate(&config, &ntt, rng)
    });
}

#[cfg(not(debug_assertions))]
#[test]
fn release_public_key_refuses_shadow_before_sampling() {
    let config = SecureConfig::secure_128().into_config();
    let ntt = NTTEngine::new(config.q, config.n);
    let sk = SecretKey::generate_secure(&config);
    assert_refused_before_sampling("PublicKey::generate", |rng| {
        PublicKey::generate(&sk, &config, &ntt, rng)
    });
}

#[cfg(not(debug_assertions))]
#[test]
fn release_evaluation_key_refuses_shadow_before_sampling() {
    let config = SecureConfig::secure_128().into_config();
    let ntt = NTTEngine::new(config.q, config.n);
    let sk = SecretKey::generate_secure(&config);
    assert_refused_before_sampling("EvaluationKey::generate", |rng| {
        EvaluationKey::generate(&sk, &config, &ntt, rng)
    });
}

#[test]
fn secure_key_constructors_remain_available() {
    let config = SecureConfig::secure_128().into_config();
    let ntt = NTTEngine::new(config.q, config.n);
    let keys = KeySet::try_generate_secure(&config, &ntt).expect("OS key generation");
    let other = KeySet::generate_secure(&config, &ntt);
    assert_ne!(keys.secret_key.s.coeffs, other.secret_key.s.coeffs);
    assert_eq!(keys.secret_key.s.coeffs.len(), config.n);
    for i in 0..config.n {
        assert!((-1..=1).contains(&keys.secret_key.s.get_signed(i)));
    }
    keys.public_key.validate(config.n, config.q).unwrap();
    keys.eval_key.validate(config.n, config.q).unwrap();
    let sk = SecretKey::try_generate_secure(&config).unwrap();
    PublicKey::generate_secure(&sk, &config, &ntt)
        .validate(config.n, config.q)
        .unwrap();
    EvaluationKey::generate_secure(&sk, &config, &ntt)
        .validate(config.n, config.q)
        .unwrap();
}

#[cfg(debug_assertions)]
#[test]
fn research_key_constructors_preserve_seeded_output() {
    let config = SecureConfig::test_fast_insecure().into_config();
    let ntt = NTTEngine::new(config.q, config.n);
    let mut first = ShadowHarvester::with_seed(42);
    let mut second = ShadowHarvester::with_seed(42);
    let keys = KeySet::generate(&config, &ntt, &mut first);
    let sk = SecretKey::generate(&config, &mut second);
    let pk = PublicKey::generate(&sk, &config, &ntt, &mut second);
    let ek = EvaluationKey::generate(&sk, &config, &ntt, &mut second);
    assert_eq!(keys.secret_key.s.coeffs, sk.s.coeffs);
    assert_eq!(keys.public_key.pk0.coeffs, pk.pk0.coeffs);
    assert_eq!(keys.public_key.pk1.coeffs, pk.pk1.coeffs);
    assert_eq!(keys.eval_key.decomp_base, ek.decomp_base);
    assert_eq!(keys.eval_key.levels, ek.levels);
    for ((b, a), (other_b, other_a)) in keys.eval_key.rlk.iter().zip(&ek.rlk) {
        assert_eq!(b.coeffs, other_b.coeffs);
        assert_eq!(a.coeffs, other_a.coeffs);
    }
    assert_eq!(first.next_u64(), second.next_u64());
}

fn encryption_fixture() -> FHEConfig {
    // An arithmetic fixture with ample single-modulus decoding headroom,
    // not an assertion about parameter security or production admission.
    let q = 1_152_921_504_606_830_593;
    FHEConfig {
        n: 4096,
        primes: vec![q],
        q,
        t: 65_537,
        eta: 3,
        security_bits: 0,
        name: "native_entropy_arithmetic_fixture",
    }
}

#[cfg(not(debug_assertions))]
#[test]
fn release_encryption_refuses_all_shadow_entrypoints() {
    let config = encryption_fixture();
    let ntt = NTTEngine::new(config.q, config.n);
    let keys = KeySet::generate_secure(&config, &ntt);
    let encoder = BFVEncoder::new(&config);
    let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
    let plaintext = encoder.encode(42);
    let direct = "BFVEncryptor::encrypt_poly";
    assert_refused_before_sampling(direct, |rng| encryptor.encrypt(42, rng));
    assert_error_before_sampling(direct, |rng| encryptor.try_encrypt(42, rng));
    assert_refused_before_sampling(direct, |rng| encryptor.encrypt_poly(&plaintext, rng));
    assert_error_before_sampling(direct, |rng| encryptor.try_encrypt_poly(&plaintext, rng));
    assert_refused_before_sampling(direct, |_| encryptor.encrypt_seeded(42, 42));
    assert_error_before_sampling(direct, |_| encryptor.try_encrypt_seeded(42, 42));
    let generic = "BFVEncryptor::encrypt_poly_with_rng";
    assert_refused_before_sampling(generic, |rng| encryptor.encrypt_with_rng(42, rng));
    assert_error_before_sampling(generic, |rng| encryptor.try_encrypt_with_rng(42, rng));
    assert_refused_before_sampling(generic, |rng| {
        encryptor.encrypt_poly_with_rng(&plaintext, rng)
    });
    assert_error_before_sampling(generic, |rng| {
        encryptor.try_encrypt_poly_with_rng(&plaintext, rng)
    });
}

#[test]
fn secure_encryption_entrypoints_preserve_roundtrips_and_input_errors() {
    let config = encryption_fixture();
    let ntt = NTTEngine::new(config.q, config.n);
    let keys = KeySet::generate_secure(&config, &ntt);
    let encoder = BFVEncoder::new(&config);
    let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
    let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
    let plaintext = encoder.encode(42);
    let mut rng = nine65::entropy::SecureRng::new();
    let ciphertexts = [
        encryptor.encrypt_secure(42),
        encryptor.try_encrypt_secure(42).unwrap(),
        encryptor.encrypt_poly_secure(&plaintext),
        encryptor.try_encrypt_poly_secure(&plaintext).unwrap(),
        encryptor.encrypt_with_rng(42, &mut rng),
        encryptor.try_encrypt_with_rng(42, &mut rng).unwrap(),
        encryptor.encrypt_poly_with_rng(&plaintext, &mut rng),
        encryptor
            .try_encrypt_poly_with_rng(&plaintext, &mut rng)
            .unwrap(),
    ];
    for ct in ciphertexts {
        assert_eq!(decryptor.decrypt(&ct), 42);
    }
    assert!(encryptor.try_encrypt_secure(config.t).is_err());
    assert!(encryptor.try_encrypt_with_rng(config.t, &mut rng).is_err());
    let mut shadow = ShadowHarvester::with_seed(42);
    assert!(matches!(
        encryptor.try_encrypt(config.t, &mut shadow),
        Err(Nine65Error::MessageOutOfBounds { .. })
    ));
    assert!(matches!(
        encryptor.try_encrypt_seeded(config.t, 42),
        Err(Nine65Error::MessageOutOfBounds { .. })
    ));
}

#[cfg(debug_assertions)]
#[test]
fn research_encryption_preserves_seeded_output() {
    let config = encryption_fixture();
    let ntt = NTTEngine::new(config.q, config.n);
    let keys = KeySet::generate(&config, &ntt, &mut ShadowHarvester::with_seed(42));
    let encoder = BFVEncoder::new(&config);
    let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
    let plaintext = encoder.encode(42);
    let ciphertexts = [
        encryptor.encrypt_seeded(42, 7),
        encryptor.try_encrypt_seeded(42, 7).unwrap(),
        encryptor.encrypt(42, &mut ShadowHarvester::with_seed(7)),
        encryptor
            .try_encrypt(42, &mut ShadowHarvester::with_seed(7))
            .unwrap(),
        encryptor.encrypt_poly(&plaintext, &mut ShadowHarvester::with_seed(7)),
        encryptor
            .try_encrypt_poly(&plaintext, &mut ShadowHarvester::with_seed(7))
            .unwrap(),
        encryptor.encrypt_with_rng(42, &mut ShadowHarvester::with_seed(7)),
        encryptor
            .try_encrypt_with_rng(42, &mut ShadowHarvester::with_seed(7))
            .unwrap(),
        encryptor.encrypt_poly_with_rng(&plaintext, &mut ShadowHarvester::with_seed(7)),
        encryptor
            .try_encrypt_poly_with_rng(&plaintext, &mut ShadowHarvester::with_seed(7))
            .unwrap(),
    ];
    for ct in &ciphertexts[1..] {
        assert_eq!(ct.c0.coeffs, ciphertexts[0].c0.coeffs);
        assert_eq!(ct.c1.coeffs, ciphertexts[0].c1.coeffs);
    }
}
