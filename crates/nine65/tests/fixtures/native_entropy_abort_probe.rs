//! Standalone release probe, compiled with `rustc -C panic=abort` against the
//! release library. Unlike Cargo's test harness, this cannot catch a panic.

use nine65::arithmetic::NTTEngine;
use nine65::entropy::ShadowHarvester;
use nine65::errors::{Nine65Error, Nine65Result};
use nine65::keys::KeySet;
use nine65::ops::{BFVDecryptor, BFVEncoder, BFVEncryptor};
use nine65::params::FHEConfig;

fn expect_policy_error<T>(result: Nine65Result<T>) {
    match result {
        Err(Nine65Error::ConfigError { message }) => {
            assert!(message.contains("SECURITY ERROR"));
        }
        Err(error) => panic!("wrong refusal: {error}"),
        Ok(_) => panic!("prohibited entropy was accepted"),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    assert!(cfg!(panic = "abort"), "probe requires panic=abort");
    assert!(!cfg!(debug_assertions), "probe requires release policy");
    // Arithmetic fixture only, not parameter-security evidence.
    let config = FHEConfig {
        n: 4096,
        primes: vec![998_244_353],
        q: 998_244_353,
        t: 257,
        eta: 3,
        security_bits: 0,
        name: "entropy_abort_probe",
    };
    let ntt = NTTEngine::new(config.q, config.n);
    let keys = KeySet::try_generate_secure(&config, &ntt)?;
    let encoder = BFVEncoder::new(&config);
    let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
    let plaintext = encoder.encode(42);
    let mut rng = ShadowHarvester::with_seed(42);
    let mut unchanged = ShadowHarvester::with_seed(42);
    expect_policy_error(encryptor.try_encrypt(42, &mut rng));
    expect_policy_error(encryptor.try_encrypt_seeded(42, 42));
    expect_policy_error(encryptor.try_encrypt_with_rng(42, &mut rng));
    expect_policy_error(encryptor.try_encrypt_poly(&plaintext, &mut rng));
    expect_policy_error(encryptor.try_encrypt_poly_with_rng(&plaintext, &mut rng));
    assert_eq!(rng.next_u64(), unchanged.next_u64());
    let ciphertext = encryptor.try_encrypt_secure(42)?;
    let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
    assert_eq!(decryptor.decrypt(&ciphertext), 42);
    println!("PASS: 5 typed entropy refusals and secure round trip with panic=abort");
    Ok(())
}
