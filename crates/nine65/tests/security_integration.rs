//! Security Integration Tests
//!
//! Comprehensive tests verifying the security hardening implementations:
//! - Secure parameter configurations
//! - Constant-time operations
//! - CSPRNG encryption
//! - Error handling
//!
//! These tests ensure that security features work correctly together
//! in realistic usage scenarios.

use nine65::entropy::{FheRng, SecureRng, ShadowHarvester};
use nine65::errors::Nine65Error;
use nine65::keys::KeySet;
use nine65::ops::encrypt::{BFVDecryptor, BFVEncoder, BFVEncryptor, Ciphertext};
use nine65::params::secure_configs::SecureConfig;
use nine65::params::FHEConfig;

#[cfg(feature = "ntt_fft")]
use nine65::arithmetic::NTTEngineFFT as NTTEngine;

#[cfg(not(feature = "ntt_fft"))]
use nine65::arithmetic::NTTEngine;

// ═══════════════════════════════════════════════════════════════════════════
// SECURE PARAMETER TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_secure_128_is_production_safe() {
    let config = SecureConfig::secure_128();
    assert!(
        config.is_production_safe(),
        "secure_128 should be production safe"
    );
    assert!(
        config.hybrid_security >= 100,
        "secure_128 should have >= 100 bits hybrid security"
    );
}

#[test]
fn test_secure_192_meets_security_claims() {
    let config = SecureConfig::secure_192();
    assert!(
        config.is_production_safe(),
        "secure_192 should be production safe"
    );
    assert!(
        config.hybrid_security >= 150,
        "secure_192 should have >= 150 bits hybrid security"
    );
}

// Note: test_fast_insecure() is only available in unit tests (lib) due to cfg attributes.
// This test verifies the secure configs meet their security claims instead.
#[test]
fn test_secure_config_security_levels() {
    let secure_128 = SecureConfig::secure_128();
    let secure_192 = SecureConfig::secure_192();

    // Verify security levels increase appropriately
    assert!(
        secure_192.hybrid_security > secure_128.hybrid_security,
        "secure_192 should have higher security than secure_128"
    );

    // Verify quantum security is also estimated
    assert!(
        secure_128.quantum_security > 0,
        "Should have quantum security estimate"
    );
    assert!(
        secure_192.quantum_security > secure_128.quantum_security,
        "secure_192 should have higher quantum security"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// SECURE ENCRYPTION FLOW TESTS
// ═══════════════════════════════════════════════════════════════════════════

fn setup_fhe() -> (FHEConfig, NTTEngine, KeySet, BFVEncoder) {
    let config = FHEConfig::light_rns_insecure();
    let ntt = NTTEngine::new(config.q, config.n);
    let mut harvester = ShadowHarvester::with_seed(42);
    let keys = KeySet::generate(&config, &ntt, &mut harvester);
    let encoder = BFVEncoder::new(&config);
    (config, ntt, keys, encoder)
}

#[test]
fn test_secure_encryption_roundtrip() {
    let (config, ntt, keys, encoder) = setup_fhe();

    let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
    let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);

    // Use secure encryption
    for m in [0u64, 1, 42, 100, 500, 1000] {
        let ct = encryptor.encrypt_secure(m);
        let decrypted = decryptor.decrypt(&ct);
        assert_eq!(decrypted, m, "Secure encrypt/decrypt failed for m={}", m);
    }
}

#[test]
fn test_secure_encryption_produces_different_ciphertexts() {
    let (config, ntt, keys, encoder) = setup_fhe();

    let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);

    // Secure encryption should produce different ciphertexts for the same message
    let ct1 = encryptor.encrypt_secure(42);
    let ct2 = encryptor.encrypt_secure(42);

    assert_ne!(
        ct1.c0.coeffs, ct2.c0.coeffs,
        "Secure encryption should produce different ciphertexts"
    );
}

#[test]
fn test_rng_trait_secure_vs_deterministic() {
    let (config, ntt, keys, encoder) = setup_fhe();

    let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
    let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);

    // Test with SecureRng (production)
    let mut secure_rng = SecureRng::new();
    assert!(secure_rng.is_secure(), "SecureRng should be secure");
    let ct_secure = encryptor.encrypt_with_rng(42, &mut secure_rng);
    assert_eq!(decryptor.decrypt(&ct_secure), 42);

    // Test with ShadowHarvester (testing)
    let mut shadow_rng = ShadowHarvester::with_seed(123);
    assert!(
        !shadow_rng.is_secure(),
        "ShadowHarvester should NOT be secure"
    );
    let ct_shadow = encryptor.encrypt_with_rng(42, &mut shadow_rng);
    assert_eq!(decryptor.decrypt(&ct_shadow), 42);
}

// ═══════════════════════════════════════════════════════════════════════════
// ERROR HANDLING TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_fallible_encoding_success() {
    let config = FHEConfig::light_rns_insecure();
    let encoder = BFVEncoder::new(&config);

    let result = encoder.try_encode(42);
    assert!(result.is_ok(), "Valid message should encode successfully");
}

#[test]
fn test_fallible_encoding_out_of_bounds() {
    let config = FHEConfig::light_rns_insecure();
    let encoder = BFVEncoder::new(&config);

    // Message >= t should fail
    let result = encoder.try_encode(config.t);
    assert!(result.is_err(), "Message >= t should fail");

    match result.unwrap_err() {
        Nine65Error::MessageOutOfBounds { message, modulus } => {
            assert_eq!(message, config.t);
            assert_eq!(modulus, config.t);
        }
        e => panic!("Wrong error type: {:?}", e),
    }
}

#[test]
fn test_fallible_encryption_success() {
    let (config, ntt, keys, encoder) = setup_fhe();

    let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
    let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);

    let result = encryptor.try_encrypt_secure(42);
    assert!(result.is_ok(), "Valid encryption should succeed");

    let ct = result.unwrap();
    assert_eq!(decryptor.decrypt(&ct), 42);
}

#[test]
fn test_fallible_encryption_out_of_bounds() {
    let (config, ntt, keys, encoder) = setup_fhe();

    let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);

    let result = encryptor.try_encrypt_secure(config.t);
    assert!(
        result.is_err(),
        "Encryption of out-of-bounds message should fail"
    );

    match result.unwrap_err() {
        Nine65Error::MessageOutOfBounds { .. } => {}
        e => panic!("Wrong error type: {:?}", e),
    }
}

#[test]
fn test_error_categories() {
    let encoding_err = Nine65Error::MessageOutOfBounds {
        message: 100,
        modulus: 50,
    };
    assert_eq!(encoding_err.category(), "Encoding");

    let kelim_err = Nine65Error::NotCoprime {
        m: 10,
        a: 15,
        gcd: 5,
    };
    assert_eq!(kelim_err.category(), "K-Elimination");

    let crypto_err = Nine65Error::DecryptionFailed;
    assert_eq!(crypto_err.category(), "Cryptographic");
}

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANT-TIME OPERATION TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_montgomery_operations_consistent() {
    use nine65::arithmetic::MontgomeryContext;

    let ctx = MontgomeryContext::new(998244353);

    // Test that constant-time operations produce correct results
    for (a, b) in [(12345, 67890), (1, 1), (0, 100), (998244352, 998244352)] {
        let a_mont = ctx.to_montgomery(a);
        let b_mont = ctx.to_montgomery(b);

        // Multiply
        let result_mont = ctx.montgomery_mul(a_mont, b_mont);
        let result = ctx.from_montgomery(result_mont);
        let expected = ((a as u128 * b as u128) % 998244353) as u64;
        assert_eq!(
            result, expected,
            "Montgomery mul failed for a={}, b={}",
            a, b
        );

        // Add
        let sum_mont = ctx.montgomery_add(a_mont, b_mont);
        let sum = ctx.from_montgomery(sum_mont);
        let expected_sum = (a + b) % 998244353;
        assert_eq!(
            sum, expected_sum,
            "Montgomery add failed for a={}, b={}",
            a, b
        );
    }
}

#[test]
fn test_k_elimination_ct_matches_vartime() {
    use nine65::arithmetic::KElimination;

    let ke = KElimination::new(&[17, 19], &[23, 29]);

    for v in [0u128, 1, 100, 1000, 10000, 100000] {
        let v_alpha = v % ke.alpha_cap;
        let v_beta = v % ke.beta_cap;

        // extract_k is the CT (constant-time) version - it's the default
        let k_ct = ke.extract_k(v_alpha, v_beta);
        // extract_k_vartime is the variable-time version (deprecated)
        #[allow(deprecated)]
        let k_vartime = ke.extract_k_vartime(v_alpha, v_beta);

        assert_eq!(
            k_ct, k_vartime,
            "CT and vartime extract_k differ for v={}",
            v
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// FULL PIPELINE TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_full_secure_pipeline() {
    // Test the complete secure pipeline:
    // 1. Use production-safe config (or test config for speed)
    // 2. Generate keys
    // 3. Encrypt with CSPRNG
    // 4. Perform homomorphic operations
    // 5. Decrypt correctly

    let config = FHEConfig::light_rns_insecure(); // Using light_rns for test speed
    let ntt = NTTEngine::new(config.q, config.n);

    // Key generation with secure entropy
    let mut secure_rng = SecureRng::new();
    // Note: In production, KeySet would use SecureRng
    let mut test_rng = ShadowHarvester::with_seed(secure_rng.next_u64());
    let keys = KeySet::generate(&config, &ntt, &mut test_rng);

    let encoder = BFVEncoder::new(&config);
    let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
    let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);

    // Encrypt with CSPRNG
    let m1 = 5u64;
    let m2 = 7u64;
    let ct1 = encryptor.encrypt_secure(m1);
    let ct2 = encryptor.encrypt_secure(m2);

    // Verify decryption
    assert_eq!(decryptor.decrypt(&ct1), m1);
    assert_eq!(decryptor.decrypt(&ct2), m2);

    // Test homomorphic addition (ct1 + ct2 should decrypt to m1 + m2)
    let ct_sum = Ciphertext {
        c0: ct1.c0.add(&ct2.c0, &ntt),
        c1: ct1.c1.add(&ct2.c1, &ntt),
    };
    assert_eq!(
        decryptor.decrypt(&ct_sum),
        m1 + m2,
        "Homomorphic addition failed: {} + {} != {}",
        m1,
        m2,
        m1 + m2
    );
}

#[test]
fn test_multiple_secure_encryptions() {
    let (config, ntt, keys, encoder) = setup_fhe();

    let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
    let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);

    // Encrypt many values and verify all decrypt correctly
    let messages: Vec<u64> = (0..100).map(|i| i % config.t).collect();

    for &m in &messages {
        let ct = encryptor.encrypt_secure(m);
        let decrypted = decryptor.decrypt(&ct);
        assert_eq!(decrypted, m, "Batch secure encryption failed for m={}", m);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SECURITY PROPERTY TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn test_ciphertext_randomness() {
    let (config, ntt, keys, encoder) = setup_fhe();

    let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);

    // Encrypt same message multiple times
    let ciphertexts: Vec<Ciphertext> = (0..10).map(|_| encryptor.encrypt_secure(42)).collect();

    // All ciphertexts should be different (IND-CPA property)
    for i in 0..ciphertexts.len() {
        for j in (i + 1)..ciphertexts.len() {
            assert_ne!(
                ciphertexts[i].c0.coeffs, ciphertexts[j].c0.coeffs,
                "Ciphertexts {} and {} should be different",
                i, j
            );
        }
    }
}

#[test]
fn test_deterministic_encryption_is_reproducible() {
    let (config, ntt, keys, encoder) = setup_fhe();

    let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);

    // Seeded encryption should be reproducible
    let ct1 = encryptor.encrypt_seeded(42, 12345);
    let ct2 = encryptor.encrypt_seeded(42, 12345);

    assert_eq!(
        ct1.c0.coeffs, ct2.c0.coeffs,
        "Seeded encryption should be reproducible"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// ADVERSARIAL DESERIALIZATION TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(feature = "serde")]
mod adversarial_tests {
    use super::*;

    #[test]
    fn test_ciphertext_validation_rejects_wrong_degree() {
        let config = FHEConfig::light_rns_insecure();

        // Create a ciphertext with wrong polynomial degree
        let wrong_n = config.n / 2; // Half the expected size
        let ct = Ciphertext {
            c0: nine65::ring::RingPolynomial::from_coeffs(vec![1u64; wrong_n], config.q),
            c1: nine65::ring::RingPolynomial::from_coeffs(vec![2u64; wrong_n], config.q),
        };

        let result = ct.validate(config.n, config.q);
        assert!(
            result.is_err(),
            "Should reject ciphertext with wrong degree"
        );
    }

    #[test]
    fn test_ciphertext_validation_rejects_coefficient_overflow() {
        let config = FHEConfig::light_rns_insecure();

        // Note: RingPolynomial::from_coeffs reduces coefficients mod q,
        // which is safe-by-design. This test verifies that malformed JSON
        // with coefficients >= q is rejected by validated deserialization.
        //
        // We craft JSON with an out-of-bounds coefficient manually.
        let malformed_json = format!(
            r#"{{"c0":{{"coeffs":[{}],"q":{}}},"c1":{{"coeffs":[{}],"q":{}}}}}"#,
            // First coefficient is q+1 (invalid!)
            std::iter::once(config.q + 1)
                .chain(std::iter::repeat_n(1, config.n - 1))
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(","),
            config.q,
            std::iter::repeat_n(1, config.n)
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(","),
            config.q
        );

        let result = Ciphertext::from_json_validated(&malformed_json, config.n, config.q);
        assert!(
            result.is_err(),
            "Should reject ciphertext with overflow coefficient via JSON"
        );
    }

    #[test]
    fn test_ciphertext_validation_rejects_modulus_mismatch() {
        let config = FHEConfig::light_rns_insecure();
        let wrong_q = config.q - 1;

        let ct = Ciphertext {
            c0: nine65::ring::RingPolynomial::from_coeffs(vec![1u64; config.n], wrong_q),
            c1: nine65::ring::RingPolynomial::from_coeffs(vec![2u64; config.n], config.q),
        };

        let result = ct.validate(config.n, config.q);
        assert!(
            result.is_err(),
            "Should reject ciphertext with modulus mismatch"
        );
    }

    #[test]
    fn test_ciphertext_roundtrip_with_validation() {
        let (config, ntt, keys, encoder) = super::setup_fhe();
        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);

        // Encrypt a value
        let ct = encryptor.encrypt_secure(42);

        // Serialize and deserialize with validation
        let json = ct.to_json().expect("Serialization should work");
        let ct_restored = Ciphertext::from_json_validated(&json, config.n, config.q)
            .expect("Validated deserialization should work for valid ciphertext");

        // Verify decryption still works
        assert_eq!(decryptor.decrypt(&ct_restored), 42);
    }

    #[test]
    fn test_malformed_json_rejected() {
        let config = FHEConfig::light_rns_insecure();

        // Completely malformed JSON
        let result = Ciphertext::from_json_validated("{}", config.n, config.q);
        assert!(result.is_err(), "Should reject malformed JSON");

        // Partially valid JSON but wrong structure
        let result2 =
            Ciphertext::from_json_validated(r#"{"c0": [], "c1": []}"#, config.n, config.q);
        assert!(result2.is_err(), "Should reject JSON with missing fields");
    }
}
