// Test that NTT engines and encoders should be cached to avoid per-message creation overhead
//
// This test demonstrates the CURRENT PROBLEM: adaptive_encrypt creates NTT/Encoder per message,
// causing massive overhead. This test will FAIL until we implement caching.

use std::time::Instant;

#[test]
#[ignore] // Performance benchmark, run with --include-ignored
fn test_ntt_encoder_caching_performance() {
    use nine65::entropy::shadow_entropy_monitor::AdaptiveFHEContext;
    use nine65::entropy::ShadowHarvester;
    use nine65::params::SecureConfig;
    use nine65::keys::KeySet;

    let config = SecureConfig::secure_128().into_config();
    let mut rng = ShadowHarvester::with_seed(42);
    let ntt_keygen = nine65::arithmetic::NTTEngine::new(config.q, config.n);
    let keys = KeySet::generate(&config, &ntt_keygen, &mut rng);
    let ctx = AdaptiveFHEContext::new(config, keys);

    let messages: Vec<u64> = (0..100).collect();

    // Warm up
    let _ = ctx.adaptive_encrypt(&messages[0..5], 42);

    // Time 100-message encryption
    let start = Instant::now();
    let _cts = ctx.adaptive_encrypt(&messages, 42);
    let elapsed = start.elapsed();

    let elapsed_ms = elapsed.as_millis();
    println!("\n100-message encryption took: {}ms", elapsed_ms);
    println!("Per-message average: {}µs", elapsed.as_micros() / 100);

    // Performance targets:
    // - Static parallel baseline (from benchmarks): ~126ms for 100 encrypts
    // - Before fix (per-message NTT/Encoder creation): ~300ms (138% overhead)
    // - After fix (thread-local NTT/Encoder caching): ~220ms
    // - Remaining overhead: Entropy monitoring, thread pool updates, RNG creation
    //
    // This test verifies NTT/Encoder are cached by detecting the absence of
    // per-message object creation overhead (would be 300ms+)

    assert!(
        elapsed_ms < 250,
        "Encryption too slow ({}ms). Per-message NTT/Encoder creation detected.\n\
         Expected: <250ms with thread-local caching\n\
         Actual: {}ms suggests object creation is not cached per-thread\n\
         Note: Adaptive overhead (entropy + pool management) adds ~70% vs static baseline",
        elapsed_ms,
        elapsed_ms
    );
}

#[test]
fn test_adaptive_encrypt_correctness() {
    // Basic correctness test - this should PASS even without caching
    use nine65::entropy::shadow_entropy_monitor::AdaptiveFHEContext;
    use nine65::entropy::ShadowHarvester;
    use nine65::params::SecureConfig;
    use nine65::keys::KeySet;
    use nine65::arithmetic::NTTEngine;
    use nine65::ops::encrypt::{BFVEncoder, BFVDecryptor};

    let config = SecureConfig::secure_128().into_config();
    let mut rng = ShadowHarvester::with_seed(42);
    let ntt_keygen = nine65::arithmetic::NTTEngine::new(config.q, config.n);
    let keys = KeySet::generate(&config, &ntt_keygen, &mut rng);
    let ctx = AdaptiveFHEContext::new(config.clone(), keys);

    let messages = vec![5, 10, 15];
    let cts = ctx.adaptive_encrypt(&messages, 42);

    // Verify we got correct number of ciphertexts
    assert_eq!(cts.len(), 3);

    // Verify they decrypt correctly
    let ntt = NTTEngine::new(config.q, config.n);
    let encoder = BFVEncoder::new(&config);
    let decryptor = BFVDecryptor::new(&ctx.keys.secret_key, &encoder, &ntt);

    for (i, ct) in cts.iter().enumerate() {
        let decrypted = decryptor.decrypt(ct);
        assert_eq!(
            decrypted, messages[i],
            "Message {} decrypted incorrectly",
            i
        );
    }
}
