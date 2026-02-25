use std::time::Instant;
use rayon::prelude::*;
use nine65::entropy::shadow_entropy_monitor::{AdaptiveFHEContext, ShadowEntropyMonitor};
use nine65::keys::KeySet;
use nine65::params::SecureConfig;
use nine65::ops::encrypt::{BFVEncoder, BFVEncryptor, BFVDecryptor};
use nine65::arithmetic::NTTEngine;

fn main() {
    // Setup for both systems
    let config = SecureConfig::secure_128().into_config();
    let ntt = NTTEngine::new(config.q, config.n);
    let mut rng = nine65::entropy::shadow::ShadowHarvester::with_seed(0xBEEF);
    let keys = KeySet::generate(&config, &ntt, &mut rng);

    // Test data
    let messages: Vec<u64> = (0..100).map(|i| i as u64).collect();

    // Benchmark Adaptive System
    let adaptive_ctx = AdaptiveFHEContext::new(config.clone(), keys.clone());
    let start = Instant::now();
    let ciphertexts = adaptive_ctx.adaptive_encrypt(&messages, 42);
    let adaptive_encrypt_time = start.elapsed();

    let start = Instant::now();
    let _decrypted = adaptive_ctx.adaptive_decrypt(&ciphertexts);
    let adaptive_decrypt_time = start.elapsed();

    // Benchmark Regular Rayon with manual parallelization
    let start = Instant::now();
    let regular_results: Vec<_> = messages
        .par_iter()
        .map(|&msg| {
            let ntt = NTTEngine::new(config.q, config.n);
            let encoder = BFVEncoder::new(&config);
            let encryptor = BFVEncryptor::new(
                &keys.public_key,
                &encoder,
                &ntt,
                config.eta,
            );
            let mut harvester = nine65::entropy::shadow::ShadowHarvester::with_seed(42);
            encryptor.encrypt(msg, &mut harvester)
        })
        .collect();
    let regular_rayon_time = start.elapsed();

    // Benchmark Regular Rayon with thread-local caching (similar to our optimized approach)
    let start = Instant::now();
    let cached_results: Vec<_> = messages
        .par_iter()
        .map_init(
            || {
                // Initialize per-thread state (runs once per thread)
                let ntt = NTTEngine::new(config.q, config.n);
                let encoder = BFVEncoder::new(&config);
                (ntt, encoder)
            },
            |(ntt, encoder), &msg| {
                // Reuse cached objects
                let encryptor = BFVEncryptor::new(
                    &keys.public_key,
                    encoder,
                    ntt,
                    config.eta,
                );
                let mut harvester = nine65::entropy::shadow::ShadowHarvester::with_seed(42);
                encryptor.encrypt(msg, &mut harvester)
            }
        )
        .collect();
    let cached_rayon_time = start.elapsed();

    println!("Performance Comparison:");
    println!("Adaptive System (encrypt): {:?}", adaptive_encrypt_time);
    println!("Adaptive System (decrypt): {:?}", adaptive_decrypt_time);
    println!("Regular Rayon (per-message objects): {:?}", regular_rayon_time);
    println!("Cached Rayon (thread-local objects): {:?}", cached_rayon_time);
    
    // Show overhead of entropy monitoring
    let entropy_overhead = (adaptive_encrypt_time.as_micros() as f64 - cached_rayon_time.as_micros() as f64) / 
                           cached_rayon_time.as_micros() as f64 * 100.0;
    println!("Entropy monitoring overhead: {:.2}% compared to cached Rayon", entropy_overhead);
}