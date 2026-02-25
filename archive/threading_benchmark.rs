use std::time::Instant;
use nine65::entropy::shadow_entropy_monitor::{AdaptiveFHEContext, ShadowEntropyMonitor};
use nine65::keys::KeySet;
use nine65::params::SecureConfig;
use nine65::ops::encrypt::{BFVEncoder, BFVEncryptor, BFVDecryptor};
use nine65::arithmetic::NTTEngine;

fn main() {
    println!("Threading Strategy Performance Comparison");
    println!("======================================");

    // Setup for all systems
    let config = SecureConfig::secure_128().into_config();
    let ntt = NTTEngine::new(config.q, config.n);
    let mut rng = nine65::entropy::shadow::ShadowHarvester::with_seed(0xBEEF);
    let keys = KeySet::generate(&config, &ntt, &mut rng);

    // Test data of different sizes
    let batch_sizes = vec![5, 20, 50, 100];
    
    for batch_size in batch_sizes {
        println!("\nBatch Size: {} messages", batch_size);
        println!("----------------------------------------");
        
        let messages: Vec<u64> = (0..batch_size).map(|i| i as u64).collect();
        
        // 1. Sequential Implementation (no Rayon)
        let start = Instant::now();
        let seq_results: Vec<_> = messages
            .iter()
            .enumerate()
            .map(|(i, &msg)| {
                // Create NTT engine and encoder for each message (no caching in sequential mode)
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
        let sequential_time = start.elapsed();

        // 2. Generic Rayon with thread-local caching (similar to optimized approach)
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

        // 3. Adaptive System (our current implementation)
        let adaptive_ctx = AdaptiveFHEContext::new(config.clone(), keys.clone());
        let start = Instant::now();
        let adaptive_results = adaptive_ctx.adaptive_encrypt(&messages, 42);
        let adaptive_time = start.elapsed();

        // Print results
        println!("Sequential (no Rayon):     {:>10?}", sequential_time);
        println!("Generic Rayon (cached):    {:>10?}", cached_rayon_time);
        println!("Adaptive System:           {:>10?}", adaptive_time);
        
        // Calculate ratios
        let seq_vs_cached = sequential_time.as_micros() as f64 / cached_rayon_time.as_micros() as f64;
        let adaptive_vs_cached = adaptive_time.as_micros() as f64 / cached_rayon_time.as_micros() as f64;
        
        println!("Sequential vs Cached:      {:>8.2}x", seq_vs_cached);
        println!("Adaptive vs Cached:        {:>8.2}x", adaptive_vs_cached);
    }
    
    println!("\nNote: Lower times are better. Ratios show performance relative to Generic Rayon.");
    println!("The Generic Rayon row represents fixed 4-thread parallelization without entropy monitoring.");
}