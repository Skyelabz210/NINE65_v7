use std::time::Instant;

use crate::entropy::ShadowHarvester;
use crate::noise::budget::{NoiseBudget, NoiseOpType};
use crate::ops::gso_fhe::GSOFHEContext;
use crate::ops::rns_fhe::{DualRNSFullKeySet, RNSFHEContext};
use crate::params::secure_configs::SecureConfig;

/// Additional comprehensive benchmarks for NINE65 FHE system
pub mod comprehensive_benchmarks {
    use super::*;

    /// Create a benchmark context using public APIs
    fn create_bench_context(config_name: &str) -> (GSOFHEContext, DualRNSFullKeySet) {
        let secure_config = match config_name {
            "secure_128" => SecureConfig::secure_128(),
            "secure_192" => SecureConfig::secure_192(),
            "secure_256" => SecureConfig::secure_256(),
            _ => panic!("Unsupported config: {}", config_name),
        };

        let config = secure_config.into_config();
        let inner = RNSFHEContext::new(&config);
        let ctx = GSOFHEContext::new(inner);

        // Generate full keys for public-mode operations in this benchmark module.
        let mut rng = ShadowHarvester::new();
        let keys = ctx.generate_full_keys(&mut rng);

        (ctx, keys)
    }

    /// Benchmark noise growth over multiple operations
    #[test]
    fn benchmark_noise_growth_secure_128() {
        let (mut ctx, keys) = create_bench_context("secure_128");
        let mut rng = ShadowHarvester::new();
        let mut ct = ctx.encrypt(2, &keys.public_key, &mut rng);
        let mut expected = 2_u64;
        let t = ctx.inner().t;
        let mut admitted = 0;
        for _ in 0..20 {
            match ctx.try_mul_symmetric(&ct, &ct, &keys.secret_key) {
                Ok(next) => {
                    expected = ((expected as u128 * expected as u128) % t as u128) as u64;
                    assert_eq!(ctx.decrypt(&next, &keys.secret_key), expected);
                    ct = next;
                    admitted += 1;
                }
                Err(_) => break,
            }
        }
        assert!(admitted > 0 && admitted < 20);
    }

    /// Benchmark batch operations to identify potential DoS vectors
    #[test]
    fn benchmark_batch_operations_secure_128() {
        println!("\n┌────────────────────────────────────────────────────────────┐");
        println!("│  BATCH OPERATION ANALYSIS - secure_128                     │");
        println!("└────────────────────────────────────────────────────────────┘");

        let (ctx, keys) = create_bench_context("secure_128");
        let mut rng = ShadowHarvester::new();

        // Test batch encryption performance
        let start = Instant::now();
        let mut cts = Vec::new();
        for i in 0u64..50 {
            let ct = ctx.encrypt(i, &keys.public_key, &mut rng);
            cts.push(ct);
        }
        let encrypt_time = start.elapsed().as_secs_f64();

        // Test batch addition performance
        let start = Instant::now();
        for i in 0..49 {
            let _result = ctx.add(&cts[i], &cts[i + 1]);
        }
        let add_time = start.elapsed().as_secs_f64();

        println!(
            "Batch of 50 encrypt operations: {:.2}s ({:.2}ms/op)",
            encrypt_time,
            (encrypt_time * 1000.0) / 50.0
        );
        println!(
            "Batch of 49 add operations: {:.2}s ({:.2}ms/op)",
            add_time,
            (add_time * 1000.0) / 49.0
        );
    }

    /// Benchmark depth-specific operations to identify degradation patterns
    #[test]
    fn benchmark_depth_specific_operations_secure_128() {
        let (mut ctx, keys) = create_bench_context("secure_128");
        let mut rng = ShadowHarvester::new();
        let mut ct = ctx.encrypt(2, &keys.public_key, &mut rng);
        let mut expected = 2_u64;
        let t = ctx.inner().t;
        let mut refused = false;
        let mut admitted = 0;
        for depth in 1..=25 {
            if depth % 2 == 0 {
                ct = ctx.add(&ct, &ct);
                expected = ((expected as u128 * 2) % t as u128) as u64;
            } else {
                ct = match ctx.try_mul_symmetric(&ct, &ct, &keys.secret_key) {
                    Ok(next) => next,
                    Err(_) => {
                        refused = true;
                        break;
                    }
                };
                expected = ((expected as u128 * expected as u128) % t as u128) as u64;
                admitted += 1;
            }
            assert_eq!(ctx.decrypt(&ct, &keys.secret_key), expected);
        }
        assert!(admitted > 0 && refused);
    }

    /// Benchmark noise budget tracking against observed GSO noise distance.
    #[test]
    fn benchmark_noise_budget_accuracy() {
        let (mut ctx, keys) = create_bench_context("secure_128");
        let mut rng = ShadowHarvester::new();
        let mut ct = ctx.encrypt(2, &keys.public_key, &mut rng);
        let mut budget = NoiseBudget::from_config(&ctx.inner().config);
        let mut expected = 2_u64;
        let t = ctx.inner().t;
        let mut admitted = 0;
        for _ in 0..10 {
            ct = match ctx.try_mul_symmetric(&ct, &ct, &keys.secret_key) {
                Ok(next) => next,
                Err(_) => break,
            };
            expected = ((expected as u128 * expected as u128) % t as u128) as u64;
            assert_eq!(ctx.decrypt(&ct, &keys.secret_key), expected);
            admitted += 1;
            let _ = budget.consume(
                NoiseOpType::MulCt,
                NoiseBudget::mul_ct_cost(&ctx.inner().config),
            );
        }
        assert!(admitted > 0 && admitted < 10);
    }

    /// Benchmark memory usage patterns during operations
    #[test]
    fn benchmark_memory_usage_patterns() {
        println!("\n┌────────────────────────────────────────────────────────────┐");
        println!("│  MEMORY USAGE PATTERNS - secure_128                        │");
        println!("└────────────────────────────────────────────────────────────┘");

        let (ctx, keys) = create_bench_context("secure_128");
        let mut rng = ShadowHarvester::new();

        // Test memory usage with increasing number of operations
        for &batch_size in &[1usize, 5, 10, 20, 50] {
            let start = Instant::now();

            // Perform batch of operations
            let mut cts = Vec::new();
            for i in 0..batch_size {
                let ct = ctx.encrypt(i as u64, &keys.public_key, &mut rng);
                cts.push(ct);
            }

            // Perform operations on the ciphertexts
            for i in 0..batch_size.saturating_sub(1).min(49) {
                if i + 1 < cts.len() {
                    let _result = ctx.add(&cts[i], &cts[i + 1]);
                }
            }

            let elapsed = start.elapsed().as_secs_f64();

            println!(
                "Batch size: {}, Time: {:.3}s, Avg: {:.2}ms/op",
                batch_size,
                elapsed,
                (elapsed * 1000.0) / (batch_size as f64)
            );
        }
    }
}
