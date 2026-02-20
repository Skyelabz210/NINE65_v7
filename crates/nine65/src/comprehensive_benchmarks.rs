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
        let inner = RNSFHEContext::new_coeff_domain(&config);
        let ctx = GSOFHEContext::new(inner);

        // Generate full keys for public-mode operations in this benchmark module.
        let mut rng = ShadowHarvester::new();
        let keys = ctx.generate_full_keys(&mut rng);

        (ctx, keys)
    }

    /// Benchmark noise growth over multiple operations
    #[test]
    fn benchmark_noise_growth_secure_128() {
        println!("\n┌────────────────────────────────────────────────────────────┐");
        println!("│  NOISE GROWTH ANALYSIS - secure_128                        │");
        println!("└────────────────────────────────────────────────────────────┘");

        let (mut ctx, keys) = create_bench_context("secure_128");
        let mut rng = ShadowHarvester::new();

        let mut ct = ctx.encrypt(2, &keys.public_key, &mut rng);

        println!("Operation | Noise Dist | Collapses | Time (ms)");
        println!("----------|-------------|-----------|----------");

        for i in 1..=20 {
            let start = Instant::now();
            let ct_clone = ct.clone();
            ct = ctx.mul_public(&ct, &ct_clone, &keys.eval_key).unwrap();
            let elapsed_ms = start.elapsed().as_micros() as f64 / 1000.0;

            let stats = ctx.noise_stats(&ct);
            println!(
                "{:9} | {:11} | {:9} | {:7.2}",
                format!("Mul #{}", i),
                stats.distance,
                stats.collapses,
                elapsed_ms
            );
        }
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
        println!("\n┌────────────────────────────────────────────────────────────┐");
        println!("│  DEPTH-SPECIFIC ANALYSIS - secure_128                      │");
        println!("└────────────────────────────────────────────────────────────┘");

        let (mut ctx, keys) = create_bench_context("secure_128");
        let mut rng = ShadowHarvester::new();

        let mut ct = ctx.encrypt(2, &keys.public_key, &mut rng);

        println!("Depth | Operation Type | Time (ms) | Noise Dist  | Collapses");
        println!("------|---------------|-----------|-------------|----------");

        for depth in 1..=25 {
            let start = Instant::now();

            // Alternate between add and mul to simulate realistic usage
            if depth % 2 == 0 {
                let ct_clone = ct.clone();
                ct = ctx.add(&ct, &ct_clone);
                let elapsed_ms = start.elapsed().as_micros() as f64 / 1000.0;
                let stats = ctx.noise_stats(&ct);
                println!(
                    "{:5} | {:13} | {:9.2} | {:11} | {:9}",
                    depth, "ADD", elapsed_ms, stats.distance, stats.collapses
                );
            } else {
                let ct_clone = ct.clone();
                ct = ctx.mul_public(&ct, &ct_clone, &keys.eval_key).unwrap();
                let elapsed_ms = start.elapsed().as_micros() as f64 / 1000.0;
                let stats = ctx.noise_stats(&ct);
                println!(
                    "{:5} | {:13} | {:9.2} | {:11} | {:9}",
                    depth, "MUL", elapsed_ms, stats.distance, stats.collapses
                );
            }
        }
    }

    /// Benchmark noise budget tracking against observed GSO noise distance.
    #[test]
    fn benchmark_noise_budget_accuracy() {
        println!("\n┌────────────────────────────────────────────────────────────┐");
        println!("│  NOISE BUDGET ACCURACY ANALYSIS                            │");
        println!("└────────────────────────────────────────────────────────────┘");

        let (mut ctx, keys) = create_bench_context("secure_128");
        let mut rng = ShadowHarvester::new();
        let mut budget = NoiseBudget::from_config(&ctx.inner.config);

        let mut ct = ctx.encrypt(2, &keys.public_key, &mut rng);

        println!("Operation | Budget(bits) | Noise Dist  | Collapses");
        println!("----------|--------------|-------------|----------");

        for i in 1..=10 {
            let ct_clone = ct.clone();
            ct = ctx.mul_public(&ct, &ct_clone, &keys.eval_key).unwrap();

            let budget_result = budget
                .consume(NoiseOpType::MulCt, NoiseBudget::mul_ct_cost(&ctx.inner.config))
                .and_then(|_| {
                    budget.consume(NoiseOpType::Relin, NoiseBudget::relin_cost(&ctx.inner.config))
                })
                .and_then(|_| {
                    budget.consume(
                        NoiseOpType::Rescale,
                        NoiseBudget::rescale_cost(&ctx.inner.config),
                    )
                });

            let stats = ctx.noise_stats(&ct);
            println!(
                "{:9} | {:12.2} | {:11} | {:9}{}",
                format!("Mul #{}", i),
                budget.remaining_millibits() as f64 / 1000.0,
                stats.distance,
                stats.collapses,
                if budget_result.is_err() {
                    " (budget exhausted)"
                } else {
                    ""
                }
            );

            if budget_result.is_err() {
                break;
            }
        }
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
