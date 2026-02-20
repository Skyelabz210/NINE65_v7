//! Adaptive Rayon Benchmark - Shadow Entropy Monitor vs Static ParallelEncryptor
//!
//! Compares:
//!   1. AdaptiveFHEContext (entropy-driven thread adaptation)
//!   2. Static ParallelEncryptor (fixed Rayon global pool)
//!   3. Entropy measurement overhead (cost of monitoring)
//!
//! Run with: cargo bench -p nine65 --bench adaptive_rayon --features parallel

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use nine65::entropy::shadow::ShadowHarvester;
use nine65::entropy::{AdaptiveFHEContext, ShadowEntropyMonitor};
use nine65::keys::KeySet;
use nine65::ops::parallel::{ParallelDecryptor, ParallelEncryptor};
use nine65::params::SecureConfig;
use nine65::prelude::*;

// ─── Helpers ──────────────────────────────────────────────────────────

fn bench_config() -> nine65::params::FHEConfig {
    SecureConfig::secure_128().into_config()
}

fn setup_adaptive() -> AdaptiveFHEContext {
    let config = bench_config();
    let ntt = NTTEngine::new(config.q, config.n);
    let mut rng = ShadowHarvester::with_seed(0xBEEF);
    let keys = KeySet::generate(&config, &ntt, &mut rng);
    AdaptiveFHEContext::new(config, keys)
}

fn setup_static() -> (nine65::params::FHEConfig, NTTEngine, KeySet, BFVEncoder) {
    let config = bench_config();
    let ntt = NTTEngine::new(config.q, config.n);
    let mut rng = ShadowHarvester::with_seed(0xBEEF);
    let keys = KeySet::generate(&config, &ntt, &mut rng);
    let encoder = BFVEncoder::new(&config);
    (config, ntt, keys, encoder)
}

// ─── Bench 1: Adaptive vs Static encrypt throughput ──────────────────

fn bench_adaptive_vs_static_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("adaptive_vs_static_encrypt");
    group.sample_size(10);

    let adaptive_ctx = setup_adaptive();
    let (config, ntt, keys, encoder) = setup_static();
    let static_enc = ParallelEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);

    for batch_size in [5, 20, 50, 100] {
        let messages: Vec<u64> = (0..batch_size)
            .map(|i| (i as u64) % (config.t / 2))
            .collect();

        group.throughput(Throughput::Elements(batch_size as u64));

        // Adaptive path (entropy-monitored thread pool)
        group.bench_with_input(
            BenchmarkId::new("adaptive", batch_size),
            &batch_size,
            |b, _| b.iter(|| black_box(adaptive_ctx.adaptive_encrypt(&messages, 42))),
        );

        // Static path (Rayon global pool)
        group.bench_with_input(
            BenchmarkId::new("static_parallel", batch_size),
            &batch_size,
            |b, _| b.iter(|| black_box(static_enc.encrypt_batch_par_seeded(&messages, 42))),
        );
    }

    group.finish();
}

// ─── Bench 2: Adaptive vs Static decrypt throughput ──────────────────

fn bench_adaptive_vs_static_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("adaptive_vs_static_decrypt");
    group.sample_size(10);

    let adaptive_ctx = setup_adaptive();
    let (config, ntt, keys, encoder) = setup_static();
    let static_enc = ParallelEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
    let static_dec = ParallelDecryptor::new(&keys.secret_key, &encoder, &ntt);

    for batch_size in [10, 50, 100] {
        let messages: Vec<u64> = (0..batch_size)
            .map(|i| (i as u64) % (config.t / 2))
            .collect();
        let ciphertexts = static_enc.encrypt_batch_par_seeded(&messages, 42);

        group.throughput(Throughput::Elements(batch_size as u64));

        group.bench_with_input(
            BenchmarkId::new("adaptive", batch_size),
            &batch_size,
            |b, _| b.iter(|| black_box(adaptive_ctx.adaptive_decrypt(&ciphertexts))),
        );

        group.bench_with_input(
            BenchmarkId::new("static_parallel", batch_size),
            &batch_size,
            |b, _| b.iter(|| black_box(static_dec.decrypt_batch_par(&ciphertexts))),
        );
    }

    group.finish();
}

// ─── Bench 3: Entropy measurement overhead ───────────────────────────

fn bench_entropy_measurement_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("entropy_overhead");

    let adaptive_ctx = setup_adaptive();
    let messages: Vec<u64> = (0..10).collect();
    let ciphertexts = adaptive_ctx.adaptive_encrypt(&messages, 42);
    let ct = &ciphertexts[0];

    let monitor = ShadowEntropyMonitor::new();

    // Cost of measuring entropy from a ciphertext
    group.bench_function("measure_ciphertext", |b| {
        b.iter(|| black_box(monitor.measure_entropy_from_ciphertext(black_box(ct))))
    });

    // Cost of adapt_threading decision
    group.bench_function("adapt_threading", |b| {
        b.iter(|| black_box(monitor.adapt_threading(10)))
    });

    // Cost of is_high_entropy check
    group.bench_function("is_high_entropy", |b| {
        b.iter(|| black_box(monitor.is_high_entropy()))
    });

    group.finish();
}

// ─── Bench 4: Thread pool creation cost ──────────────────────────────

fn bench_thread_pool_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("thread_pool_creation");

    for num_threads in [1, 2, 4, 8] {
        group.bench_with_input(
            BenchmarkId::new("rayon_pool", num_threads),
            &num_threads,
            |b, &nt| {
                b.iter(|| {
                    let pool = rayon::ThreadPoolBuilder::new()
                        .num_threads(nt)
                        .build()
                        .expect("pool creation");
                    black_box(pool);
                })
            },
        );
    }

    group.finish();
}

// ─── Bench 5: Adaptive add throughput ────────────────────────────────

fn bench_adaptive_add(c: &mut Criterion) {
    let mut group = c.benchmark_group("adaptive_add");
    group.sample_size(10);

    let adaptive_ctx = setup_adaptive();

    for batch_size in [5, 15, 50] {
        let a_msgs: Vec<u64> = (0..batch_size).map(|i| i as u64).collect();
        let b_msgs: Vec<u64> = (0..batch_size).map(|i| (i + 1) as u64).collect();

        let ct_a = adaptive_ctx.adaptive_encrypt(&a_msgs, 100);
        let ct_b = adaptive_ctx.adaptive_encrypt(&b_msgs, 200);

        group.throughput(Throughput::Elements(batch_size as u64));

        group.bench_with_input(
            BenchmarkId::new("adaptive_add", batch_size),
            &batch_size,
            |b, _| b.iter(|| black_box(adaptive_ctx.adaptive_add(&ct_a, &ct_b))),
        );
    }

    group.finish();
}

criterion_group!(
    adaptive_benches,
    bench_adaptive_vs_static_encrypt,
    bench_adaptive_vs_static_decrypt,
    bench_entropy_measurement_overhead,
    bench_thread_pool_creation,
    bench_adaptive_add,
);

criterion_main!(adaptive_benches);
