//! Throughput Benchmark - Batch & Parallel Operations
//!
//! Measures encryption/decryption throughput with:
//! - BatchEncoder (SIMD-style encoding)
//! - ParallelEncryptor/ParallelDecryptor (parallel operations)
//!
//! Run with: cargo bench -p nine65 --bench throughput --features parallel

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use nine65::params::SecureConfig;
use nine65::prelude::*;

/// Benchmark batch encoding/decoding throughput
fn bench_batch_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_encoding");

    // Test with secure config
    let config = SecureConfig::secure_128().into_config();
    let batch_encoder = nine65::ops::BatchEncoder::new(&config).unwrap();

    // Test different batch sizes
    for batch_size in [64, 256, 512, 1024] {
        let values: Vec<u64> = (0..batch_size)
            .map(|i| (i as u64 * 17) % (config.t / 2))
            .collect();

        group.throughput(Throughput::Elements(batch_size as u64));

        group.bench_with_input(
            BenchmarkId::new("encode", batch_size),
            &batch_size,
            |b, _| b.iter(|| black_box(batch_encoder.encode(&values).unwrap())),
        );

        let encoded = batch_encoder.encode(&values).unwrap();
        group.bench_with_input(
            BenchmarkId::new("decode", batch_size),
            &batch_size,
            |b, _| b.iter(|| black_box(batch_encoder.decode(&encoded, batch_size))),
        );
    }

    group.finish();
}

/// Benchmark sequential vs parallel encryption throughput
fn bench_parallel_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("parallel_encryption");
    group.sample_size(10); // Fewer samples for slower operations

    let config = SecureConfig::secure_128().into_config();
    let ntt = NTTEngine::new(config.q, config.n);
    let mut rng = ShadowHarvester::with_seed(0xDEADBEEF);
    let keys = KeySet::generate(&config, &ntt, &mut rng);
    let encoder = BFVEncoder::new(&config);

    // Parallel encryptor
    let parallel_enc = ParallelEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);

    // Test different batch sizes
    for batch_size in [10, 50, 100, 500] {
        let messages: Vec<u64> = (0..batch_size)
            .map(|i| (i as u64) % (config.t / 2))
            .collect();

        group.throughput(Throughput::Elements(batch_size as u64));

        // Sequential baseline
        group.bench_with_input(
            BenchmarkId::new("sequential", batch_size),
            &batch_size,
            |b, _| {
                let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
                b.iter(|| {
                    let cts: Vec<_> = messages
                        .iter()
                        .map(|&m| encryptor.encrypt_secure(m))
                        .collect();
                    black_box(cts)
                })
            },
        );

        // Parallel
        group.bench_with_input(
            BenchmarkId::new("parallel", batch_size),
            &batch_size,
            |b, _| b.iter(|| black_box(parallel_enc.encrypt_batch_par_secure(&messages))),
        );
    }

    group.finish();
}

/// Benchmark sequential vs parallel decryption throughput
fn bench_parallel_decryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("parallel_decryption");
    group.sample_size(10);

    let config = SecureConfig::secure_128().into_config();
    let ntt = NTTEngine::new(config.q, config.n);
    let mut rng = ShadowHarvester::with_seed(0xDEADBEEF);
    let keys = KeySet::generate(&config, &ntt, &mut rng);
    let encoder = BFVEncoder::new(&config);

    let parallel_enc = ParallelEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
    let parallel_dec = ParallelDecryptor::new(&keys.secret_key, &encoder, &ntt);

    for batch_size in [10, 50, 100, 500] {
        let messages: Vec<u64> = (0..batch_size)
            .map(|i| (i as u64) % (config.t / 2))
            .collect();

        // Pre-encrypt ciphertexts for decryption benchmark
        let ciphertexts = parallel_enc.encrypt_batch_par_seeded(&messages, 12345);

        group.throughput(Throughput::Elements(batch_size as u64));

        // Sequential baseline
        group.bench_with_input(
            BenchmarkId::new("sequential", batch_size),
            &batch_size,
            |b, _| {
                let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);
                b.iter(|| {
                    let msgs: Vec<_> = ciphertexts.iter().map(|ct| decryptor.decrypt(ct)).collect();
                    black_box(msgs)
                })
            },
        );

        // Parallel
        group.bench_with_input(
            BenchmarkId::new("parallel", batch_size),
            &batch_size,
            |b, _| b.iter(|| black_box(parallel_dec.decrypt_batch_par(&ciphertexts))),
        );
    }

    group.finish();
}

/// Benchmark full encrypt-decrypt roundtrip throughput
fn bench_roundtrip_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("roundtrip_throughput");
    group.sample_size(10);

    let config = SecureConfig::secure_128().into_config();
    let ntt = NTTEngine::new(config.q, config.n);
    let mut rng = ShadowHarvester::with_seed(0xDEADBEEF);
    let keys = KeySet::generate(&config, &ntt, &mut rng);
    let encoder = BFVEncoder::new(&config);

    let parallel_enc = ParallelEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
    let parallel_dec = ParallelDecryptor::new(&keys.secret_key, &encoder, &ntt);

    for batch_size in [100, 500, 1000] {
        let messages: Vec<u64> = (0..batch_size)
            .map(|i| (i as u64) % (config.t / 2))
            .collect();

        group.throughput(Throughput::Elements(batch_size as u64));

        group.bench_with_input(
            BenchmarkId::new("parallel_roundtrip", batch_size),
            &batch_size,
            |b, _| {
                b.iter(|| {
                    let cts = parallel_enc.encrypt_batch_par_secure(&messages);
                    let decrypted = parallel_dec.decrypt_batch_par(&cts);
                    black_box(decrypted)
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    throughput_benches,
    bench_batch_encoding,
    bench_parallel_encryption,
    bench_parallel_decryption,
    bench_roundtrip_throughput,
);

criterion_main!(throughput_benches);
