//! FHE Scaling Benchmark - Full FFT + Nested Parallelism Power
//!
//! Tests homo_mul performance across N=1024, 2048, 4096, 8192
//! to demonstrate O(N log N) FFT scaling vs O(N²) baseline
//!
//! All benchmarks use production-safe SecureConfig with proper security levels.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use nine65::params::SecureConfig;
use nine65::prelude::*;

fn bench_homo_mul_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("homo_mul_scaling");
    group.sample_size(10); // Fewer samples for large N

    // Test configurations at different N values - ALL use secure 128-bit+ configs
    let configs = [
        ("N=2048/128-bit", SecureConfig::secure_128().into_config()),
        (
            "N=4096/128-bit-deep",
            SecureConfig::secure_128_deep().into_config(),
        ),
        ("N=4096/192-bit", SecureConfig::secure_192().into_config()),
        ("N=8192/256-bit", SecureConfig::secure_256().into_config()),
    ];

    for (name, config) in configs.iter() {
        let ntt = NTTEngine::new(config.q, config.n);
        let mut rng = ShadowHarvester::with_seed(0xDEADBEEF);
        let keys = KeySet::generate(&config, &ntt, &mut rng);
        let encoder = BFVEncoder::new(&config);

        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let evaluator = BFVEvaluator::new(&ntt, &encoder, Some(&keys.eval_key));

        let ct1 = encryptor.encrypt(42, &mut rng);
        let ct2 = encryptor.encrypt(17, &mut rng);

        group.bench_with_input(BenchmarkId::new("parallel", name), &name, |b, _| {
            b.iter(|| black_box(evaluator.mul(&ct1, &ct2)))
        });
    }

    group.finish();
}

fn bench_ntt_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("ntt_scaling");
    group.sample_size(20);

    let sizes = [1024, 2048, 4096, 8192];
    let q = 998244353u64; // NTT-friendly prime

    for &n in &sizes {
        let ntt = NTTEngine::new(q, n);
        let data: Vec<u64> = (0..n).map(|i| (i as u64 * 12345) % q).collect();

        group.bench_with_input(BenchmarkId::new("forward", n), &n, |b, _| {
            b.iter(|| {
                let mut input = data.clone();
                ntt.ntt_inplace(&mut input);
                black_box(input)
            })
        });

        group.bench_with_input(BenchmarkId::new("roundtrip", n), &n, |b, _| {
            b.iter(|| {
                let mut input = data.clone();
                ntt.ntt_inplace(&mut input);
                ntt.intt_inplace(&mut input);
                black_box(input)
            })
        });
    }

    group.finish();
}

fn bench_encrypt_decrypt_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt_decrypt_scaling");
    group.sample_size(20);

    // All configs use production-safe 128-bit+ security
    // Note: Each N must be unique to avoid benchmark ID conflicts
    let configs = [
        (2048, SecureConfig::secure_128().into_config()),
        (4096, SecureConfig::secure_192().into_config()),
        (8192, SecureConfig::secure_256().into_config()),
    ];

    for (n, config) in configs.iter() {
        let ntt = NTTEngine::new(config.q, config.n);
        let mut rng = ShadowHarvester::with_seed(42);
        let keys = KeySet::generate(&config, &ntt, &mut rng);
        let encoder = BFVEncoder::new(&config);

        let encryptor = BFVEncryptor::new(&keys.public_key, &encoder, &ntt, config.eta);
        let decryptor = BFVDecryptor::new(&keys.secret_key, &encoder, &ntt);

        group.bench_with_input(BenchmarkId::new("encrypt", n), &n, |b, _| {
            b.iter(|| black_box(encryptor.encrypt(42, &mut rng)))
        });

        let ct = encryptor.encrypt(42, &mut rng);
        group.bench_with_input(BenchmarkId::new("decrypt", n), &n, |b, _| {
            b.iter(|| black_box(decryptor.decrypt(&ct)))
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_homo_mul_scaling,
    bench_ntt_scaling,
    bench_encrypt_decrypt_scaling
);
criterion_main!(benches);
