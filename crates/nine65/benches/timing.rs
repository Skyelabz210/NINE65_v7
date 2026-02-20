use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use nine65::arithmetic::k_elimination::{
    bench_mul_mod_u128_ct, bench_sub_mod_u128_ct, KElimConfig,
};
use nine65::arithmetic::{BarrettContext, ExactDivider, KElimination, NTTEngine};
use nine65::entropy::ShadowHarvester;
use nine65::ops::RNSFHEContext;
use nine65::params::SecureConfig;

#[cfg(feature = "ntt_fft")]
use nine65::arithmetic::NTTEngineFFT;

const TEST_PRIME: u64 = 998_244_353;

fn bench_barrett_ct(c: &mut Criterion) {
    let ctx = BarrettContext::new(TEST_PRIME);

    let mut group = c.benchmark_group("barrett_ct");
    group.bench_function(BenchmarkId::new("reduce", "small"), |b| {
        let mut a: u128 = 12345;
        b.iter(|| {
            a = a.wrapping_add(1);
            black_box(ctx.reduce_ct(black_box(a)));
        });
    });
    group.bench_function(BenchmarkId::new("reduce", "large"), |b| {
        let mut a: u128 = (TEST_PRIME as u128 - 1) * (TEST_PRIME as u128 - 1);
        b.iter(|| {
            a = a.wrapping_sub(1);
            black_box(ctx.reduce_ct(black_box(a)));
        });
    });

    group.bench_function(BenchmarkId::new("mul", "small"), |b| {
        let mut a: u64 = 1;
        let mut cval: u64 = 2;
        b.iter(|| {
            a = a.wrapping_add(1);
            cval = cval.wrapping_add(2);
            black_box(ctx.mul_ct(black_box(a % 1000), black_box(cval % 1000)));
        });
    });
    group.bench_function(BenchmarkId::new("mul", "large"), |b| {
        let mut a: u64 = TEST_PRIME - 1;
        let mut cval: u64 = TEST_PRIME - 2;
        b.iter(|| {
            a = a.wrapping_sub(1);
            cval = cval.wrapping_sub(2);
            black_box(ctx.mul_ct(black_box(a), black_box(cval)));
        });
    });

    group.finish();
}

fn bench_k_elimination_ct(c: &mut Criterion) {
    let ke = KElimination::from_config(KElimConfig::Standard);
    let mut group = c.benchmark_group("k_elimination_ct");

    let small_v: u128 = 1;
    let small_alpha = small_v % ke.alpha_cap;
    let small_beta = small_v % ke.beta_cap;

    let large_v: u128 = ke.alpha_cap * 1000 + 50;
    let large_alpha = large_v % ke.alpha_cap;
    let large_beta = large_v % ke.beta_cap;

    let edge_v: u128 = ke.beta_cap - 1;
    let edge_alpha = edge_v % ke.alpha_cap;
    let edge_beta = edge_v % ke.beta_cap;

    group.bench_function(BenchmarkId::new("extract_k", "small"), |b| {
        b.iter(|| black_box(ke.extract_k(black_box(small_alpha), black_box(small_beta))));
    });
    group.bench_function(BenchmarkId::new("extract_k", "large"), |b| {
        b.iter(|| black_box(ke.extract_k(black_box(large_alpha), black_box(large_beta))));
    });
    group.bench_function(BenchmarkId::new("extract_k", "edge"), |b| {
        b.iter(|| black_box(ke.extract_k(black_box(edge_alpha), black_box(edge_beta))));
    });

    let m = 4_611_686_018_427_387_847u128; // 62-bit prime
    group.bench_function(BenchmarkId::new("mul_mod_u128_ct", "small"), |b| {
        b.iter(|| {
            black_box(bench_mul_mod_u128_ct(
                black_box(1u128),
                black_box(1u128),
                black_box(m),
            ))
        });
    });
    group.bench_function(BenchmarkId::new("mul_mod_u128_ct", "large"), |b| {
        let a = m - 1;
        let bval = m - 1;
        b.iter(|| {
            black_box(bench_mul_mod_u128_ct(
                black_box(a),
                black_box(bval),
                black_box(m),
            ))
        });
    });

    let m_small = 667u128;
    group.bench_function(BenchmarkId::new("sub_mod_u128_ct", "no_borrow"), |b| {
        b.iter(|| {
            black_box(bench_sub_mod_u128_ct(
                black_box(500u128),
                black_box(100u128),
                black_box(m_small),
            ))
        });
    });
    group.bench_function(BenchmarkId::new("sub_mod_u128_ct", "borrow"), |b| {
        b.iter(|| {
            black_box(bench_sub_mod_u128_ct(
                black_box(100u128),
                black_box(500u128),
                black_box(m_small),
            ))
        });
    });

    group.finish();
}

fn bench_exact_divider(c: &mut Criterion) {
    let divider = ExactDivider::for_fhe(TEST_PRIME);
    let mut group = c.benchmark_group("k_elimination_divider");

    // Use varying values so optimizer cannot fold constants.
    let values: Vec<u128> = (1..=2048u128).map(|v| v.wrapping_mul(123_457)).collect();
    let encoded: Vec<(u64, u64)> = values.iter().map(|&v| divider.encode(v)).collect();

    group.bench_function(BenchmarkId::new("reconstruct_exact", "rolling"), |b| {
        let mut i = 0usize;
        b.iter(|| {
            let (m_res, a_res) = encoded[i];
            i = (i + 1) % encoded.len();
            black_box(divider.reconstruct_exact(black_box(m_res), black_box(a_res)));
        });
    });

    // exact_divide requires exact divisibility; feed values multiplied by divisor.
    let divisor = 5u64;
    let div_values: Vec<(u64, u64)> = (1..=2048u128)
        .map(|v| divider.encode(v * divisor as u128))
        .collect();
    group.bench_function(BenchmarkId::new("exact_divide", "div_by_5"), |b| {
        let mut i = 0usize;
        b.iter(|| {
            let (m_res, a_res) = div_values[i];
            i = (i + 1) % div_values.len();
            black_box(divider.exact_divide(black_box(m_res), black_box(a_res), black_box(divisor)));
        });
    });

    group.bench_function(BenchmarkId::new("divmod", "div_by_7"), |b| {
        let mut i = 0usize;
        b.iter(|| {
            let (m_res, a_res) = encoded[i];
            i = (i + 1) % encoded.len();
            black_box(divider.divmod(black_box(m_res), black_box(a_res), black_box(7u64)));
        });
    });

    group.bench_function(BenchmarkId::new("scale_and_round", "bfv_like"), |b| {
        let mut i = 0usize;
        b.iter(|| {
            let (m_res, a_res) = encoded[i];
            i = (i + 1) % encoded.len();
            black_box(divider.scale_and_round(
                black_box(m_res),
                black_box(a_res),
                black_box(500_000u64),
                black_box(TEST_PRIME),
            ));
        });
    });

    group.finish();
}

fn bench_ntt_ct(c: &mut Criterion) {
    let engine = NTTEngine::new(TEST_PRIME, 256);
    let small_input: Vec<u64> = vec![0; 256];
    let large_input: Vec<u64> = vec![TEST_PRIME - 1; 256];

    let mut group = c.benchmark_group("ntt_ct");
    group.bench_function(BenchmarkId::new("ntt", "small"), |b| {
        b.iter(|| black_box(engine.ntt(black_box(&small_input))));
    });
    group.bench_function(BenchmarkId::new("ntt", "large"), |b| {
        b.iter(|| black_box(engine.ntt(black_box(&large_input))));
    });
    group.bench_function(BenchmarkId::new("intt", "small"), |b| {
        b.iter(|| black_box(engine.intt(black_box(&small_input))));
    });
    group.bench_function(BenchmarkId::new("intt", "large"), |b| {
        b.iter(|| black_box(engine.intt(black_box(&large_input))));
    });

    let small_a: Vec<u64> = vec![0; 256];
    let small_b: Vec<u64> = vec![0; 256];
    let large_a: Vec<u64> = vec![TEST_PRIME - 1; 256];
    let large_b: Vec<u64> = vec![TEST_PRIME - 1; 256];

    group.bench_function(BenchmarkId::new("multiply", "small"), |b| {
        b.iter(|| black_box(engine.multiply_ct(black_box(&small_a), black_box(&small_b))));
    });
    group.bench_function(BenchmarkId::new("multiply", "large"), |b| {
        b.iter(|| black_box(engine.multiply_ct(black_box(&large_a), black_box(&large_b))));
    });

    group.finish();
}

fn bench_ntt_fft(c: &mut Criterion) {
    #[cfg(feature = "ntt_fft")]
    {
        let mut group = c.benchmark_group("ntt_fft");

        let engine_1024 = NTTEngineFFT::new(TEST_PRIME, 1024);
        let a_1024: Vec<u64> = (0..1024).map(|i| i % TEST_PRIME).collect();
        let b_1024: Vec<u64> = (0..1024).map(|i| (i * 2) % TEST_PRIME).collect();
        group.bench_function(BenchmarkId::new("multiply", "1024"), |b| {
            b.iter(|| black_box(engine_1024.multiply(black_box(&a_1024), black_box(&b_1024))));
        });

        let engine_4096 = NTTEngineFFT::new(TEST_PRIME, 4096);
        let a_4096: Vec<u64> = (0..4096).map(|i| i % TEST_PRIME).collect();
        let b_4096: Vec<u64> = (0..4096).map(|i| (i * 2) % TEST_PRIME).collect();
        group.bench_function(BenchmarkId::new("multiply", "4096"), |b| {
            b.iter(|| black_box(engine_4096.multiply(black_box(&a_4096), black_box(&b_4096))));
        });

        group.finish();
    }
    #[cfg(not(feature = "ntt_fft"))]
    {
        let _ = c;
    }
}

#[allow(deprecated)]
fn bench_rns_kelim_rescale(c: &mut Criterion) {
    let config = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::new(&config);
    let mut rng = ShadowHarvester::with_seed(42);
    let keys = ctx.generate_keys_dual(&mut rng);
    let ct = ctx.encrypt_dual(42, &keys.public_key, &mut rng);

    let mut group = c.benchmark_group("rns_kelim_rescale");
    group.bench_function("k_elim_rescale", |b| {
        b.iter(|| black_box(ctx.bench_k_elim_rescale_dual(black_box(&ct.c1))));
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_barrett_ct,
    bench_k_elimination_ct,
    bench_exact_divider,
    bench_ntt_ct,
    bench_rns_kelim_rescale,
    bench_ntt_fft,
);
criterion_main!(benches);
