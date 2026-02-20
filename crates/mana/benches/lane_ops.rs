//! MANA Lane Operations Benchmarks

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use mana::lane::{Lane, LaneOps};
use mana::stream::{ManaStream, StreamOps};

#[cfg(feature = "parallel")]
use mana::parallel::ParallelStream;

const TEST_PRIME: u64 = 998244353;

/// 8 NTT-friendly primes for full 8-core utilization
const PRIMES: [u64; 8] = [
    998244353, 985661441, 754974721, 469762049, 1638350849, 1638137857, 1637990401, 1637613569,
];

fn bench_lane_add(c: &mut Criterion) {
    let mut group = c.benchmark_group("lane_add");

    for size in [2048, 4096, 8192] {
        let a_data: Vec<u64> = (0..size).map(|i| (i * 12345) % TEST_PRIME).collect();
        let b_data: Vec<u64> = (0..size).map(|i| (i * 67890) % TEST_PRIME).collect();

        let a = Lane::from_coeffs(a_data.clone(), TEST_PRIME);
        let b = Lane::from_coeffs(b_data.clone(), TEST_PRIME);

        group.bench_with_input(BenchmarkId::new("sequential", size), &size, |bench, _| {
            bench.iter(|| black_box(a.add(&b)))
        });
    }

    group.finish();
}

fn bench_stream_add(c: &mut Criterion) {
    let mut group = c.benchmark_group("stream_add");

    for size in [2048, 4096, 8192] {
        let a_data: Vec<u64> = (0..size).map(|i| (i * 12345) % TEST_PRIME).collect();
        let b_data: Vec<u64> = (0..size).map(|i| (i * 67890) % TEST_PRIME).collect();

        let a = ManaStream::from_ints(&a_data, &PRIMES);
        let b = ManaStream::from_ints(&b_data, &PRIMES);

        group.bench_with_input(BenchmarkId::new("sequential", size), &size, |bench, _| {
            bench.iter(|| black_box(a.add(&b)))
        });

        #[cfg(feature = "parallel")]
        {
            let pa = ParallelStream::new(a.clone());
            let pb = ParallelStream::new(b.clone());

            group.bench_with_input(BenchmarkId::new("rayon_8lane", size), &size, |bench, _| {
                bench.iter(|| black_box(pa.add_par(&pb)))
            });
        }
    }

    group.finish();
}

fn bench_lane_mul(c: &mut Criterion) {
    let mut group = c.benchmark_group("lane_mul");

    for size in [2048, 4096, 8192] {
        let a_data: Vec<u64> = (0..size).map(|i| (i * 12345) % TEST_PRIME).collect();
        let b_data: Vec<u64> = (0..size).map(|i| (i * 67890) % TEST_PRIME).collect();

        let a = Lane::from_coeffs(a_data, TEST_PRIME);
        let b = Lane::from_coeffs(b_data, TEST_PRIME);

        group.bench_with_input(BenchmarkId::new("sequential", size), &size, |bench, _| {
            bench.iter(|| black_box(a.mul(&b)))
        });
    }

    group.finish();
}

criterion_group!(benches, bench_lane_add, bench_stream_add, bench_lane_mul);
criterion_main!(benches);
