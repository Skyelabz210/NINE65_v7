//! UNHAL Performance Benchmark
//!
//! Run with: cargo run --release --example unhal_benchmark -p unhal

use std::hint::black_box;
use std::time::Instant;

use unhal::prelude::*;

/// 8 NTT-friendly primes for 8-lane parallelism
const PRIMES: [u64; 8] = [
    998244353, 985661441, 754974721, 469762049, 1638350849, 1638137857, 1637990401, 1637613569,
];

fn format_ops(ops: u128) -> String {
    if ops >= 1_000_000_000 {
        let whole = ops / 1_000_000_000;
        let frac = (ops % 1_000_000_000) / 100_000_000; // tenths
        format!("{}.{}G", whole, frac)
    } else if ops >= 1_000_000 {
        let whole = ops / 1_000_000;
        format!("{}M", whole)
    } else {
        format!("{}", ops)
    }
}

fn bench_ops(label: &str, accel: &Accelerator, a: &ManaStream, b: &ManaStream, iters: usize) {
    let lanes = a.num_lanes() as u128;
    let n = a.len() as u128;

    let start = Instant::now();
    for _ in 0..iters {
        black_box(accel.add_streams(a, b));
    }
    let add_time = start.elapsed();
    let add_ops = (n * lanes * iters as u128 * 1_000_000_000) / add_time.as_nanos().max(1);

    let start = Instant::now();
    for _ in 0..iters {
        black_box(accel.sub_streams(a, b));
    }
    let sub_time = start.elapsed();
    let sub_ops = (n * lanes * iters as u128 * 1_000_000_000) / sub_time.as_nanos().max(1);

    let start = Instant::now();
    for _ in 0..iters {
        black_box(accel.mul_streams(a, b));
    }
    let mul_time = start.elapsed();
    let mul_ops = (n * lanes * iters as u128 * 1_000_000_000) / mul_time.as_nanos().max(1);

    println!(
        "{} Add/Sub/Mul (N={}, {} lanes): Add={} ops/s, Sub={} ops/s, Mul={} ops/s",
        label,
        n,
        lanes,
        format_ops(add_ops),
        format_ops(sub_ops),
        format_ops(mul_ops)
    );
}

fn bench_size(n: usize, iters: usize) {
    let a_data: Vec<u64> = (0..n).map(|i| (i as u64 * 12345) % PRIMES[0]).collect();
    let b_data: Vec<u64> = (0..n).map(|i| (i as u64 * 67890) % PRIMES[0]).collect();

    let a = ManaStream::from_ints(&a_data, &PRIMES);
    let b = ManaStream::from_ints(&b_data, &PRIMES);

    let seq = Accelerator::new(AcceleratorConfig::sequential());
    let par = Accelerator::new(AcceleratorConfig {
        mode: ExecutionMode::Parallel,
        parallel_threshold: 1,
        num_threads: 0,
        lane_parallel_threshold: 1,
    });

    println!("\n--- UNHAL Benchmark N={} (iters={}) ---", n, iters);
    bench_ops("Sequential", &seq, &a, &b, iters);
    bench_ops("Parallel", &par, &a, &b, iters);
}

fn main() {
    println!("=== UNHAL Accelerator Benchmarks ===");

    bench_size(1024, 2000);
    bench_size(4096, 500);
    bench_size(8192, 200);

    println!("\n=== UNHAL Benchmark Complete ===");
}
