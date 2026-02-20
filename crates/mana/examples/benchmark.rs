//! MANA Performance Benchmark
//!
//! Run with: cargo run --release --example benchmark -p mana

use mana::lane::{Lane, LaneOps};
use mana::stream::{ManaStream, StreamOps};

#[cfg(feature = "parallel")]
use mana::parallel::ParallelStream;

use std::hint::black_box;
use std::time::Instant;

const TEST_PRIME: u64 = 998244353;

/// Format operations count with suffix (M = million, G = billion)
/// Uses integer arithmetic only -- no floating-point.
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

/// 8 NTT-friendly primes for full 8-core utilization
const PRIMES: [u64; 8] = [
    998244353, 985661441, 754974721, 469762049, // original 4
    1638350849, 1638137857, 1637990401, 1637613569, // 4 new for 8-core saturation
];

fn bench_lane_add(size: usize, iterations: usize) {
    let a_data: Vec<u64> = (0..size).map(|i| (i as u64 * 12345) % TEST_PRIME).collect();
    let b_data: Vec<u64> = (0..size).map(|i| (i as u64 * 67890) % TEST_PRIME).collect();

    let a = Lane::from_coeffs(a_data.clone(), TEST_PRIME);
    let b = Lane::from_coeffs(b_data.clone(), TEST_PRIME);

    // Sequential lane operations (branchless)
    let start = Instant::now();
    for _ in 0..iterations {
        black_box(a.add(&b));
    }
    let seq_time = start.elapsed();
    let seq_ops = (size as u128 * iterations as u128 * 1_000_000_000) / seq_time.as_nanos().max(1);

    println!(
        "Lane Add (N={}): {} ops/s (branchless)",
        size,
        format_ops(seq_ops)
    );
}

fn bench_stream_add(size: usize, iterations: usize) {
    let a_data: Vec<u64> = (0..size).map(|i| (i as u64 * 12345) % TEST_PRIME).collect();
    let b_data: Vec<u64> = (0..size).map(|i| (i as u64 * 67890) % TEST_PRIME).collect();

    let a = ManaStream::from_ints(&a_data, &PRIMES);
    let b = ManaStream::from_ints(&b_data, &PRIMES);

    // Sequential stream operations
    let start = Instant::now();
    for _ in 0..iterations {
        black_box(a.add(&b));
    }
    let seq_time = start.elapsed();
    let seq_ops = (size as u128 * PRIMES.len() as u128 * iterations as u128 * 1_000_000_000)
        / seq_time.as_nanos().max(1);

    #[cfg(feature = "parallel")]
    {
        let pa = ParallelStream::new(a.clone());
        let pb = ParallelStream::new(b.clone());

        // Lane-level parallel (8 lanes → 8 threads)
        let start = Instant::now();
        for _ in 0..iterations {
            black_box(pa.add_par(&pb));
        }
        let par_time = start.elapsed();
        let par_ops = (size as u128 * PRIMES.len() as u128 * iterations as u128 * 1_000_000_000)
            / par_time.as_nanos().max(1);

        let speedup_hundredths = (par_ops * 100) / seq_ops.max(1);
        println!(
            "Stream Add (N={}, {} lanes): Seq={} → Rayon={} ({}.{:02}x)",
            size,
            PRIMES.len(),
            format_ops(seq_ops),
            format_ops(par_ops),
            speedup_hundredths / 100,
            speedup_hundredths % 100
        );
    }

    #[cfg(not(feature = "parallel"))]
    {
        println!(
            "Stream Add (N={}, {} lanes): Sequential={} ops/s",
            size,
            PRIMES.len(),
            seq_ops
        );
    }
}

fn main() {
    println!("=== MANA FHE Accelerator Benchmarks ===\n");

    println!("--- Lane Operations (single prime) ---");
    bench_lane_add(1024, 10000);
    bench_lane_add(4096, 2500);
    bench_lane_add(8192, 1000);

    println!("\n--- Stream Operations (multi-prime CRT) ---");
    bench_stream_add(1024, 5000);
    bench_stream_add(4096, 1000);
    bench_stream_add(8192, 500);

    println!("\n=== Benchmark Complete ===");
}
