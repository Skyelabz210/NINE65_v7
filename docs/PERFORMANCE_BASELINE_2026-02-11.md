# Performance Baseline (2026-02-11)

Results are hardware- and config-dependent; re-run on your target hardware and
record updated baselines when publishing.

## Environment
- Timestamp (UTC): 2026-02-11T16:31:32Z
- OS: Linux coreI7 6.12.48+deb13-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.12.48-1 (2025-09-20) x86_64 GNU/Linux
- CPU: Intel(R) Core(TM) i7-3632QM CPU @ 2.20GHz
- Rust: rustc 1.90.0 (1159e78c4 2025-09-14)
- Cargo: cargo 1.90.0 (840b83a10 2025-07-30)
- Commit: 91dcb2c
- Benchmark profile class: secure (claim-grade)

## Commands

### Criterion Timing Bench (K-Elimination + Core Arithmetic)

Command:
```
cargo bench -p nine65 --bench timing --features benchmarks -- --noplot --save-baseline perf_2026-02-11
```

Output:
```
warning: profiles for the non root package will be ignored, specify profiles at the workspace root:
package:   /home/acid/Projects/NINE65/v5/crates/exact_transcendentals/Cargo.toml
workspace: /home/acid/Projects/NINE65/v5/Cargo.toml
warning: use of deprecated associated function `nine65::params::FHEConfig::light_rns_exact`: INSECURE: light_rns_exact() has only ~80-bit security (n=1024). Use SecureConfig::secure_128() for production.
   --> crates/nine65/benches/timing.rs:247:29
    |
247 |     let config = FHEConfig::light_rns_exact();
    |                             ^^^^^^^^^^^^^^^
    |
    = note: `#[warn(deprecated)]` on by default

warning: `nine65` (bench "timing") generated 1 warning
    Finished `bench` profile [optimized] target(s) in 0.09s
     Running benches/timing.rs (target/release/deps/timing-b5a46d85b1f8da7a)
Benchmarking barrett_ct/reduce/small
Benchmarking barrett_ct/reduce/small: Warming up for 3.0000 s
Benchmarking barrett_ct/reduce/small: Collecting 100 samples in estimated 5.0000 s (1.1B iterations)
Benchmarking barrett_ct/reduce/small: Analyzing
barrett_ct/reduce/small time:   [4.7140 ns 4.7330 ns 4.7512 ns]
Found 1 outliers among 100 measurements (1.00%)
  1 (1.00%) high mild
Benchmarking barrett_ct/reduce/large
Benchmarking barrett_ct/reduce/large: Warming up for 3.0000 s
Benchmarking barrett_ct/reduce/large: Collecting 100 samples in estimated 5.0000 s (1.0B iterations)
Benchmarking barrett_ct/reduce/large: Analyzing
barrett_ct/reduce/large time:   [4.7422 ns 4.7860 ns 4.8522 ns]
Found 4 outliers among 100 measurements (4.00%)
  3 (3.00%) low mild
  1 (1.00%) high severe
Benchmarking barrett_ct/mul/small
Benchmarking barrett_ct/mul/small: Warming up for 3.0000 s
Benchmarking barrett_ct/mul/small: Collecting 100 samples in estimated 5.0000 s (527M iterations)
Benchmarking barrett_ct/mul/small: Analyzing
barrett_ct/mul/small    time:   [9.4372 ns 9.4743 ns 9.5133 ns]
Found 5 outliers among 100 measurements (5.00%)
  3 (3.00%) low mild
  1 (1.00%) high mild
  1 (1.00%) high severe
Benchmarking barrett_ct/mul/large
Benchmarking barrett_ct/mul/large: Warming up for 3.0000 s
Benchmarking barrett_ct/mul/large: Collecting 100 samples in estimated 5.0000 s (765M iterations)
Benchmarking barrett_ct/mul/large: Analyzing
barrett_ct/mul/large    time:   [6.3138 ns 6.3835 ns 6.4803 ns]
Found 6 outliers among 100 measurements (6.00%)
  1 (1.00%) low mild
  3 (3.00%) high mild
  2 (2.00%) high severe

Benchmarking k_elimination_ct/extract_k/small
Benchmarking k_elimination_ct/extract_k/small: Warming up for 3.0000 s
Benchmarking k_elimination_ct/extract_k/small: Collecting 100 samples in estimated 5.0017 s (5.6M iterations)
Benchmarking k_elimination_ct/extract_k/small: Analyzing
k_elimination_ct/extract_k/small
                        time:   [891.24 ns 897.56 ns 904.37 ns]
Found 5 outliers among 100 measurements (5.00%)
  4 (4.00%) high mild
  1 (1.00%) high severe
Benchmarking k_elimination_ct/extract_k/large
Benchmarking k_elimination_ct/extract_k/large: Warming up for 3.0000 s
Benchmarking k_elimination_ct/extract_k/large: Collecting 100 samples in estimated 5.0030 s (5.6M iterations)
Benchmarking k_elimination_ct/extract_k/large: Analyzing
k_elimination_ct/extract_k/large
                        time:   [890.24 ns 894.93 ns 899.74 ns]
Found 2 outliers among 100 measurements (2.00%)
  2 (2.00%) high severe
Benchmarking k_elimination_ct/extract_k/edge
Benchmarking k_elimination_ct/extract_k/edge: Warming up for 3.0000 s
Benchmarking k_elimination_ct/extract_k/edge: Collecting 100 samples in estimated 5.0013 s (5.6M iterations)
Benchmarking k_elimination_ct/extract_k/edge: Analyzing
k_elimination_ct/extract_k/edge
                        time:   [894.43 ns 901.21 ns 910.11 ns]
Found 7 outliers among 100 measurements (7.00%)
  1 (1.00%) low mild
  1 (1.00%) high mild
  5 (5.00%) high severe
Benchmarking k_elimination_ct/mul_mod_u128_ct/small
Benchmarking k_elimination_ct/mul_mod_u128_ct/small: Warming up for 3.0000 s
Benchmarking k_elimination_ct/mul_mod_u128_ct/small: Collecting 100 samples in estimated 5.0012 s (5.4M iterations)
Benchmarking k_elimination_ct/mul_mod_u128_ct/small: Analyzing
k_elimination_ct/mul_mod_u128_ct/small
                        time:   [893.78 ns 897.55 ns 901.35 ns]
Found 7 outliers among 100 measurements (7.00%)
  1 (1.00%) low mild
  2 (2.00%) high mild
  4 (4.00%) high severe
Benchmarking k_elimination_ct/mul_mod_u128_ct/large
Benchmarking k_elimination_ct/mul_mod_u128_ct/large: Warming up for 3.0000 s
Benchmarking k_elimination_ct/mul_mod_u128_ct/large: Collecting 100 samples in estimated 5.0002 s (5.5M iterations)
Benchmarking k_elimination_ct/mul_mod_u128_ct/large: Analyzing
k_elimination_ct/mul_mod_u128_ct/large
                        time:   [904.64 ns 919.86 ns 943.40 ns]
Found 9 outliers among 100 measurements (9.00%)
  5 (5.00%) high mild
  4 (4.00%) high severe
Benchmarking k_elimination_ct/sub_mod_u128_ct/no_borrow
Benchmarking k_elimination_ct/sub_mod_u128_ct/no_borrow: Warming up for 3.0000 s
Benchmarking k_elimination_ct/sub_mod_u128_ct/no_borrow: Collecting 100 samples in estimated 5.0000 s (1.2B iterations)
Benchmarking k_elimination_ct/sub_mod_u128_ct/no_borrow: Analyzing
k_elimination_ct/sub_mod_u128_ct/no_borrow
                        time:   [4.0342 ns 4.0530 ns 4.0732 ns]
Found 6 outliers among 100 measurements (6.00%)
  6 (6.00%) high mild
Benchmarking k_elimination_ct/sub_mod_u128_ct/borrow
Benchmarking k_elimination_ct/sub_mod_u128_ct/borrow: Warming up for 3.0000 s
Benchmarking k_elimination_ct/sub_mod_u128_ct/borrow: Collecting 100 samples in estimated 5.0000 s (1.2B iterations)
Benchmarking k_elimination_ct/sub_mod_u128_ct/borrow: Analyzing
k_elimination_ct/sub_mod_u128_ct/borrow
                        time:   [4.1008 ns 4.1244 ns 4.1495 ns]
Found 10 outliers among 100 measurements (10.00%)
  3 (3.00%) low mild
  2 (2.00%) high mild
  5 (5.00%) high severe

Benchmarking k_elimination_divider/reconstruct_exact/rolling
Benchmarking k_elimination_divider/reconstruct_exact/rolling: Warming up for 3.0000 s
Benchmarking k_elimination_divider/reconstruct_exact/rolling: Collecting 100 samples in estimated 5.0001 s (135M iterations)
Benchmarking k_elimination_divider/reconstruct_exact/rolling: Analyzing
k_elimination_divider/reconstruct_exact/rolling
                        time:   [36.505 ns 36.627 ns 36.756 ns]
Found 4 outliers among 100 measurements (4.00%)
  2 (2.00%) high mild
  2 (2.00%) high severe
Benchmarking k_elimination_divider/exact_divide/div_by_5
Benchmarking k_elimination_divider/exact_divide/div_by_5: Warming up for 3.0000 s
Benchmarking k_elimination_divider/exact_divide/div_by_5: Collecting 100 samples in estimated 5.0002 s (98M iterations)
Benchmarking k_elimination_divider/exact_divide/div_by_5: Analyzing
k_elimination_divider/exact_divide/div_by_5
                        time:   [50.577 ns 50.714 ns 50.866 ns]
Found 3 outliers among 100 measurements (3.00%)
  2 (2.00%) low mild
  1 (1.00%) high mild
Benchmarking k_elimination_divider/divmod/div_by_7
Benchmarking k_elimination_divider/divmod/div_by_7: Warming up for 3.0000 s
Benchmarking k_elimination_divider/divmod/div_by_7: Collecting 100 samples in estimated 5.0002 s (94M iterations)
Benchmarking k_elimination_divider/divmod/div_by_7: Analyzing
k_elimination_divider/divmod/div_by_7
                        time:   [52.732 ns 52.920 ns 53.139 ns]
Found 7 outliers among 100 measurements (7.00%)
  1 (1.00%) low severe
  2 (2.00%) low mild
  2 (2.00%) high mild
  2 (2.00%) high severe
Benchmarking k_elimination_divider/scale_and_round/bfv_like
Benchmarking k_elimination_divider/scale_and_round/bfv_like: Warming up for 3.0000 s
Benchmarking k_elimination_divider/scale_and_round/bfv_like: Collecting 100 samples in estimated 5.0001 s (81M iterations)
Benchmarking k_elimination_divider/scale_and_round/bfv_like: Analyzing
k_elimination_divider/scale_and_round/bfv_like
                        time:   [61.021 ns 61.285 ns 61.604 ns]
Found 4 outliers among 100 measurements (4.00%)
  2 (2.00%) high mild
  2 (2.00%) high severe

Benchmarking ntt_ct/ntt/small
Benchmarking ntt_ct/ntt/small: Warming up for 3.0000 s
Benchmarking ntt_ct/ntt/small: Collecting 100 samples in estimated 5.0333 s (692k iterations)
Benchmarking ntt_ct/ntt/small: Analyzing
ntt_ct/ntt/small        time:   [7.2333 µs 7.2979 µs 7.3994 µs]
Found 2 outliers among 100 measurements (2.00%)
  1 (1.00%) high mild
  1 (1.00%) high severe
Benchmarking ntt_ct/ntt/large
Benchmarking ntt_ct/ntt/large: Warming up for 3.0000 s
Benchmarking ntt_ct/ntt/large: Collecting 100 samples in estimated 5.0306 s (687k iterations)
Benchmarking ntt_ct/ntt/large: Analyzing
ntt_ct/ntt/large        time:   [7.2829 µs 7.3148 µs 7.3508 µs]
Found 8 outliers among 100 measurements (8.00%)
  8 (8.00%) high mild
Benchmarking ntt_ct/intt/small
Benchmarking ntt_ct/intt/small: Warming up for 3.0000 s
Benchmarking ntt_ct/intt/small: Collecting 100 samples in estimated 5.0157 s (616k iterations)
Benchmarking ntt_ct/intt/small: Analyzing
ntt_ct/intt/small       time:   [8.1177 µs 8.1614 µs 8.2088 µs]
Found 3 outliers among 100 measurements (3.00%)
  1 (1.00%) low mild
  2 (2.00%) high mild
Benchmarking ntt_ct/intt/large
Benchmarking ntt_ct/intt/large: Warming up for 3.0000 s
Benchmarking ntt_ct/intt/large: Collecting 100 samples in estimated 5.0017 s (606k iterations)
Benchmarking ntt_ct/intt/large: Analyzing
ntt_ct/intt/large       time:   [8.2096 µs 8.2522 µs 8.2985 µs]
Found 8 outliers among 100 measurements (8.00%)
  8 (8.00%) high mild
Benchmarking ntt_ct/multiply/small
Benchmarking ntt_ct/multiply/small: Warming up for 3.0000 s
Benchmarking ntt_ct/multiply/small: Collecting 100 samples in estimated 5.0127 s (202k iterations)
Benchmarking ntt_ct/multiply/small: Analyzing
ntt_ct/multiply/small   time:   [24.254 µs 24.427 µs 24.602 µs]
Found 4 outliers among 100 measurements (4.00%)
  2 (2.00%) high mild
  2 (2.00%) high severe
Benchmarking ntt_ct/multiply/large
Benchmarking ntt_ct/multiply/large: Warming up for 3.0000 s
Benchmarking ntt_ct/multiply/large: Collecting 100 samples in estimated 5.0328 s (192k iterations)
Benchmarking ntt_ct/multiply/large: Analyzing
ntt_ct/multiply/large   time:   [26.175 µs 26.409 µs 26.661 µs]
Found 2 outliers among 100 measurements (2.00%)
  1 (1.00%) high mild
  1 (1.00%) high severe

Benchmarking rns_kelim_rescale/k_elim_rescale
Benchmarking rns_kelim_rescale/k_elim_rescale: Warming up for 3.0000 s
Benchmarking rns_kelim_rescale/k_elim_rescale: Collecting 100 samples in estimated 5.3236 s (1500 iterations)
Benchmarking rns_kelim_rescale/k_elim_rescale: Analyzing
rns_kelim_rescale/k_elim_rescale
                        time:   [3.4993 ms 3.5121 ms 3.5258 ms]
Found 1 outliers among 100 measurements (1.00%)
  1 (1.00%) high severe

Benchmarking ntt_fft/multiply/1024
Benchmarking ntt_fft/multiply/1024: Warming up for 3.0000 s
Benchmarking ntt_fft/multiply/1024: Collecting 100 samples in estimated 5.4588 s (20k iterations)
Benchmarking ntt_fft/multiply/1024: Analyzing
ntt_fft/multiply/1024   time:   [267.11 µs 268.44 µs 270.19 µs]
Found 5 outliers among 100 measurements (5.00%)
  3 (3.00%) high mild
  2 (2.00%) high severe
Benchmarking ntt_fft/multiply/4096
Benchmarking ntt_fft/multiply/4096: Warming up for 3.0000 s

Warning: Unable to complete 100 samples in 5.0s. You may wish to increase target time to 6.6s, enable flat sampling, or reduce sample count to 60.
Benchmarking ntt_fft/multiply/4096: Collecting 100 samples in estimated 6.5960 s (5050 iterations)
Benchmarking ntt_fft/multiply/4096: Analyzing
ntt_fft/multiply/4096   time:   [1.3070 ms 1.3168 ms 1.3289 ms]
Found 8 outliers among 100 measurements (8.00%)
  1 (1.00%) low severe
  4 (4.00%) high mild
  3 (3.00%) high severe

```


### Secure Config FHE Ops (secure_128)

Command:
```
cargo test -p nine65 --lib --release --features shadow-entropy ops::gso_fhe::arithmetic_benchmarks::benchmark_fhe_ops_secure_128 -- --nocapture
```

Output:
```
warning: profiles for the non root package will be ignored, specify profiles at the workspace root:
package:   /home/acid/Projects/NINE65/v5/crates/exact_transcendentals/Cargo.toml
workspace: /home/acid/Projects/NINE65/v5/Cargo.toml
   Compiling nine65 v0.1.0 (/home/acid/Projects/NINE65/v5/crates/nine65)
    Finished `release` profile [optimized] target(s) in 1m 08s
     Running unittests src/lib.rs (target/release/deps/nine65-c3c5577b7eb6e698)

running 1 test

┌────────────────────────────────────────────────────────────┐
│  FHE OPERATIONS (GSO-FHE) - secure_128           │
└────────────────────────────────────────────────────────────┘
  Operation      │ Time        │ Ops/sec     │ ms/op
  ───────────────┼─────────────┼─────────────┼────────
  FHE_ENCRYPT    │   1178.45ms │          42 │  23.56
  FHE_ADD        │     41.77ms │        1196 │   0.83
  FHE_MUL        │   7606.68ms │           6 │ 152.13
  FHE_DECRYPT    │    553.29ms │          90 │  11.06
test ops::gso_fhe::arithmetic_benchmarks::benchmark_fhe_ops_secure_128 ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 499 filtered out; finished in 9.53s

```


### Secure Config FHE Ops (secure_192)

Command:
```
cargo test -p nine65 --lib --release --features shadow-entropy ops::gso_fhe::arithmetic_benchmarks::benchmark_fhe_ops_secure_192 -- --nocapture
```

Output:
```
warning: profiles for the non root package will be ignored, specify profiles at the workspace root:
package:   /home/acid/Projects/NINE65/v5/crates/exact_transcendentals/Cargo.toml
workspace: /home/acid/Projects/NINE65/v5/Cargo.toml
    Finished `release` profile [optimized] target(s) in 0.08s
     Running unittests src/lib.rs (target/release/deps/nine65-c3c5577b7eb6e698)

running 1 test

┌────────────────────────────────────────────────────────────┐
│  FHE OPERATIONS (GSO-FHE) - secure_192           │
└────────────────────────────────────────────────────────────┘
  Operation      │ Time        │ Ops/sec     │ ms/op
  ───────────────┼─────────────┼─────────────┼────────
  FHE_ENCRYPT    │   1847.88ms │          16 │  61.59
  FHE_ADD        │     63.13ms │         475 │   2.10
  FHE_MUL        │  13770.77ms │           2 │ 459.02
  FHE_DECRYPT    │    870.04ms │          34 │  29.00
test ops::gso_fhe::arithmetic_benchmarks::benchmark_fhe_ops_secure_192 ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 499 filtered out; finished in 16.99s

```


### Symmetric Max Depth (secure_128)

Command:
```
cargo test -p nine65 --lib --release ops::gso_fhe::depth_benchmarks::benchmark_symmetric_max_depth_secure_128 -- --nocapture
```

Output:
```
warning: profiles for the non root package will be ignored, specify profiles at the workspace root:
package:   /home/acid/Projects/NINE65/v5/crates/exact_transcendentals/Cargo.toml
workspace: /home/acid/Projects/NINE65/v5/Cargo.toml
   Compiling nine65 v0.1.0 (/home/acid/Projects/NINE65/v5/crates/nine65)
    Finished `release` profile [optimized] target(s) in 1m 05s
     Running unittests src/lib.rs (target/release/deps/nine65-56c87ff246e95a3f)

running 1 test
SECURE_128 MAX DEPTH: 50 multiplicative levels
Total collapses: 0
Total time: 6.290957759s
Avg time/mul: 125.81ms
test ops::gso_fhe::depth_benchmarks::benchmark_symmetric_max_depth_secure_128 ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 458 filtered out; finished in 6.42s

```


### Symmetric Max Depth (secure_192)

Command:
```
cargo test -p nine65 --lib --release ops::gso_fhe::depth_benchmarks::benchmark_symmetric_max_depth_secure_192 -- --nocapture
```

Output:
```
warning: profiles for the non root package will be ignored, specify profiles at the workspace root:
package:   /home/acid/Projects/NINE65/v5/crates/exact_transcendentals/Cargo.toml
workspace: /home/acid/Projects/NINE65/v5/Cargo.toml
    Finished `release` profile [optimized] target(s) in 0.08s
     Running unittests src/lib.rs (target/release/deps/nine65-56c87ff246e95a3f)

running 1 test
SECURE_192 MAX DEPTH: 50 multiplicative levels
Total collapses: 0
Total time: 10.095945343s
Avg time/mul: 201.91ms
test ops::gso_fhe::depth_benchmarks::benchmark_symmetric_max_depth_secure_192 ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 458 filtered out; finished in 10.48s

```

## Claim-Grade Summary

| Operation | secure_128 (ms) | secure_192 (ms) |
|---|---:|---:|
| Encrypt | 23.56 | 61.59 |
| Add | 0.83 | 2.10 |
| Mul | 152.13 | 459.02 |
| Decrypt | 11.06 | 29.00 |

| Depth benchmark | secure_128 total (s) | secure_192 total (s) |
|---|---:|---:|
| symmetric depth-50 | 6.29 | 10.10 |

## Criterion Artifacts

- Machine-readable summary: `docs/PERFORMANCE_BASELINE_2026-02-11_criterion.json`
- Raw Criterion tree: `target/criterion/`

The criterion summary above is now the source for K-Elimination micro-op timings
to avoid timer-resolution artifacts (e.g., historical 0 ns rows).
