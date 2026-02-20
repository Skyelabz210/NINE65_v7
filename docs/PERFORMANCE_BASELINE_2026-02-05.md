# Performance Baseline (2026-02-05)

Results are hardware- and config-dependent; re-run on your target hardware and
record updated baselines when publishing.

## Environment
- OS: Linux coreI7 6.12.48+deb13-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.12.48-1 (2025-09-20) x86_64 GNU/Linux
- CPU: Intel(R) Core(TM) i7-3632QM CPU @ 2.20GHz
- Rust: rustc 1.90.0 (1159e78c4 2025-09-14)
- Cargo: cargo 1.90.0 (840b83a10 2025-07-30)

## Commands

### Full Arithmetic Benchmark (light_rns_exact)

Command:
```
cargo test -p nine65 --lib --release --features shadow-entropy ops::gso_fhe::arithmetic_benchmarks::benchmark_full_arithmetic -- --nocapture
```

Output:
```
    Finished `release` profile [optimized] target(s) in 0.09s
     Running unittests src/lib.rs (target/release/deps/nine65-c3c5577b7eb6e698)

running 1 test

╔══════════════════════════════════════════════════════════════╗
║          NINE65 FULL ARITHMETIC BENCHMARK                    ║
╚══════════════════════════════════════════════════════════════╝

┌────────────────────────────────────────────────────────────┐
│  RNS ARITHMETIC (4-lane parallel)                         │
└────────────────────────────────────────────────────────────┘
  Operation      │ Time        │ Ops/sec     │ ns/op
  ───────────────┼─────────────┼─────────────┼────────
  ADD            │      5.21ms │    1.92e7 │   52.1
  SUB            │      6.40ms │    1.56e7 │   64.0
  MUL            │      9.52ms │    1.05e7 │   95.2
  MUL+Signature  │     10.29ms │    9.71e6 │  102.9

┌────────────────────────────────────────────────────────────┐
│  EXACT DIVISION (K-Elimination)                            │
└────────────────────────────────────────────────────────────┘
  Operation      │ Time        │ Ops/sec     │ ns/op
  ───────────────┼─────────────┼─────────────┼────────
  RECONSTRUCT    │      0.00ms │   1.25e12 │    0.0
  EXACT_DIVIDE   │      0.00ms │   4.13e11 │    0.0
  DIVMOD         │      0.00ms │   2.22e12 │    0.0
  SCALE_ROUND    │      0.00ms │   1.72e12 │    0.0

┌────────────────────────────────────────────────────────────┐
│  EXACT COEFFICIENT ARITHMETIC (Dual-Track)                 │
└────────────────────────────────────────────────────────────┘
  Operation      │ Time        │ Ops/sec     │ ns/op
  ───────────────┼─────────────┼─────────────┼────────
  COEFF_ADD      │      5.99ms │    1.67e7 │   59.9
  COEFF_MUL      │      8.33ms │    1.20e7 │   83.3
  COEFF_DIV      │      5.39ms │    1.86e7 │   53.9
  COEFF_SCALE    │      5.06ms │    1.98e7 │   50.6

┌────────────────────────────────────────────────────────────┐
│  FHE OPERATIONS (GSO-FHE)                                  │
└────────────────────────────────────────────────────────────┘
  Operation      │ Time        │ Ops/sec     │ ms/op
  ───────────────┼─────────────┼─────────────┼────────
  FHE_ENCRYPT    │    458.67ms │    2.18e2 │   4.59
  FHE_ADD        │     19.71ms │    5.07e3 │   0.20
  FHE_MUL        │   2803.47ms │    3.57e1 │  28.03
  FHE_DECRYPT    │    207.32ms │    4.82e2 │   2.07

╔══════════════════════════════════════════════════════════════╗
║                      SUMMARY                                 ║
╠══════════════════════════════════════════════════════════════╣
║  RNS 4-lane:                                                 ║
║    ADD:              52 ns   ( 19.19M ops/sec)               ║
║    MUL:              95 ns   ( 10.51M ops/sec)               ║
║                                                              ║
║  K-Elimination Division:                                     ║
║    EXACT_DIV:         0 ns   (413223.14M ops/sec)               ║
║    SCALE:             0 ns   (1724137.93M ops/sec)               ║
║                                                              ║
║  FHE Operations:                                             ║
║    ENCRYPT:        4.59 ms                                    ║
║    ADD:            0.20 ms                                    ║
║    MUL:           28.03 ms                                    ║
║    DECRYPT:        2.07 ms                                    ║
╚══════════════════════════════════════════════════════════════╝

test ops::gso_fhe::arithmetic_benchmarks::benchmark_full_arithmetic ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 464 filtered out; finished in 3.57s

```


### Secure Config FHE Ops (secure_128)

Command:
```
cargo test -p nine65 --lib --release --features shadow-entropy ops::gso_fhe::arithmetic_benchmarks::benchmark_fhe_ops_secure_128 -- --nocapture
```

Output:
```
    Finished `release` profile [optimized] target(s) in 0.08s
     Running unittests src/lib.rs (target/release/deps/nine65-c3c5577b7eb6e698)

running 1 test

┌────────────────────────────────────────────────────────────┐
│  FHE OPERATIONS (GSO-FHE) - secure_128           │
└────────────────────────────────────────────────────────────┘
  Operation      │ Time        │ Ops/sec     │ ms/op
  ───────────────┼─────────────┼─────────────┼────────
  FHE_ENCRYPT    │   1185.12ms │    4.22e1 │  23.70
  FHE_ADD        │     43.48ms │    1.15e3 │   0.87
  FHE_MUL        │   7171.16ms │    6.97e0 │ 143.42
  FHE_DECRYPT    │    550.49ms │    9.08e1 │  11.01
test ops::gso_fhe::arithmetic_benchmarks::benchmark_fhe_ops_secure_128 ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 464 filtered out; finished in 9.10s

```


### Secure Config FHE Ops (secure_192)

Command:
```
cargo test -p nine65 --lib --release --features shadow-entropy ops::gso_fhe::arithmetic_benchmarks::benchmark_fhe_ops_secure_192 -- --nocapture
```

Output:
```
    Finished `release` profile [optimized] target(s) in 0.10s
     Running unittests src/lib.rs (target/release/deps/nine65-c3c5577b7eb6e698)

running 1 test

┌────────────────────────────────────────────────────────────┐
│  FHE OPERATIONS (GSO-FHE) - secure_192           │
└────────────────────────────────────────────────────────────┘
  Operation      │ Time        │ Ops/sec     │ ms/op
  ───────────────┼─────────────┼─────────────┼────────
  FHE_ENCRYPT    │   1927.24ms │    1.56e1 │  64.24
  FHE_ADD        │     65.64ms │    4.57e2 │   2.19
  FHE_MUL        │  12691.75ms │    2.36e0 │ 423.06
  FHE_DECRYPT    │    892.70ms │    3.36e1 │  29.76
test ops::gso_fhe::arithmetic_benchmarks::benchmark_fhe_ops_secure_192 ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 464 filtered out; finished in 16.03s

```


### Symmetric Max Depth (secure_128)

Command:
```
cargo test -p nine65 --lib --release ops::gso_fhe::depth_benchmarks::benchmark_symmetric_max_depth_secure_128 -- --nocapture
```

Output:
```
    Finished `release` profile [optimized] target(s) in 0.09s
     Running unittests src/lib.rs (target/release/deps/nine65-56c87ff246e95a3f)

running 1 test
SECURE_128 MAX DEPTH: 50 multiplicative levels
Total collapses: 0
Total time: 7.737978771s
Avg time/mul: 154.76ms
test ops::gso_fhe::depth_benchmarks::benchmark_symmetric_max_depth_secure_128 ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 423 filtered out; finished in 7.87s

```


### Symmetric Max Depth (secure_192)

Command:
```
cargo test -p nine65 --lib --release ops::gso_fhe::depth_benchmarks::benchmark_symmetric_max_depth_secure_192 -- --nocapture
```

Output:
```
    Finished `release` profile [optimized] target(s) in 0.09s
     Running unittests src/lib.rs (target/release/deps/nine65-56c87ff246e95a3f)

running 1 test
SECURE_192 MAX DEPTH: 50 multiplicative levels
Total collapses: 0
Total time: 23.150145012s
Avg time/mul: 463.00ms
test ops::gso_fhe::depth_benchmarks::benchmark_symmetric_max_depth_secure_192 ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 423 filtered out; finished in 23.54s

```

