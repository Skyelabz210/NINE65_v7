# Performance Baseline (2026-02-09)

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
   Compiling nine65 v0.1.0 (/home/acid/Projects/NINE65/v5/crates/nine65)
    Finished `release` profile [optimized] target(s) in 1m 02s
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
  ADD            │      5.26ms │    18977017 │     52
  SUB            │      6.14ms │    16275517 │     61
  MUL            │      9.14ms │    10940451 │     91
  MUL+Signature  │     11.11ms │     8995177 │    111

┌────────────────────────────────────────────────────────────┐
│  EXACT DIVISION (K-Elimination)                            │
└────────────────────────────────────────────────────────────┘
  Operation      │ Time        │ Ops/sec     │ ns/op
  ───────────────┼─────────────┼─────────────┼────────
  RECONSTRUCT    │      0.00ms │ 2222222222222 │      0
  EXACT_DIVIDE   │      0.00ms │ 943396226415 │      0
  DIVMOD         │      0.00ms │ 3448275862068 │      0
  SCALE_ROUND    │      0.00ms │ 3333333333333 │      0

┌────────────────────────────────────────────────────────────┐
│  EXACT COEFFICIENT ARITHMETIC (Dual-Track)                 │
└────────────────────────────────────────────────────────────┘
  Operation      │ Time        │ Ops/sec     │ ns/op
  ───────────────┼─────────────┼─────────────┼────────
  COEFF_ADD      │      5.77ms │    17322166 │     57
  COEFF_MUL      │      7.60ms │    13151438 │     76
  COEFF_DIV      │      4.93ms │    20243599 │     49
  COEFF_SCALE    │      4.94ms │    20222790 │     49

┌────────────────────────────────────────────────────────────┐
│  FHE OPERATIONS (GSO-FHE)                                  │
└────────────────────────────────────────────────────────────┘
  Operation      │ Time        │ Ops/sec     │ ms/op
  ───────────────┼─────────────┼─────────────┼────────
  FHE_ENCRYPT    │    435.69ms │         229 │   4.35
  FHE_ADD        │     17.73ms │        5639 │   0.17
  FHE_MUL        │   2645.17ms │          37 │  26.45
  FHE_DECRYPT    │    198.64ms │         503 │   1.98

╔══════════════════════════════════════════════════════════════╗
║                      SUMMARY                                 ║
╠══════════════════════════════════════════════════════════════╣
║  RNS 4-lane:                                                 ║
║    ADD:              52 ns   (    18M ops/sec)               ║
║    MUL:              91 ns   (    10M ops/sec)               ║
║                                                              ║
║  K-Elimination Division:                                     ║
║    EXACT_DIV:         0 ns   (943396M ops/sec)               ║
║    SCALE:             0 ns   (3333333M ops/sec)               ║
║                                                              ║
║  FHE Operations:                                             ║
║    ENCRYPT:        4.35 ms                                    ║
║    ADD:            0.17 ms                                    ║
║    MUL:           26.45 ms                                    ║
║    DECRYPT:        1.98 ms                                    ║
╚══════════════════════════════════════════════════════════════╝

test ops::gso_fhe::arithmetic_benchmarks::benchmark_full_arithmetic ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 499 filtered out; finished in 3.38s

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
  FHE_ENCRYPT    │   1128.52ms │          44 │  22.57
  FHE_ADD        │     41.32ms │        1209 │   0.82
  FHE_MUL        │   7319.06ms │           6 │ 146.38
  FHE_DECRYPT    │    518.43ms │          96 │  10.36
test ops::gso_fhe::arithmetic_benchmarks::benchmark_fhe_ops_secure_128 ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 499 filtered out; finished in 9.16s

```


### Secure Config FHE Ops (secure_192)

Command:
```
cargo test -p nine65 --lib --release --features shadow-entropy ops::gso_fhe::arithmetic_benchmarks::benchmark_fhe_ops_secure_192 -- --nocapture
```

Output:
```
    Finished `release` profile [optimized] target(s) in 0.07s
     Running unittests src/lib.rs (target/release/deps/nine65-c3c5577b7eb6e698)

running 1 test

┌────────────────────────────────────────────────────────────┐
│  FHE OPERATIONS (GSO-FHE) - secure_192           │
└────────────────────────────────────────────────────────────┘
  Operation      │ Time        │ Ops/sec     │ ms/op
  ───────────────┼─────────────┼─────────────┼────────
  FHE_ENCRYPT    │   1804.53ms │          16 │  60.15
  FHE_ADD        │     60.91ms │         492 │   2.03
  FHE_MUL        │  13327.07ms │           2 │ 444.23
  FHE_DECRYPT    │    840.34ms │          35 │  28.01
test ops::gso_fhe::arithmetic_benchmarks::benchmark_fhe_ops_secure_192 ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 499 filtered out; finished in 16.46s

```


### Symmetric Max Depth (secure_128)

Command:
```
cargo test -p nine65 --lib --release ops::gso_fhe::depth_benchmarks::benchmark_symmetric_max_depth_secure_128 -- --nocapture
```

Output:
```
    Finished `release` profile [optimized] target(s) in 0.08s
     Running unittests src/lib.rs (target/release/deps/nine65-56c87ff246e95a3f)

running 1 test
SECURE_128 MAX DEPTH: 50 multiplicative levels
Total collapses: 0
Total time: 6.118996139s
Avg time/mul: 122.37ms
test ops::gso_fhe::depth_benchmarks::benchmark_symmetric_max_depth_secure_128 ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 458 filtered out; finished in 6.25s

```


### Symmetric Max Depth (secure_192)

Command:
```
cargo test -p nine65 --lib --release ops::gso_fhe::depth_benchmarks::benchmark_symmetric_max_depth_secure_192 -- --nocapture
```

Output:
```
    Finished `release` profile [optimized] target(s) in 0.08s
     Running unittests src/lib.rs (target/release/deps/nine65-56c87ff246e95a3f)

running 1 test
SECURE_192 MAX DEPTH: 50 multiplicative levels
Total collapses: 0
Total time: 9.785933914s
Avg time/mul: 195.71ms
test ops::gso_fhe::depth_benchmarks::benchmark_symmetric_max_depth_secure_192 ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 458 filtered out; finished in 10.15s

```

