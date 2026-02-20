# Performance Baseline (2026-01-27)

This baseline captures the current performance output used to support README tables.
Results are hardware- and config-dependent; re-run on your target hardware and
record updated baselines when publishing. README FHE ops and depth use secure_128
and secure_192 baselines below.

## Environment

- OS: Linux coreI7 6.12.48+deb13-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.12.48-1 (2025-09-20) x86_64 GNU/Linux
- CPU: Intel(R) Core(TM) i7-3632QM CPU @ 2.20GHz (4C/8T, max 3.2GHz)
- Rust: rustc 1.90.0 (1159e78c4 2025-09-14)
- Cargo: 1.90.0 (840b83a10 2025-07-30)

## Commands

### Full Arithmetic Benchmark (test config, light_rns_exact)

```
cargo test -p nine65 --lib --release --features shadow-entropy \
  ops::gso_fhe::arithmetic_benchmarks::benchmark_full_arithmetic -- --nocapture
```

Key output (light_rns_exact, test config):

RNS Arithmetic (4-lane):
- ADD: 65.7 ns (1.52e7 ops/sec)
- SUB: 52.9 ns (1.89e7 ops/sec)
- MUL: 95.6 ns (1.05e7 ops/sec)
- MUL+Signature: 100.0 ns (1.00e7 ops/sec)

Exact Coefficient Arithmetic (Dual-Track):
- COEFF_ADD: 60.0 ns (1.67e7 ops/sec)
- COEFF_MUL: 84.0 ns (1.19e7 ops/sec)
- COEFF_DIV: 53.5 ns (1.87e7 ops/sec)
- COEFF_SCALE: 53.7 ns (1.86e7 ops/sec)

FHE Operations (GSO-FHE, test config):
- ENCRYPT: 4.76 ms
- ADD: 0.19 ms
- MUL: 26.51 ms
- DECRYPT: 2.16 ms

Note: These FHE ops are from the light_rns_exact test config. README FHE ops and
depth use secure_128 and secure_192 baselines below.

### Secure Config FHE Ops (secure_128)

```
cargo test -p nine65 --lib --release --features shadow-entropy \
  ops::gso_fhe::arithmetic_benchmarks::benchmark_fhe_ops_secure_128 -- --ignored --nocapture
```

Key output (secure_128):
- ENCRYPT: 23.93 ms
- ADD: 0.91 ms
- MUL: 125.01 ms
- DECRYPT: 11.17 ms

### Secure Config FHE Ops (secure_192)

```
cargo test -p nine65 --lib --release --features shadow-entropy \
  ops::gso_fhe::arithmetic_benchmarks::benchmark_fhe_ops_secure_192 -- --ignored --nocapture
```

Key output (secure_192):
- ENCRYPT: 62.14 ms
- ADD: 2.18 ms
- MUL: 411.55 ms
- DECRYPT: 28.88 ms

### Secure Config Symmetric Max Depth (secure_128)

```
cargo test -p nine65 --lib --release \
  ops::gso_fhe::depth_benchmarks::benchmark_symmetric_max_depth_secure_128 -- --ignored --nocapture
```

Key output (secure_128):
- Symmetric max depth: 50 multiplicative levels
- Total collapses: 0
- Total time: 6.147476487 s
- Avg time per mul: 122.95 ms

### Secure Config Symmetric Max Depth (secure_192)

```
cargo test -p nine65 --lib --release \
  ops::gso_fhe::depth_benchmarks::benchmark_symmetric_max_depth_secure_192 -- --ignored --nocapture
```

Key output (secure_192):
- Symmetric max depth: 50 multiplicative levels
- Total collapses: 0
- Total time: 22.624989769 s
- Avg time per mul: 452.50 ms

## Notes

- Benchmarks are hardware- and config-dependent.
- secure_192 uses U256 rescale/modswitch paths; re-run after parameter changes.
- For release gating, record the exact machine, Rust version, and command output.
