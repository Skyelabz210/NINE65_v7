# Pre-Upgrade Metrics Summary (Before exact_transcendentals Integration)

Timestamp (UTC): 2026-02-09T09:24:37Z
NINE65 commit: `58fec6006fc455a70b65d9ad0018cc9e137511ac` (branch `main`)
Host: Linux coreI7 6.12.48+deb13-amd64 x86_64
Toolchain: rustc 1.90.0, cargo 1.90.0
Neighbor project identified: `/home/acid/Projects/exact_transcendentals` (commit `5ba6146`)

## 1) Correctness Baseline (release)

| Suite | Result |
|---|---|
| nine65 core (`cargo test -p nine65 --lib --release`) | 459 passed, 0 failed |
| mana | 30 passed, 0 failed |
| clockwork-core | 46 passed, 0 failed |
| nexgen_rational | 95 passed, 0 failed |
| unhal | 10 passed, 0 failed |

Raw logs: `nine65_core_tests.log`, `mana_tests.log`, `clockwork_core_tests.log`, `nexgen_rational_tests.log`, `unhal_tests.log`

## 2) Core Performance Baseline

From `PERFORMANCE_BASELINE_2026-02-09.md`:
- Full arithmetic (light_rns_exact):
  - FHE encrypt 4.35 ms, add 0.17 ms, mul 26.45 ms, decrypt 1.98 ms
  - RNS summary: add 52 ns, mul 91 ns
- Secure FHE ops:
  - secure_128: encrypt 22.57 ms, add 0.82 ms, mul 146.38 ms, decrypt 10.36 ms
  - secure_192: encrypt 60.15 ms, add 2.03 ms, mul 444.23 ms, decrypt 28.01 ms
- Symmetric depth benchmarks:
  - secure_128: depth 50, 0 collapses, total 6.118996139 s, avg 122.37 ms/mul
  - secure_192: depth 50, 0 collapses, total 9.785933914 s, avg 195.71 ms/mul

## 3) Extended Benchmarks (additional)

- CRT Shadow throughput: 9,258,830 ops/sec; 296.28 Mbits/sec entropy (`crt_shadow_throughput.log`)
- Signature overhead benchmark: 100k ops, reported overhead 0.0% (`crt_shadow_signature_overhead.log`)
- WASSAN benchmark (perf enabled): 1M samples in 12.050701 ms (~12 ns/sample) (`wassan_vs_shadow.log`)
- 1024-point NTT benchmark: x100 multiplies in 1.639187499 s (`ntt_benchmark_1024.log`)
- Persistent Montgomery benchmark: reported `0 ns/mul` (timer-resolution bound), 86,956,521 M ops/sec (`persistent_montgomery_benchmark.log`)
- Parallel throughput benchmark: encrypt 1000 msgs in 117.695 ms (117.695 us/msg), decrypt 1000 msgs in 50.545 ms (50.544 us/msg) (`parallel_throughput_benchmark.log`)
- Entropy during FHE (shadow): 1,000,000 ops in 118.730 ms, 8,422,456 ops/sec, 32,000,000 bits harvested (`entropy_during_fhe.log`)
- Full system integration: depth 20, 0 collapses, 640 bits harvested, total 530.964 ms (`full_system_integration.log`)

## 4) Artifact Index

Primary artifacts for pre-upgrade comparison:
- `PERFORMANCE_BASELINE_2026-02-09.md`
- `LATTICE_ESTIMATOR_BASELINE_2026-02-09.md`
- `PRE_UPGRADE_METRICS_SUMMARY.md`
- `extra_bench_status.tsv`, `test_suite_status.tsv`
- all `*.log` files in this directory
