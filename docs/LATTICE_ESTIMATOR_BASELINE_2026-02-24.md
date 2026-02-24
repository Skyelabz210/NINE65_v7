# Lattice Estimator Baseline (2026-02-24)

Command:
- cargo run -p nine65 --bin security_estimator_baseline

## Environment
- Timestamp (UTC): 2026-02-24T15:28:10Z
- OS: Linux devbox 6.8.0 #1 SMP PREEMPT_DYNAMIC Wed Jan 14 23:11:35 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux
- CPU: Intel(R) Xeon(R) Processor @ 2.30GHz
- Rust: rustc 1.92.0 (ded5c06cf 2025-12-08)
- Cargo: cargo 1.92.0 (344c4567c 2025-10-21)
- Commit: 1c12422
- Benchmark profile class: secure (claim-grade)

## Results (Core-SVP)
| SecureConfig | n | log2(q) | min attack log2(rop) | cost model |
| --- | --- | --- | --- | --- |
| secure_128 | 4096 | 89.08 | 129 | core-svp |
| secure_192 | 16384 | 145.08 | 318 | core-svp |
| secure_256 | 16384 | 174.18 | 264 | core-svp |
