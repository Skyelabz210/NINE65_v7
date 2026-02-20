# Lattice Estimator Baseline (2026-02-09)

Command:
- cargo run -p nine65 --bin security_estimator_baseline

## Environment
- OS: Linux coreI7 6.12.48+deb13-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.12.48-1 (2025-09-20) x86_64 GNU/Linux
- Rust: rustc 1.90.0 (1159e78c4 2025-09-14)
- Cargo: cargo 1.90.0 (840b83a10 2025-07-30)

## Results (Core-SVP)
| SecureConfig | n | log2(q) | min attack log2(rop) | cost model |
| --- | --- | --- | --- | --- |
| secure_128 | 4096 | 89.08 | 129 | core-svp |
| secure_192 | 8192 | 145.08 | 159 | core-svp |
| secure_256 | 16384 | 203.38 | 226 | core-svp |
