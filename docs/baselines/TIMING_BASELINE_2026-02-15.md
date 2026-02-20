# Timing Baseline — 2026-02-15

## Environment
- Build: debug profile (unoptimized + debuginfo)
- CPU: AMD64
- OS: Linux 6.12.48+deb13-amd64
- Rust: stable
- Config: SecureConfig::test_fast() (N=1024, 30-bit primes)

## Baseline Measurements

| Operation | Iterations | Total Time | Per-Call |
|-----------|-----------|------------|---------|
| KeyGen (deterministic) | 100 | 1.075s | ~10.7ms |
| KeyGen (secure/CSPRNG) | 100 | 2.010s | ~20.1ms |
| Encrypt (BFV) | 1000 | 4.779s | ~4.8ms |
| GRO-gated keygen | 10 | ~190ms | ~19.0ms |

## GRO Timing Variance

- Mean: 18,966,730 ns (~19.0ms)
- Max deviation: 1,699,091 ns (~1.7ms)
- Variance ratio: 8%
- Target: <5% (software GRO simulation; hardware DDS achieves lower variance)

## Notes

- Debug mode is ~5-10x slower than release; use release baselines for production comparison
- CSPRNG keygen is ~2x slower than deterministic (expected: OS entropy syscalls)
- GRO gate adds negligible overhead (window search is < 1ms)

## Test Count at Baseline

- Default features: 1,039 passed, 0 failed
- With clockwork feature: 589 passed (nine65 lib only), 0 failed
