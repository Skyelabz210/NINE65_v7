# FHE Benchmark Comparison (Exploratory, Non-Claim)

## Status

This document is exploratory context, not a publication-grade claim source.

Benchmark profile policy and claim mapping are enforced by:
- `docs/BENCHMARK_PROFILE_POLICY.md`
- `docs/CLAIM_REGISTRY.csv`

Claim-grade NINE65 performance must be sourced from:
- `docs/PERFORMANCE_BASELINE_2026-02-11.md`
- `docs/LATTICE_ESTIMATOR_BASELINE_2026-02-09.md`

Do not use this file alone for public "faster than X" statements.

---

## NINE65 Claim Profile (Secure Configs)

Measured values below are direct excerpts from `docs/PERFORMANCE_BASELINE_2026-02-11.md`
using secure profiles (`secure_128`, `secure_192`).

| Metric | secure_128 | secure_192 |
|---|---:|---:|
| Encrypt | 23.56 ms | 61.59 ms |
| Add | 0.83 ms | 2.10 ms |
| Mul | 152.13 ms | 459.02 ms |
| Decrypt | 11.06 ms | 29.00 ms |
| Symmetric depth | 50 | 50 |
| Depth-50 total time | 6.29 s | 10.10 s |
| Bootstraps | 0 | 0 |

These are the only benchmark numbers currently approved for README claim usage.

---

## Internal Test Profile (Non-Claim)

Historically, some comparisons used `FHEConfig::light_rns_exact()` to tune algorithms.
Those numbers are useful for internal iteration only and are not claim-grade.

Rule:
- Secure profile (`secure_128` / `secure_192`) -> can support public claims.
- Light/test profile (`light*`, `he_standard_128`, `test_*`) -> internal only.

---

## External Ecosystem Context (Non-Normalized)

External figures below are high-level ranges from public reports. They are not normalized
to identical hardware, parameters, ciphertext shapes, or workloads.

| Library | Publicly reported characteristics (high-level) |
|---|---|
| OpenFHE | Leveled and bootstrapped modes; depth and latency vary by scheme/params |
| Microsoft SEAL | Strong leveled BFV/CKKS focus; practical depth depends on modulus chain |
| TFHE-rs | Fast programmable bootstrapping paths, often GPU-accelerated in top reports |
| HElib | Mature BGV/CKKS stack; performance depends heavily on parameterization |

Interpretation policy:
- Treat these entries as qualitative context, not direct speedup evidence.
- Any direct cross-library claim requires a comparator manifest with parameter mapping,
  hardware parity, and reproducible scripts/artifacts.

---

## Claim Hygiene Requirements

Before adding or updating benchmark claims:
1. Re-run secure baselines and store artifacts under `docs/`.
2. Record environment metadata (OS, CPU, Rust/Cargo versions).
3. Link each README claim to an explicit artifact path.
4. Reject claims derived from light/test configs.

---

## Source Links

- Cross-Platform FHE Benchmarks (2025): https://arxiv.org/abs/2503.11216v2
- SEAL vs OpenFHE Performance Analysis: https://eprint.iacr.org/2025/473.pdf
- Zama TFHE bootstrapping report: https://www.zama.org/post/bootstrapping-tfhe-ciphertexts-in-less-than-one-millisecond
- FHEBench repository: https://github.com/TrustworthyComputing/T2-FHE-Compiler-and-Benchmarks
