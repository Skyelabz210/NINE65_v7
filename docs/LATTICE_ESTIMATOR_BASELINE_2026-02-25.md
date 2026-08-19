# Lattice Estimator Baseline (2026-02-25)

> **Provenance and staleness (2026-08-19):** this is the most recent baseline
> in `docs/`, and CLAUDE.md cites it as the confirmed evidence for the
> `secure_128`/`secure_192`/`secure_256` bit-security figures it lists. Two
> caveats an implementer needs before relying on the numbers below:
>
> 1. **The `secure_128` row was computed at `n=4096`.** Current code
>    (`crates/nine65/src/params/secure_configs.rs::SecureConfig::secure_128`)
>    uses `n=8192`. A larger `n` at the same `log2(q)` only *improves*
>    Core-SVP/MATZOV security under the estimator's `3.36 * (n / log_q)`
>    formula, so the 129-bit/116-bit figures below are a **lower bound**, not
>    the current number — but they are not the current number either, and
>    should not be quoted as if freshly computed against `n=8192`.
> 2. **No run in this repository since 2026-01-27 has used the real external
>    `lattice-estimator` tool** (`malb/lattice-estimator` via SageMath). This
>    file and the 2026-02-05/2026-02-09 baselines were produced by the
>    in-tree `LatticeSecurityEstimator` Rust binary
>    (`cargo run -p nine65 --release --bin security_estimator_baseline`),
>    which is a deterministic integer heuristic, not an independent
>    certificate (its own module doc says so —
>    `crates/nine65/src/params/security_estimator.rs`). The 2026-01-27
>    baseline is the one run that did use the external tool, but it too used
>    now-superseded parameters (`secure_128` n=4096, `secure_192` n=8192).
>    `secure_configs.rs:4-7`'s stated policy — "every release that carries a
>    named security claim must archive an external lattice-estimator result
>    for the exact tuple `(N, Q, t, secret distribution, error
>    distribution)`" — is currently unmet for the parameters actually shipped
>    (`n=8192`/`16384`).
>
> **To regenerate once a `lattice-estimator`/SageMath toolchain is
> available** (none is installed in this sandbox, confirmed): run it against
> the exact tuples in `secure_configs.rs` for `secure_128`, `secure_128_deep`,
> `secure_192`, and `secure_256` at their current `n`, `q` chain, and `t`;
> archive the raw output the same way `LATTICE_ESTIMATOR_BASELINE_2026-01-27.md`
> did (tool commit hash, runtime image, raw `rop` figures per attack); and add
> a new dated file rather than editing this one, following the existing
> naming convention. Update CLAUDE.md's "Lattice Estimator confirmed" line to
> point at the new file once it exists.

Track E — Depth Ceiling Investigation: Formal Security Parameter Validation

## Command
```
cargo run -p nine65 --release --bin security_estimator_baseline
cargo run -p nine65 --release --bin security_estimator_baseline -- --cost-model matzov
```

## Environment
- OS: Linux coreI7 6.12.73+deb13-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.12.73-1 (2026-02-17) x86_64 GNU/Linux
- Rust: rustc 1.93.1 (01f6ddf75 2026-02-11)
- Cargo: cargo 1.93.1 (083ac5135 2025-12-15)
- Estimator: NINE65 built-in `LatticeSecurityEstimator` (integer-only, zero external dependencies)

## Results — Core-SVP Model (Conservative)

| SecureConfig | n | log2(q) | min attack log2(rop) | cost model |
| --- | --- | --- | --- | --- |
| secure_128 | 4096 | 89.08 | 129 | core-svp |
| secure_192 | 16384 | 145.08 | 318 | core-svp |
| secure_256 | 16384 | 174.18 | 264 | core-svp |

## Results — MATZOV Model (Aggressive/Realistic)

| SecureConfig | n | log2(q) | min attack log2(rop) | cost model |
| --- | --- | --- | --- | --- |
| secure_128 | 4096 | 89.08 | 116 | matzov |
| secure_192 | 16384 | 145.08 | 286 | matzov |
| secure_256 | 16384 | 174.18 | 237 | matzov |

## Dual-Model Summary

| Config | Core-SVP (bits) | MATZOV (bits) | Binding (min) | Claimed | Status |
| --- | --- | --- | --- | --- | --- |
| secure_128 | 129 | 116 | 116 | 128 | MEETS (Core-SVP) / margin at MATZOV |
| secure_192 | 318 | 286 | 286 | 192 | EXCEEDS both models |
| secure_256 | 264 | 237 | 237 | 256 | MEETS (Core-SVP) / margin at MATZOV |

## Analysis

### secure_128
- Core-SVP: 129-bit effective security (meets 128-bit claim)
- MATZOV: 116-bit effective security (below 128-bit target under aggressive model)
- HE Standard v1.1: n=4096 allows log2(q) up to 109 for 128-bit; our log2(q)=89 is well within bounds
- Assessment: Meets 128-bit security under conservative Core-SVP. The MATZOV 116-bit figure reflects the ~10% more aggressive attack model. HE Standard compliance confirmed.

### secure_192
- Core-SVP: 318-bit effective security (far exceeds 192-bit claim)
- MATZOV: 286-bit effective security (far exceeds 192-bit claim)
- This was upgraded from n=8192 to n=16384 (previous baseline showed only 159-bit at n=8192)
- Assessment: Strongly exceeds claimed security under both models. The parameter upgrade to n=16384 was the correct decision.

### secure_256
- Core-SVP: 264-bit effective security (meets 256-bit claim)
- MATZOV: 237-bit effective security (below 256-bit target under aggressive model)
- HE Standard v1.1: n=16384 allows log2(q) up to 237 for 256-bit; our log2(q)=174 is well within
- Assessment: Meets 256-bit under Core-SVP. MATZOV gives 237-bit, which is the binding constraint.

## Comparison to Previous Baseline (2026-02-09)

| Config | Old n | New n | Old log2(q) | New log2(q) | Old rop | New rop (Core-SVP) |
| --- | --- | --- | --- | --- | --- | --- |
| secure_128 | 4096 | 4096 | 89.08 | 89.08 | 129 | 129 |
| secure_192 | 8192 | **16384** | 145.08 | 145.08 | 159 | **318** |
| secure_256 | 16384 | 16384 | 203.38 | **174.18** | 226 | **264** |

Key changes:
- **secure_192**: n doubled from 8192 to 16384, doubling effective security (159 -> 318 bits)
- **secure_256**: log2(q) reduced from 203.38 to 174.18, improving n/log(q) ratio and security (226 -> 264 bits)
- **secure_128**: Unchanged — parameters were already correct

## Methodology

The NINE65 `LatticeSecurityEstimator` uses:
- HE Standard v1.1 methodology: `security = 3.36 * (n / log_q)` base formula
- Ternary secret penalty: 850/1000 (15% reduction for MITM advantage)
- Hybrid attack: optimal MITM/BKZ split search over g guessed coordinates
- Quantum: hybrid * 0.67 (Grover speedup)
- All arithmetic is integer-only with millibits precision (no floating-point)
- BKZ block size: `beta = classical_bits * 1000 / 292`
- Core-SVP cost: `2^(0.292 * beta)`, MATZOV cost: `2^(0.265 * beta)`
