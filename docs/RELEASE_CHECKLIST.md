# Release Checklist

## Preflight
- Confirm the `LICENSE` file and distribution intent.
- Confirm supported feature flags for the debut (default set + any optional flags).
- Ensure `cargo test` and `cargo bench` run without warnings.

## Functional Verification
- `cargo test --workspace`
- `cargo test -p nine65 --features shadow-entropy,parallel,accelerated`

(The `v2` and `wassan` Cargo feature aliases were removed 2026-03-01 as
no-ops; `wassan_noise` itself — `WassanNoiseField` — was deleted entirely in
issue #68, having had zero production callers. `shadow-entropy` is what
gates the surviving `v2_integration_tests` module, which now covers FFT NTT
only.)

## Performance Gates (opt-in)
Set `NINE65_PERF_TESTS=1` to enable perf tests.
Perf gates are machine-dependent (CPU scaling, contention, test profile). Tune
thresholds for your target hardware and record the environment used.

Optional thresholds:
- `NINE65_FFT_1024_MAX_MS` (default: 200)

Commands:
- `NINE65_PERF_TESTS=1 cargo test -p nine65 --lib v2_integration_tests::v2_integration_tests::test_fft_1024_benchmark`

## Benchmarks
- `cargo bench --workspace`
- Archive the raw `target/criterion` tree per run before it gets overwritten
  by the next `cargo bench` invocation: `scripts/archive_criterion_run.sh`
  (writes a timestamped, commit-pinned copy to `bench-archive/`, gitignored —
  see `docs/BENCHMARK_PROFILE_POLICY.md` "Raw Criterion Archival"). Do this
  for the release artifact and for any performance-sensitive change under
  review.

## Baseline Artifacts (Reproducible)
- `scripts/generate_security_baseline.sh` -> `docs/LATTICE_ESTIMATOR_BASELINE_YYYY-MM-DD.md`
- `scripts/generate_performance_baseline.sh` -> `docs/PERFORMANCE_BASELINE_YYYY-MM-DD.md`
  and machine-readable artifacts:
  - `docs/PERFORMANCE_BASELINE_YYYY-MM-DD.json`
  - `docs/PERFORMANCE_BASELINE_YYYY-MM-DD_criterion.json`
- Archive generated baseline docs with the release artifact.

## Claim Drift Gates
- `scripts/check_claim_registry.sh`
- `scripts/check_stale_claims.sh`
- CI must fail when claim drift is detected (README vs artifact mismatch).

## Docs
- Update `README.md` feature list and examples if flags or paths change.
- Review `docs/SECURITY_PROOFS.md` and `docs/FHE_BENCHMARK_COMPARISON.md` for accuracy.
