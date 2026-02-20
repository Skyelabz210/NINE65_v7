# Release Checklist

## Preflight
- Confirm the `LICENSE` file and distribution intent.
- Confirm supported feature flags for the debut (default set + any optional flags).
- Ensure `cargo test` and `cargo bench` run without warnings.

## Functional Verification
- `cargo test --workspace`
- `cargo test -p nine65 --features v2,parallel,accelerated,wassan`

## Performance Gates (opt-in)
Set `NINE65_PERF_TESTS=1` to enable perf tests.
Perf gates are machine-dependent (CPU scaling, contention, test profile). Tune
thresholds for your target hardware and record the environment used.

Optional thresholds:
- `NINE65_WASSAN_1M_MAX_MS` (default: 120)
- `NINE65_WASSAN_POLY_MAX_MS` (default: 400)
- `NINE65_FFT_1024_MAX_MS` (default: 200)
- `NINE65_WASSAN_V2_MAX_MS` (default: 80)

Commands:
- `NINE65_PERF_TESTS=1 cargo test -p nine65 --lib entropy::wassan_noise::tests::test_benchmark_vs_shadow`
- `NINE65_PERF_TESTS=1 cargo test -p nine65 --lib v2_integration_tests::v2_integration_tests::test_fft_1024_benchmark`

## Benchmarks
- `cargo bench --workspace`
- Archive `target/criterion` reports for the release artifact.

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
