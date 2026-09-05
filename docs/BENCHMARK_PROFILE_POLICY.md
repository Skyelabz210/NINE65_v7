# Benchmark Profile Policy

## Purpose

This policy separates publication-grade benchmark evidence from internal tuning data.
It exists to prevent accidental claim drift when test profiles or exploratory runs are faster
than secure production profiles.

## Profile Classes

`secure` (claim-grade):
- `secure_128`
- `secure_192`
- `secure_256`

`exploratory` (non-claim):
- `light*`
- `he_standard_128`
- `test_*`
- any run requiring `allow_insecure`

## Claim Rules

1. Public README and release claims MUST map to `secure` artifacts.
2. Every public claim MUST have an entry in `docs/CLAIM_REGISTRY.csv`.
3. Artifact paths in the registry MUST exist in-repo.
4. Exploratory profile outputs may be used for engineering direction only, never for public
   performance/security claims.

## Required Baseline Metadata

All claim-grade baselines must include:
- UTC timestamp
- OS and CPU model
- Rust and Cargo versions
- commit hash used for the run

## Raw Criterion Archival

`cargo bench` writes Criterion's full HTML/JSON report tree to
`target/criterion/`, and each new run overwrites the previous one's data in
place — nothing about a prior run's raw evidence survives by default. That is
how the `secure_128` public-mul figure documented in `README.md` ("Why these
replaced the previous figures") went stale and unverifiable: the number
published in `CLAUDE.md` had no archived raw run behind it to check.

Run `scripts/archive_criterion_run.sh [label]` after `cargo bench` (or before
*and* after a performance-sensitive change, so the two runs can be diffed) to
snapshot `target/criterion/` verbatim into a timestamped, commit-pinned
directory under `bench-archive/<UTC-timestamp>_<commit>[-dirty][_<label>]/`,
alongside a `MANIFEST.md` (timestamp, commit, dirty flag, toolchain, host) and
a `criterion_summary.json` (via `scripts/extract_criterion_summary.py`).

`bench-archive/` is gitignored — these are large, regenerable build artifacts,
not source, and per-viewer raw HTML/JSON dumps do not belong in git history.
This is a **local/CI evidence layer**, distinct from the claim-grade artifacts
Rule 3 above requires to exist in-repo:

- **`bench-archive/…`** — every raw run, kept locally (or as a CI job
  artifact), not committed. Use it to answer "what did commit X actually
  measure" without re-running history.
- **`docs/PERFORMANCE_BASELINE_YYYY-MM-DD*.{md,json}`** — the small, committed,
  citable summary produced by `scripts/generate_performance_baseline.sh` when
  a number is meant to back a public claim. This is what `CLAIM_REGISTRY.csv`
  entries should point at, per Rule 3.

Promote a `bench-archive/` run to a committed baseline (rather than citing the
archive path directly in README/CLAUDE.md) whenever its numbers are meant to
support a public claim. Wiring this archival step into automated CI
regression comparison is tracked separately under issue #19.

## CI Gate Modes

- `advisory`: pull requests (warn on failures, surface artifacts).
- `enforced`: scheduled runs and `main` branch pushes (fail on claim hygiene violations and
  benchmark regression flags).

## Source Of Truth

- Claim mapping: `docs/CLAIM_REGISTRY.csv`
- Performance artifact generation: `scripts/generate_performance_baseline.sh`
- Raw Criterion run archival: `scripts/archive_criterion_run.sh`
- Security artifact generation: `scripts/generate_security_baseline.sh`
- Drift scanner: `scripts/check_stale_claims.sh`
