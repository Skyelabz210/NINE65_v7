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

## CI Gate Modes

- `advisory`: pull requests (warn on failures, surface artifacts).
- `enforced`: scheduled runs and `main` branch pushes (fail on claim hygiene violations and
  benchmark regression flags).

## Source Of Truth

- Claim mapping: `docs/CLAIM_REGISTRY.csv`
- Performance artifact generation: `scripts/generate_performance_baseline.sh`
- Security artifact generation: `scripts/generate_security_baseline.sh`
- Drift scanner: `scripts/check_stale_claims.sh`
