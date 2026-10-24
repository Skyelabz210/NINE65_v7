# GitHub Copilot instructions for NINE65

## What this repository is
NINE65 is a Rust workspace for exact integer/residue arithmetic, CRAM/CRT operations, and BFV/DualRNS homomorphic encryption, with proof artifacts and integration services. Read `CLAUDE.md` (project context), `docs/LINEAGE.md` (retired claims), and `docs/CLAIM_SURFACE_AND_LIMITS_2026-08-22.md` before changing crypto code. Preserve public API semantics and admission guards.

## Non-negotiable safety and correctness
- Every reported success must cite the exact git SHA and actual executed commands; distinguish compiled tests from reasoning, simulations or historical logs.
- Use integer arithmetic in active cryptographic paths. Keep f32/f64 out of residue, key, ciphertext, security and phase arithmetic. Exact rational approximations of mathematical constants must be labeled as such.
- Treat CLASS-F NTT-prime requirements separately from *generic* coprime CRT lifting. `KElimination::try_new` accepts pairwise-coprime composite alpha lanes for a generic exact CRT lift; the `k_elimination_basis_regression` test explicitly verifies this and rejects non-coprime cases. Apply prime-only requirements at NTT-specific entry points, never conflate the two algebraic contracts.
- Do not weaken cryptographic admission, constant-time boundaries, authentication, or parameter screening to satisfy a test.
- `public_phase1_soundness_gate()` intentionally blocks an unsound public BFV refresh transition. Issue #95 describes a missing secret-dependent quotient/carry term. Do not bypass the gate, fabricate a valid bootstrap, or mark a test as passed without a mathematically valid construction and plaintext oracle.
- Keep `WassanNoiseField` retirement distinct from active `exact_transcendentals::dyn_crt::WassanRing`. For the active ring, coefficient-wise addition and carry-aware positional integer addition are different operations. See issue #184 and `docs/WASSAN_A1_CONTRACT.md` when present.
- Do not treat files in `artifacts/` or archived reports as fresh benchmark results. Evidence must be reproducible against the reviewed commit.

## Efficient repository entry points
Lint and formatting gates are active in CI and block on failures. Run them
when changing lint configuration or when explicitly requested. See
`docs/CI_LINT_POLICY.md`.

- `cargo test -p exact_transcendentals --lib`
- `cargo test -p exact_transcendentals --no-default-features --lib`
- `cargo test -p nine65 --test k_elimination_basis_regression`
- `bash scripts/run_tests_medium.sh` (full workspace, uses `--no-fail-fast`)
- `python3 scripts/check_required_ci_actor_bypass.py`
- `bash scripts/check_claim_registry.sh`
- `bash scripts/check_no_panics.sh ratchet`
- `bash scripts/check_no_floats_runtime.sh`

`.github/workflows/ci.yml` defines primary required CI; application-specific checks also run separately. A passing fast gate does not mean the full suite passed.

## Current known blockers
The October 2026 baseline had eight `nine65 --lib` failures (public refresh / auto-bootstrap, depth/noise behavior) and a stale K-Elimination alpha-primality assertion. The latter has been updated to test the mathematically implemented generic CRT coprimality contract without reducing coverage. The eight cryptographic failures remain genuine blockers. Run the exactness-focused workflow for separate scoped evidence; do not claim full green CI until workspace tests pass.

## Change process
Work on a feature branch, supply smallest valid change with regression tests, preserve all existing required checks, then open a PR describing observed failures, new results, remaining risks, and before/after evidence. Use a human-approved merge for changes to cryptographic semantics. Never include secrets, keys, private tenant data or full production ciphertexts in issues or logs.
