# GitHub Copilot instructions for NINE65

## What this repository is
NINE65 is a Rust workspace for exact integer/residue arithmetic, CRAM/CRT operations, and BFV/DualRNS homomorphic encryption, with proof artifacts and integration services. Read `CLAUDE.md` (project context), `docs/LINEAGE.md` (retired claims), and `docs/CLAIM_SURFACE_AND_LIMITS_2026-08-22.md` before changing crypto code. Preserve public API semantics and admission guards.

## Non-negotiable safety and correctness
- Every reported success must cite the exact git SHA and actual executed commands; distinguish compiled tests from reasoning, simulations or historical logs.
- Use integer arithmetic in active cryptographic paths. Keep f32/f64 out of residue, key, ciphertext, security and phase arithmetic. Exact rational approximations of mathematical constants must be labeled as such.
- Treat CLASS-F NTT-prime requirements separately from *generic* coprime CRT lifting. `KElimination::try_new` presently accepts pairwise-coprime composite alpha lanes; the `k_elimination_basis_regression` integration test expects primes, which is an outstanding specification conflict. Do not silence the test or introduce unrelated primality changes for green CI.
- Do not weaken cryptographic admission, constant-time boundaries, authentication, or parameter screening to satisfy a test.
- `public_phase1_soundness_gate()` intentionally blocks an unsound public BFV refresh transition. Issue #95 describes a missing secret-dependent quotient/carry term. Do not bypass the gate, fabricate a valid bootstrap, or mark a test as passed without a mathematically valid construction and plaintext oracle.
- Keep `WassanNoiseField` retirement distinct from active `exact_transcendentals::dyn_crt::WassanRing`. For the active ring, coefficient-wise addition and carry-aware positional integer addition are different operations. See issue #184 and `docs/WASSAN_A1_CONTRACT.md` when present.
- Do not treat files in `artifacts/` or archived reports as fresh benchmark results. Evidence must be reproducible against the reviewed commit.

## Efficient repository entry points
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
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
As of the October 2026 CI review, the full workspace suite has nine known failures in two targets: eight `nine65 --lib` tests (public-refresh/auto-bootstrap, depth/noise behavior) and one `k_elimination_basis_regression` test (prime-versus-composite alpha contract). Track root causes, do not suppress failures. Run the exactness-focused workflow to obtain independent scoped green/red evidence while the full suite remains an honest red.

## Change process
Work on a feature branch, supply smallest valid change with regression tests, preserve all existing required checks, then open a PR describing observed failures, new results, remaining risks, and before/after evidence. Use a human-approved merge for changes to cryptographic semantics. Never include secrets, keys, private tenant data or full production ciphertexts in issues or logs.