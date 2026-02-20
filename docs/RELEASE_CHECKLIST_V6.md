# Release Checklist — NINE65 v6 "a Clockwork Prime"

This checklist extends the v5 release checklist with v6-specific gates.
All items must pass before tagging a release.

## Phase 1: Build Verification

- [ ] `cargo build --release --workspace --exclude nine65-python --exclude nine65-wasm` — 0 errors
- [ ] `cargo build -p nine65 --features clockwork` — 0 errors
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` — 0 warnings
- [ ] `cargo fmt --all -- --check` — all formatted

## Phase 2: Test Suite

- [ ] `cargo test --workspace` — all tests pass (target: 1,056+)
- [ ] `cargo test -p nine65 --lib --features clockwork` — clockwork tests pass (target: 589+)
- [ ] `cargo test -p nine65 --test error_variant_coverage` — all 29 error variants covered
- [ ] `cargo test -p nine65 --features v2,parallel,accelerated,wassan` — optional features pass

## Phase 3: Quality Gates

- [ ] `bash scripts/check_no_panics.sh` — 0 violations (or documented exemptions)
- [ ] `bash scripts/check_no_floats_runtime.sh` — 0 float violations in production code
- [ ] `bash scripts/check_claim_registry.sh` — claim registry valid
- [ ] `bash scripts/check_stale_claims.sh` — no stale claims

## Phase 4: Security Verification

- [ ] `cargo test -p nine65 security::tests -- --nocapture` — all security tests pass
- [ ] `cargo audit` — no known vulnerabilities
- [ ] `cargo deny check` — licenses and advisories clean
- [ ] Entropy health check passes (`entropy_health_check()` returns true)
- [ ] GRO timing gate tests pass (clockwork feature)
- [ ] Circular security validation tests pass

## Phase 5: Performance Baseline

- [ ] `scripts/generate_performance_baseline.sh` — generates dated baseline
- [ ] `scripts/generate_security_baseline.sh` — generates lattice estimator baseline
- [ ] Archive `target/criterion` reports
- [ ] Verify no major regressions vs previous baseline
- [ ] Timing baseline captured in `docs/baselines/`

## Phase 6: Formalization

- [ ] `docs/FORMALIZATION_INDEX.md` — all proof files mapped
- [ ] Coq proofs compile: `cd proofs/coq && coqc *.v`
- [ ] Lean4 proofs build: `cd lean4/KElimination && lake build`
- [ ] Error taxonomy complete (all `Nine65Error` variants mapped to theorems)

## Phase 7: Documentation

- [ ] `README.md` updated with current test counts and feature list
- [ ] `docs/NIST_COMPLIANCE_MATRIX.md` reviewed for accuracy
- [ ] `docs/SIDE_CHANNEL_THREAT_MODEL.md` current
- [ ] `docs/SECURITY_PROOFS.md` reviewed
- [ ] `docs/FHE_BENCHMARK_COMPARISON.md` sources current
- [ ] `CLAUDE.md` updated with any new conventions

## Phase 8: v6 Clockwork-Specific

- [ ] GRO timing gate integrated on keygen (`GatedKeyGen`)
- [ ] GRO timing gate integrated on decrypt (`GatedDecryptor`)
- [ ] `SecretKeyPath` trait implemented for `SecretPoly`
- [ ] Bound tracking operational (`bounded_rns.rs`, clockwork feature)
- [ ] Key lifecycle management operational (`key_manager.rs`, clockwork feature)
- [ ] Limb integrity checks operational (`integrity.rs`, clockwork feature)
- [ ] Garner reconstruction cross-validates K-Elimination (`clockwork-core`)

## Phase 9: CI Pipeline

- [ ] All CI jobs green on main branch:
  - [ ] Build (debug + release)
  - [ ] Test (lib + all)
  - [ ] Clippy
  - [ ] Rustfmt
  - [ ] Security Audit
  - [ ] Cargo Deny
  - [ ] No-Panics Gate
  - [ ] No-Floats Gate
  - [ ] Clockwork Feature Tests
  - [ ] Formalization Validation
  - [ ] Error Variant Coverage

## Phase 10: Pre-Release

- [ ] `LICENSE` file present and correct
- [ ] Version number updated in all `Cargo.toml` files
- [ ] CHANGELOG written for v6
- [ ] Git tag created: `v6.0.0`
- [ ] Release notes drafted

## Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Developer | | | |
| Security Reviewer | | | |
| Release Manager | | | |

## Notes

- Test-only configs (`allow_insecure`) are compile-blocked in release builds
- `compiler.rs` is the sole float exemption (compile-time analysis, not runtime)
- GRO timing variance target: < 5% (software simulation; hardware achieves lower)
- Minimum recommended deployment config: `secure_192`
