# NINE65 v5 Comprehensive Test Report

Date: 2026-02-09
Target: NINE65 v5 (core + supporting crates)
Profile: release

## Scope
This report covers the public crates in the NINE65 v5 workspace:
- crates/nine65 (core FHE implementation)
- crates/mana (modular arithmetic accelerator)
- crates/clockwork-core (gearstack + integrity)
- crates/nexgen_rational (exact rationals)
- crates/unhal (hardware abstraction / pipeline)
- Optional bindings: crates/nine65-python, crates/nine65-wasm (not built in the default sweep)
- Lean formalization build for K-Elimination (lean4/KElimination)

## Test Commands Executed
1) `cargo test -p nine65 --lib --release`
2) `cargo test -p mana --release`
3) `cargo test -p clockwork-core --release`
4) `cargo test -p nexgen_rational --release`
5) `cargo test -p unhal --release`
6) `cargo test -p nine65 --lib --release --features exact_transcendentals_backend`
7) `cd lean4/KElimination && lake build`

Optional (not executed):
- `cargo test -p nine65-python --features python`
- `cargo test -p nine65-wasm --target wasm32-unknown-unknown`

## Results Summary
### Unit / Integration Tests (release)
- nine65 (core): **459 passed**, 0 failed, 0 ignored (includes integration tests + KATs)
- nine65 (exact backend): **461 passed**, 0 failed, 0 ignored (`--features exact_transcendentals_backend`)
- mana: **30 passed**, 0 failed, 0 ignored
- clockwork-core: **46 passed**, 0 failed, 0 ignored
- nexgen_rational: **95 passed**, 0 failed, 0 ignored
- unhal: **10 passed**, 0 failed, 0 ignored

### Doc Tests (release)
- nine65: 2 passed, 35 ignored
- mana: 0 passed, 1 ignored
- unhal: 0 passed, 3 ignored
- nexgen_rational: 0 passed, 1 ignored
- clockwork-core: no doc-tests defined

### Formal Verification
- lean4/KElimination: `lake build` **SUCCESS** (warnings-as-error enabled; no deferred proofs)

## Notes / Gaps
- Fuzzing (fuzz/), criterion benchmarks, and doc-tests (mostly ignored) are not executed in this run.
- Python and WASM bindings are optional and require extra toolchains/features; they were not built in this sweep.
- Cargo workspace `cargo test --workspace` will fail unless `--features python` and wasm target are available because `nine65-python` is marked `required-features = ["python"]`.

## Overall Status
PASS. All executed tests completed successfully in release mode with zero failures.
