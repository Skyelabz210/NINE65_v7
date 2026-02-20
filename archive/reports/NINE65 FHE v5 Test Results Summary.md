# NINE65 FHE v5 Test Results Summary

Date: 2026-02-09
Profile: release

## Overall Status
PASS - Core + support crate tests completed with zero failures. Optional bindings (python/wasm) not executed in this sweep.

## Summary (release)
- Unit / integration tests:
  - mana: 30 passed
  - nine65: 459 passed (includes integration + KATs)
  - nine65 (exact backend): 461 passed with `--features exact_transcendentals_backend`
  - clockwork-core: 46 passed
  - nexgen_rational: 95 passed
  - unhal: 10 passed
- Doc-tests: 2 passed, 40 ignored (nine65 35, mana 1, unhal 3, nexgen_rational 1)
- Formal verification: lean4/KElimination lake build SUCCESS

## Notes
- Workspace-wide `cargo test --workspace` requires excluding bindings or enabling their toolchains; use `cargo test --release --exclude nine65-python --exclude nine65-wasm` for the default sweep.
- Python (`nine65-python`) and WASM (`nine65-wasm`) bindings are optional; build with `--features python` and wasm target respectively.
- Test count increased from 446 → 459 after Codex gap-analysis remediation (TDD cycles 5-9).

## Full Report
See docs/COMPREHENSIVE_TEST_REPORT_V5.md
