# Issue #89: [P1] Enforce or ratchet the production panic/unwrap/expect quality gate

- state: open
- labels: (none)
- created: 2026-08-31T07:10:51Z  updated: 2026-09-04T09:58:35Z
- url: https://github.com/Skyelabz210/NINE65_v7/issues/89

---

## Finding

`scripts/check_no_panics.sh` explicitly defaults to **advisory** mode. It reports production `panic!`, `.unwrap()`, and `.expect()` sites and exits success. `scripts/regression_scan.sh enforced` likewise does not enable the stricter panic policy.

The script itself records that the remaining findings are a real backlog and that the owner decision between hard cutover and ratchet is still open. With `panic = "abort"` in release, an attacker- or caller-reachable accidental panic is process termination.

This issue is the repository-wide companion to the concrete fallible-constructor defect in #85.

## Required work

1. Produce the exact current production-site inventory with file, line, call path, and reachability classification.
2. Classify each occurrence:
   - caller-controlled/recoverable -> typed `Result`/error,
   - internal proven invariant -> documented invariant with a narrowly scoped allowlist if necessary,
   - intentionally infallible public wrapper -> explicit panic contract wrapping a fallible primitive,
   - test/demo/benchmark -> outside production gate.
3. Immediately enable a **ratchet** that fails CI on any new production panic-pattern site relative to an exact committed baseline.
4. Burn the baseline to zero or to a minimal reviewed allowlist, then switch to hard enforcement.
5. Make the scanner parser robust enough that test modules, strings, comments, macros, and generated code cannot create false pass/fail behavior.
6. Add release-mode adversarial tests for every previously caller-reachable panic fixed.
7. Keep CSPRNG fatal behavior explicit and reviewed rather than hidden among general `.expect()` sites.

## Mandatory before/after correctness evidence

Before: archive scanner output and a machine-readable baseline file.

After: `check_no_panics.sh enforced` (or replacement) must fail on a deliberately injected production panic pattern and pass the real tree; release-mode invalid-input corpus must return typed errors without process termination.

## Mandatory before/after speed evidence

For every panic-to-Result conversion on a hot path, benchmark the affected operation before/after. Also run the canonical encrypt/add/public-mul/symmetric-mul/decrypt suite. Record integer timing units. Error-path hardening must not add repeated validation inside proven inner loops; validate once at the boundary.

## Completion condition

A production panic-pattern regression cannot merge silently, and all caller-controlled failure modes reachable through fallible APIs are typed errors.