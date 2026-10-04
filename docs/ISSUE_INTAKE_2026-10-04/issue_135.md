# Issue #135: Deprecated BFVEvaluator::mul() silently returns wrong plaintexts (untested for years; found via Python bindings work)

- state: open
- labels: bug
- created: 2026-09-04T11:08:15Z  updated: 2026-09-04T11:08:15Z
- url: https://github.com/Skyelabz210/NINE65_v7/issues/135

---

## Scope, stated up front

This is about `BFVEvaluator::mul()` (`crates/nine65/src/ops/homomorphic.rs:265`, already `#[deprecated]`), a **separate, legacy single-modulus code path**, not `RNSFHEContext`/`DualRNSContext` (`ops/rns_fhe.rs`) — the machinery that essentially all of this repo's current ct×ct correctness work (Track 1/2, WIRE-Q, WR-4/5A/5B/7/8, issue #81's depth-2 verification, etc.) actually concerns. Nothing here contradicts or reopens any of that verified work.

## Finding

Found by a subagent working issues #17/#63 (Python bindings, PR #133) while verifying "no silent precision loss" across the FFI boundary. `nine65-python`'s bindings wrap `BFVEvaluator::mul()`, and testing it turned up that it's simply wrong: **every case tried returns an incorrect plaintext, including the simplest one, `1 * 1`**, reproduced across `secure_128` (n=8192) and, at n=1024, `light_mul_insecure`/`light_insecure`/`test_fast_insecure`. Reproduced directly in plain Rust with no PyO3 involved, so this is not an FFI-boundary defect — it's in `nine65` itself.

## Why this went unnoticed

None of `nine65`'s own currently-passing tests actually assert a decrypted value from this exact function:
- `test_homomorphic_mul_with_relin` and `test_ct_mul_multiple_values` — names read as if they cover it, but both call `mul_no_relin()` + `decrypt_degree2()` instead, bypassing relinearize/rescale entirely.
- `test_homomorphic_mul_diagnostic` calls `mul()` but only prints a `[FAIL]`/`[OK]` line — it asserts nothing.

So this has apparently been silently wrong for as long as those test names have existed, invisible because the tests that look like coverage aren't.

## A second, related finding in the same investigation

Plaintext values near the modulus don't round-trip through plain encrypt/decrypt either (no multiplication involved) — `BFVEncoder::decode()`'s `round(t*c/q)` formula has a real, noise-free bias for `(q=998244353, t=65537)`, the pair every exposed `SecureConfig` shares through this single-modulus path. Safe up to ~9000 (measured over 300 trials across 10 keysets); values near `t` fail consistently with a small, one-directional drift. Same file/subsystem, same investigation, may or may not be the same root cause as the `mul()` defect — not established here.

## Evidence

Both are captured as `xfail(strict=True)` tests in `crates/nine65-python/tests/test_known_limitations.py` (PR #133) — CI reflects reality, and if either ever unexpectedly starts passing that's a signal the underlying bug is fixed. Full writeup in that PR's description and in `FHEContext.mul()`'s doc comment in `crates/nine65-python/src/lib.rs`.

## Required work

1. Decide `BFVEvaluator::mul()`'s disposition given it's already deprecated and apparently unused/untested for a real fix window: either root-cause and fix it, or formally retire it (remove it, or make it typed-fail-closed like `RNSFHEContext::mul()` was made to do for its own uncertified regime in #107) — do not leave a public, callable, silently-wrong multiply on the books.
2. Fix or retire the two test names that read as covering this (`test_homomorphic_mul_with_relin`, `test_ct_mul_multiple_values`) so they either genuinely test `mul()` or are renamed to stop implying they do.
3. Investigate the `BFVEncoder::decode()` near-modulus rounding bias independently — it's not multiplication-specific and may affect other single-modulus callers.

## Not done here

No fix attempted — this issue was filed to route the finding, not resolve it; scoped intentionally narrow (bindings work shouldn't second-guess core-crate arithmetic without the crate's own test suite backing it up).