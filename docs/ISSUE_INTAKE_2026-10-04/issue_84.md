# Issue #84: [P1] Fix negative-branch DualRNS noise diagnostic ideal-point calculation

- state: open
- labels: (none)
- created: 2026-08-31T07:09:26Z  updated: 2026-09-04T09:58:24Z
- url: https://github.com/Skyelabz210/NINE65_v7/issues/84

---

## Finding

Both u128 and U256 implementations of `decrypt_dual_with_diagnostics` compute the negative-half ideal point from the wrapped decoded value:

```text
ideal = Q - decoded * Delta
```

For a negative plaintext magnitude `k`, BFV decoding returns `decoded = t - k`. The encoded negative ideal point is therefore based on the **magnitude** `k`, i.e. `Q - k*Delta`, not on `(t-k)*Delta`.

The current expression can report an error on the order of Q for a perfectly ordinary negative/upper-half plaintext and therefore corrupt the diagnostic margin. This affects any use of the decryption margin as a noise oracle or validation signal.

A direct integer check on the current `secure_128` tuple shows the wrong ideal-point distance jumps to roughly full-Q width for small negative magnitudes.

## Required fix

1. In both u128 and U256 paths derive the negative magnitude exactly:
   `k = if decoded == 0 { 0 } else { t - decoded }`.
2. Compute the negative ideal point from `k`, preserving the module's deliberate **floored Delta** convention.
3. Centralize the ideal-point/error calculation so debug/test and release variants cannot drift.
4. Preserve signed margin semantics and saturation behavior for wide U256 values.
5. Audit `try_decrypt_dual`, noise-profile tests, and any budget calibration that consumes this margin.
6. No floating point.

## Correctness tests

Add exhaustive/sampled tests over:
- `m = 0, 1, t/2-1, t/2, t-1`,
- positive and negative representatives around Q/2,
- exact Delta-grid points where margin should be maximal,
- offsets at `Delta/2 - 1`, `Delta/2`, `Delta/2 + 1`,
- both u128 and U256 decode routes.

Use an independent Python arbitrary-precision integer oracle for the ideal point and margin. Require exact agreement.

Existing ciphertext decryption outputs must remain unchanged; this issue repairs the diagnostic value, not plaintext semantics.

## Mandatory before/after performance evidence

Before/after benchmark `decrypt_dual_with_diagnostics` and `try_decrypt_dual` on `secure_128`, `secure_192`, and `secure_256` with identical seeded ciphertext corpora. Publish integer nanosecond/microsecond medians and exact margin vectors. Any measurable hot-path cost should be eliminated by sharing already-computed integers rather than weakening the diagnostic.

## Completion condition

Positive and negative representatives produce exact, oracle-matching margins in both integer-width paths, and all noise/budget validation tests consume the corrected metric.