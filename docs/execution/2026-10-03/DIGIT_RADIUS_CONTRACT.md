# R01 bounded-digit radius: `BLOCKED_DESIGN`

This is a partial derivation, not an R01 acceptance. The executable scalar
oracle is valid for its stated input: a ciphertext under one fixed secret and
an already-certified scaled phase-error bound. It does not cover the complete
transform / sparse-key encapsulation / digit-extraction history.

## Scalar expanded-phase bound

Let `Q` be the exact odd ciphertext modulus, `t` the odd plaintext modulus,
`N` the ring degree, and `s` the secret used to decrypt the expanded-phase
ciphertext. Let

```text
V = || t * (c0 + c1*s) - Q*m ||_infinity
```

for the centered plaintext lift `m`; `V` is an integer bound already including
the input's prior phase error and encoding correction. Assume `2V < Q`.
Scaling each component to `t^2` uses nearest-integer rounding, with error at
most `(Q-1)/(2Q)` in the normalized component. For
`||s||_1 <= H`, the residual after subtracting `t*m` is bounded by

```text
|rho| <= floor(t*V/Q + (H+1)*(Q-1)/(2Q)).
```

The corresponding *partial* admission predicate is `2B < t` and the integer
right-hand side is at most `B`. This is the contract implemented by
`scripts/digit_radius_oracle.py`; the exhaustive small-ring tests validate
this scalar inequality and the rounded extraction on their toy domains.

For an arbitrary ternary work secret, the only deterministic support supplied
by its distribution is `H=N`. At `N=8192`, `t=65537`, and the Q fixture in
the tests, the rounding term alone is
`(N+1)*(Q-1)/(2Q)`, whose floor is 4096. Thus this conservative scalar
certificate cannot admit `B=17` or `B=32`, even when `V=0`. It is a refusal of
this certificate, not an impossibility proof for sharper correlated bounds.
For the three existing `V` fixtures, the oracle returns radii 4096, 4096, and
22310. The third fixture's `t*V/Q` term is about 18,214.40 and dominates its
rounding allowance.

## Why the reference's weight-32 key does not replace `H=8192`

The pinned Fheanor reference first transforms to coefficients, modulus-switches
to a lower-modulus sparse-key ring, and key-switches to the temporary sparse
secret. Its noisy-expansion step then obtains plaintext components `(c0,c1)`
and constructs `c0 + c1 * Enc_work(s_sparse)` under the original work key. It
subsequently transforms that ciphertext to slots and performs digit
extraction. Therefore the secret multiplying component-wise scale-rounding at
the expanded work-key phase is still `s_work`; the temporary key's Hamming
weight 32 bounds a different intermediate-noise contribution. Substituting
32 for `N` in the scalar oracle would silently change the key domain and is
not a valid bound for this sequence.

The code path is visible in the pinned upstream
[`bootstrap.rs`](https://github.com/FeanorTheElf/fheanor/blob/2ba00539204cc03816dd258b57fad94904f54d41/src/bfv/bootstrap.rs):
`bootstrap_thin` calls slots-to-coefficients, noisy expansion,
coefficients-to-slots, and digit extraction in sequence; `perform_noisy_expansion`
mod-switches and switches to the sparse key, then multiplies by the encrypted
sparse key under the original ciphertext ring. The same source describes the
temporary switch and sparse-key ciphertext fields.

## Missing terms and next proof obligation

No full admission predicate or B is selected. In particular, this derivation
does not yet bound, for one exact key/parameter family:

* previous operation history and every forward/inverse transform's
  coefficient error;
* modulus-switch rounding and the sparse key-switch evaluation-key error;
* sparse-secret encapsulation error multiplied through `c1` under the work
  secret, including the work-secret norm and key-switch decomposition;
* the `Q mod t` floor-encoding correction at every relevant level; or
* a deterministic sampler support or a composed, quantified failure
  probability for the randomized errors.

The reference's `--digit-bound 17/32` is a circuit input parameter, not a
derived radius. Its successful functional runs therefore do not close any of
these terms. The existing native-history fixtures are not tied here to an
authenticated operation lineage or a source-bound key/parameter certificate.

There is also an upstream task-order gap: R01 depends on R00, but
`docs/execution/2026-10-03/TIGHT_BOUND_RESULT.md` is absent and the execution
plan currently reports only F00 as dependency-ready. The R01 test command
passes three tests, but those tests cover only the partial scalar formula;
they do not supply the missing R00 result, complete-route recurrence, selected
B, specialist review, or R01 acceptance vectors bound to a live history.

**Decision:** keep the bounded-digit input gate closed. Continue only after R00
produces a reviewed exact operation/error schedule, then derive the sparse
route without transferring the sparse Hamming-weight bound across the
re-encryption to the work key. If that complete bound remains too wide, retain
`BLOCKED_DESIGN`; do not tune B to the reference samples.
