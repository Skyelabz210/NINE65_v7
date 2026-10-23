# Paired-chart K-Elimination bridge

This connects the native 99/121 chart to the tropical covering-space lift in
[the 2026-10-22 K-Elimination analysis](../2026-10-22/TROPICAL_LIFT_K_ELIMINATION.md).
It is a candidate gate replacing the fixed-polynomial LUT; its encrypted
paired-residue producer is not implemented.

The complete variable and execution map is in
[the public-refresh architecture note](ULTRADISCRETE_PUBLIC_REFRESH_ARCHITECTURE.md).

## Exact chart-to-sheet map

The paired chart uses the unimodular change of coordinates

```text
U = -4*Z99 + 5*Z121
D =  9*Z99 - 11*Z121
Z99  = 11*U + 5*D
Z121 =  9*U + 4*D.
```

Its integer Jacobian has determinant `-1`, so it preserves the full lift
coordinate and all residue views. `D` removes the ideal sheet and phase
direction; `U` retains the sheet. The client chart readout is

```text
K = floor((99*Z99 + M/2)/M),     M = 32768 = 2^15.
```

The earlier tropical analysis gives the rank-one theta finite difference
`T_Q(S+1)-T_Q(S)=-2*K-b`, where `b` marks the cell wall. That difference
recovers the sheet modulo odd Safe-Basis coordinates; its parity records the
wall event. These are two coordinate descriptions of the same integer lift.
Inoue and Takenawa identify generic ultradiscrete periodic-Toda invariant
fibers with tropical Jacobians; this is the geometric context, not an FHE
correctness theorem ([primary paper](https://arxiv.org/abs/0902.0448)).

## K-Elimination identity and the 2/11 roles

Let `X=99*Z99+M/2`, `r=X mod M`, and `X_p=X mod p`, with `p=65537`. Since
`X=r+M*K`,

```text
K = (X_p-r) * M^(-1) mod p.
```

Here `p=2*M+1`, so `M^(-1)=-2 mod p` and the quotient is just
`K=2*(r-X_p) mod p`. The carry range `|K|<=48` gives a unique centered
representative. `M=2^15` uses the existing Safe-Basis root 2; the 99/121
chart retains the existing 11 role. This needs one Safe-Basis root with
dependent phase-locked trays, not another root and not a degree-33 polynomial
over the whole chart domain.

Once the quotient has been recovered in the same plaintext-`p` encoding as
`Z99`, the centered chart residual is also linear:

```text
e99 = 99*Z99 - M*K = r - M/2.
```

This is the exact zero response along the integer sheet direction: changing
`Z99` by one ideal sheet changes `99*Z99` by `M`, which is canceled by
`M*K`. The source-correlated chart bound is `|e99|<=5313`, strictly inside
the half-cell `M/2`. That makes `e99` a bounded correction candidate. It does
not by itself restore the original message or reset ciphertext error; the
existing return ledger still needs a producer-issued error certificate and
must pass the following dense multiplication.

The exact oracle checks every integer `Z99` in `[-16005,16005]` and several
full `p*M` representative windings. It confirms the quotient, the `2*M+1`
shortcut, and `|K|<=48`. The wider `Z99` interval alone does not bound the
centered residual tightly; the source norm and `Q_source/64` phase cap give

```text
|99*Z99 - M*K| < 99*(96+1)/2 + M/64 = 5313.5,
```

so its integer magnitude is at most `5313`, strictly below `M/2`.

Run the integer oracle with:

```text
python3 scripts/test_paired_chart_k_elimination.py
python3 scripts/paired_chart_k_elimination.py
```

## Bounded encrypted tray check

The Safe-Basis unit probe exercises the arithmetic after a chart state is
available. It encrypts one-hot selectors for five public support rows with
`K = -48, -1, 0, 1, 48`, attaches `2^15` and `65537` views to the same
`Root211`, and checks the common-encoding calculation of `K` and `e99`
coefficientwise. It also follows the noise ledger through the first square,
checking the square if admitted and requiring a typed refusal before
multiplication otherwise. The focused test passed all five cases; the
root/history-rebinding regression and all seven Python oracle tests passed.

This test uses key-holder-precharged one-hot chart-row selectors. It verifies
that one root can supply the required dependent trays and that the K-Elimination
identities work in the common plaintext encoding. It does not connect the
actual dense public `Z99/Z121` producer to that root, so it does not close the
encrypted low-tray producer gate below.

## Encrypted gap to bridge

The formula needs `r=X mod M` and `X_p=X mod p` encrypted in the same
plaintext-`p` encoding and derived from the same authenticated chart state.
Then `2*(r-X_p)` and `99*Z99-M*K` are linear ciphertext operations. The
existing `Root211::attach` research capability already permits an arbitrary
`M=32768` view and encodes every view in the root's common plaintext ring;
its composition tests use a bounded selector state. The unresolved step is
producing that low view from the actual dense public chart while retaining the
same root/history capability and a useful producer error bound. An
independent ciphertext modulo `M` cannot be relabeled as a `p` ciphertext.
Re-decoding one `p*M` ciphertext under `p` also leaves the source residual as
ciphertext error.

The next implementation test should attach the `2^15` tray to the actual
99/121 public chart state through the existing single Safe-Basis capability,
then compute `K` and `e99` in the common `p` encoding. It must check every
coefficient, signed carry boundaries, nonzero source noise, the correction
consumer, the first post-return multiplication, and a second refresh. A
failed phase-lock, capacity, or noise certificate must refuse before output.
Until this passes, issue #95 stays open and public refresh remains
fail-closed.
