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
integer lift, but ciphertext arithmetic does not need a centering operation:
the residue `K mod p` already represents a negative carry as `p-|K|` in the
plaintext ring. `M=2^15` uses the existing Safe-Basis root 2; the 99/121
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

## Adjacent-tray K-Elimination

The same source-correlated residual gives a direct carry quotient through the
arbitrary tray `A=M+1=32769`. Since

```text
X = M*K + M/2 + e99
  = A*K + (M/2 + e99 - K),
```

and `|e99|<=5313`, `|K|<=48`, the final remainder is strictly inside
`[11023,21745]`, hence canonical in `[0,A)`. Therefore
`floor(X/A)=K` on the admitted source window. Also `2*A=p+1`, so
`A^(-1)=2 mod p` and

```text
K = 2 * (X mod p - (X mod A) mod p) mod p.
e99 = (X mod A) + K - M/2 mod p.
```

This uses a dependent `A` tray in the common `p` encoding and needs no
signed-centering or carry-sign operation. The exact oracle checks all 10,411
source-correlated chart points, including `K=-48` and `K=48`; observed
canonical tray residues range from `11038` to `21730`. The proof depends on
the source-correlated residual bound, not the wider `Z99` interval alone.

A focused Rust fixture now precharges encrypted one-hot chart selectors and
uses one `Root211` to attach the `M`, `p`, 98, and `M+1` views. It evaluates
`K mod p` and `e99 mod p` from the `M+1` pair and checks five carries
`[-48,-1,0,1,48]`; the existing `M` pair and composite-98 residue are checked
from the same selected state. This verifies the encrypted consumer arithmetic
and its admitted noise bound. Its chart rows are a bounded research fixture,
not the production dense chart producer, so it does not yet establish a
same-history low tray or an end-to-end refresh gate.

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
root/history-rebinding regression and all nine Python oracle tests passed.

This test uses key-holder-precharged one-hot chart-row selectors. It verifies
that one root can supply the required dependent trays and that the K-Elimination
identities work in the common plaintext encoding. It does not connect the
actual dense public `Z99/Z121` producer to that root, so it does not close the
encrypted low-tray producer gate below.

## Composite-98 carry candidate

There is a second exact residue route that avoids the wide `M=32768` tray.
Set `Y=198*Z99`. Since `e99=99*Z99-M*K` and `p=2*M+1`,

```text
Y = p*K + (2*e99-K).
```

The certified source envelope gives `|2*e99-K| <= 2*5313+48 = 10674 < p/2`.
Thus the centered p residue `w=center(Y mod p)` is exactly `2*e99-K`, and
`K` is the quotient in `Y=w+p*K`. Modulo the composite tray `A=98=2*7^2`,
`p=73` and `73^(-1)=47`, so

```text
K = center_98(47 * ((Y mod 98) - (w mod 98)) mod 98).
```

The corridor `|K|<=48<49` makes the centered residue unique. The exact oracle
checks this identity on all 10,411 source-correlated `Z99` values; the largest
observed `|w|` is 10,659. Tray 98 uses existing Safe-Basis factors 2 and 7
and does not add a root. This is an integer identity, not yet an encrypted gate:
the dense producer still has to bind `Y mod 98` and the centered p residue
`w mod 98` to one authenticated chart history. Forming `w` requires centering
the p residue. Because tray98 gives `K mod 98`, this route also needs a signed
lift into the p plaintext ring before the return consumer can use it.

The encrypted selector probe now also attaches tray98 to the same root as
`2^15` and p, derives `Y mod 98` and `w mod 98` from the same bounded selector
state, and checks `47*(Y_98-w_98)` is congruent to each selected carry for
`K=-48,-1,0,1,48`. Its client-side test centers that residue and interprets
the signed carry; the evaluator emits only the residue modulo 98, not the
corresponding `K mod p`. The selector fixture is not the dense chart producer.

### Split the composite tray into 49 and 2

Factoring `98=49*2` makes the signed lift step explicit. Write `Y=p*K+w`,
where `w=center(Y mod p)`. Phase-locked residues give

```text
k49 = ((Y mod 49 - w mod 49) * 47) mod 49,  with 0 <= k49 < 49
k2  = (Y mod 2 - w mod 2) mod 2
c   = (k49 - k2) mod 2
K   = k49 - 49*c.
```

Here `p^(-1)=47 mod 49`, and `p^(-1)=1 mod 2`. For `|K|<=48`, `c` is one
exactly when `K` is negative. This reconstructs the signed carry from the
49-residue and the existing 2-root view. The exact oracle verifies the formula
for all 10,411 source-correlated chart points and all five carry boundaries.

This factors the residue arithmetic; it does not make signed conversion a
linear ciphertext operation. The composite route first needs an encrypted
centering decision for `Y mod p` to form `w`. It then needs canonical `k49` in
`[0,48]`, its parity, and the correction bit to lift K into the common p
encoding. The direct `2^15` route avoids both of these centering operations:
its K-Elimination output is already `K mod p`. Neither route has a dense-source
implementation. The current Rust selector probe checks the 98 residue only
and centers `w` and K in its client oracle; it does not test either encrypted
decision.

## Encrypted gap to bridge

The direct formula needs `r=X mod M` and `X_p=X mod p` encrypted in the same
plaintext-`p` encoding and derived from the same authenticated chart state.
Then `2*(r-X_p)` produces K directly in `Z_p`; negative K already has its
ordinary residue encoding, and `99*Z99-M*K` is linear ciphertext arithmetic.
The adjacent `M+1` identity above is an equivalent tray choice whose inverse
modulo `p` is `2`; its source-correlated remainder also gives `e99` linearly.
The existing `Root211::attach` research capability already permits an arbitrary
`M=32768` view and encodes every view in the root's common plaintext ring;
its composition tests use a bounded selector state. The unresolved step is
producing either low view from the actual dense public chart while retaining the
same root/history capability and a useful producer error bound. An independent
ciphertext modulo `M` or `M+1` cannot be relabeled as a `p` ciphertext.
Re-decoding one `p*M` ciphertext under `p` also leaves the source residual as
ciphertext error. The composite route instead needs same-history 49/2 and p
views, encrypted centering of the p residue, and canonicalization of the
49-residue with its signed correction bit. The exact 49/2 identity supplies
none of these encrypted operations.

The next implementation test should attach the `M+1` tray to the actual
99/121 public chart state through the existing single Safe-Basis capability,
then compute `K` and `e99` in the common `p` encoding. It must check every
coefficient, signed carry boundaries, nonzero source noise, the correction
consumer, the first post-return multiplication, and a second refresh. A
failed phase-lock, capacity, or noise certificate must refuse before output.
Until this passes, issue #95 stays open and public refresh remains
fail-closed.
