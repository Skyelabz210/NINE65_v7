# Paired-chart K-Elimination bridge

This connects the native 99/121 chart to the tropical covering-space lift in
[the 2026-10-22 K-Elimination analysis](../2026-10-22/TROPICAL_LIFT_K_ELIMINATION.md).
It now has a direct composite-scale BFV readout experiment: the dense native
99 chart decodes to the hidden Phase 1 carry under the p view without making a
low tray. The corrected return and production capability are still open.

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
`M*K`. The live source-correlated chart bound is `|e99|<=6849`, strictly inside
the half-cell `M/2`. That makes `e99` a bounded correction candidate. It does
not by itself restore the original message or reset ciphertext error; the
existing return ledger still needs a producer-issued error certificate and
must pass the following dense multiplication.

The exact oracle checks every integer `Z99` in `[-16005,16005]` and several
full `p*M` representative windings. It confirms the quotient, the `2*M+1`
shortcut, and `|K|<=48`. The wider `Z99` interval alone does not bound the
centered residual tightly; the source norm and live `Q_source/16` phase cap give

```text
|99*Z99 - M*K| < 99*(96+1)/2 + M/16 = 6849.5,
```

so its integer magnitude is at most `6849`, strictly below `M/2`.

## Adjacent-tray K-Elimination

The same source-correlated residual gives a direct carry quotient through the
arbitrary tray `A=M+1=32769`. Since

```text
X = M*K + M/2 + e99
  = A*K + (M/2 + e99 - K),
```

and `|e99|<=6849`, `|K|<=48`, the final remainder is strictly inside
`[9487,23281]`, hence canonical in `[0,A)`. Therefore
`floor(X/A)=K` on the admitted source window. Also `2*A=p+1`, so
`A^(-1)=2 mod p` and

```text
K = 2 * (X mod p - (X mod A) mod p) mod p.
e99 = (X mod A) + K - M/2 mod p.
```

This uses a dependent `A` tray in the common `p` encoding and needs no
signed-centering or carry-sign operation. The exact oracle checks all 13,423
source-correlated chart points, including `K=-48` and `K=48`; observed
canonical tray residues range from `9553` to `23215`. The proof depends on
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

The certified source envelope gives `|2*e99-K| <= 2*6849+48 = 13746 < p/2`.
Thus the centered p residue `w=center(Y mod p)` is exactly `2*e99-K`, and
`K` is the quotient in `Y=w+p*K`. Modulo the composite tray `A=98=2*7^2`,
`p=73` and `73^(-1)=47`, so

```text
K = center_98(47 * ((Y mod 98) - (w mod 98)) mod 98).
```

The corridor `|K|<=48<49` makes the centered residue unique. The exact oracle
checks this identity on all 13,423 source-correlated `Z99` values; the largest
observed `|w|` is 13,680. Tray 98 uses existing Safe-Basis factors 2 and 7
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
for all 13,423 source-correlated chart points and all five carry boundaries.

This factors the residue arithmetic; it does not make signed conversion a
linear ciphertext operation. The composite route first needs an encrypted
centering decision for `Y mod p` to form `w`. It then needs canonical `k49` in
`[0,48]`, its parity, and the correction bit to lift K into the common p
encoding. The direct `2^15` route avoids both of these centering operations:
its K-Elimination output is already `K mod p`. Neither route has a dense-source
implementation. The current Rust selector probe checks the 98 residue only
and centers `w` and K in its client oracle; it does not test either encrypted
decision.

## Composite scale-locked quotient readout

The low-tray producer can be avoided by using the chart's adjacent integer
scale directly. Let `A=M+1`, `T=p*A`, and `x=99*Z99`. On the source-correlated
window,

```text
x = A*K + (e99-K),
|e99-K| <= 6849+48 = 6897 < A/2.
```

Precharge the same sparse source under plaintext scale `T`, form the encrypted
99 chart there, and multiply its ciphertext by 99. If `phi_T` is a centered
decryption phase and `B=|T*phi_T-Q*x|<Q/2` is the issued T-scale error bound,
decoding those same ciphertext components under `p` gives

```text
round(p*phi_T/Q) = round(x/A + (T*phi_T-Q*x)/(A*Q)) = K.
```

The ciphertext-noise contribution is below `1/(2*A)`. The integer margin is
strict because `2*6897+1=13795 < 32769`; no low residue, centering bit, extra
Safe-Basis root, clear quotient, or re-encryption is involved. Negative carries
retain their ordinary `Z_p` encoding.

The Rust integration exercises this with a screened four-prime
`N_outer=16384` chain and `T=2,147,581,953`. In the native source-weight-96,
`Q/16` test, the same chart ciphertext decodes to `K_phase` at all 16,384
doubled-ring coefficients, including odd zeros. Its measured maximum
`|99*Z99-A*K|` is 2,574; the certificate uses the wider source bound 6,897.
Scaling the affine componentwise Phase 1 term by `A`, then adding the carry
ciphertext, also recovers the original source plaintext at every coefficient.
Both component and carry bounds fit below `Q/2` before p-view decoding. The
`N=512`, weight-2 test checks the same path. The separate `Root211` and tray
experiments remain useful alternatives, but are no longer needed to produce
or apply this carry.

The follow-up now measures the corrected output's phase error under `p` rather
than stopping at successful decryption. Let `r=99*Z99-A*K` and `V_T` be the
T-scaled error around its T-scale plaintext `A*m+r`; then

```text
V_p = |p*phase-Q*m| <= (Q*|r|+V_T)/A.
```

The native N8192 run observed 121-bit p-view error against a 125-bit
`Q_outer` (with a 122-bit bound), while the input bound was 56 bits against a
60-bit `Q_source`: both are at the live `Q/16` scale, so this is carry
correction without noise contraction. The N512 diagnostic observed 121/125
bits at the output versus 53/60 at input, showing the same chart remainder can
raise a quieter input to roughly the `Q/16` scale. The readout therefore
solves the hidden integer carry but does not refresh the residual phase.

## Remaining encrypted obligations

The scale-locked experiment closes the dense chart's carry readout and affine
Phase 1 correction under its sparse-source, basis, level, and error contract.
Production still needs a typed capability that binds the `T` precharge to the
source key/history and active level and issues its phase/noise certificate.
The measured p-view error retains the `(Q/A)*r` term, so an independent
canonical-residual or carry ciphertext is still required to prove error
reduction through the next dense multiplication and a second refresh. A failed
phase, history, capacity, security, or return certificate must refuse before
output. Issue #95 remains open and production refresh remains fail-closed.
