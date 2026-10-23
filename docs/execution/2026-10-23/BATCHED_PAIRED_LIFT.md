# Native encrypted initialization of a paired integer lift chart

The weighted lift phase is now constructed for all8192 source coefficients
at once. Composites99 and121 share the11 anchor. Their encrypted views
produce a bounded K-eliminated residual and an integer coordinate preserving
the original pair. Every native ciphertext coefficient and every odd zero
coefficient passes independent client checks.

This advances the CRAM-native K-elimination route: the native paired chart
can be initialized from public input components and one encrypted source
polynomial. The encrypted nonlinear map consuming that chart remains open.
The new chart is not an admitted refresh, and its initialization timings
are not bootstrap timings.

## Public batch construction at the actual native domain

Use sourceN8192/Q60 with balanced source norm96, outerN16384/Q241,
p65537, phase capQ60/16 and M=2*N_outer=32768. The previously implemented
dense-work/source switch supplies this source domain. Source precharge
encrypts `s_source(Y^2)` under the dense outer key.

For each public input component and odd composite m, residue-only projection
forms `b_m = round(M*(p*C/Q-A)/m)`, with `A=round(p*C/Q)`. The rounded
weighted source polynomial is

`Z_m = B_m,0 + B_m,1 * s_source`.

One signed PUBLIC polynomial multiplication by the encrypted source, plus
one public plaintext addition, constructs all coefficients of encrypted Z_m.
The multiplication uses negacyclic wrap and signed weights directly in each
ciphertext prime. It visits no private source support. The source norm is a
public bound; the secret and client phase measurements do not enter these
operations.

For m99 and m121, the clock widths are13699 and15833, both below16384.
Their conservative signed Z bounds are16005 and13095, both below p/2.
Thus decryption modulo p retains an unambiguous integer representative for
these chart inputs. This is an actual Q60 residue construction, not a small
period substituted for the source modulus.

## K-elimination and the integer Jacobian

Write `R0+R1*s_source=Q*K+g`, with `|g|<=V_source`. The ideal parts of the
two weighted views are `M*(K+g/Q)/99` and `M*(K+g/Q)/121`. Therefore

```text
D =  9*Z99 - 11*Z121       ideal part: 0
U = -4*Z99 +  5*Z121       ideal part: M*(K+g/Q)/1089

Z99  = 11*U + 5*D
Z121 =  9*U + 4*D.
```

The integer coordinate matrix has determinant -1. Its inverse also has
integer coefficients, so this chart preserves the entire pair, and is
invertible modulo2, modulo11 and every dependent composite. No division by
a nonunit, added Safe Basis root or new persistent ciphertext lane is needed.
This is an explicit constant integer Jacobian; it does not by itself
establish a nonlinear tropical lift map or cryptographic root admission.

For one component x, `D(x)=9*round(x/99)-11*round(x/121)` contains only
rounding residuals. A conservative bound is10 per source term, hence
`|D|<=970`. Public enumeration of every component rounding cell sharpens
that to9 per term and873 for norm96; the encrypted probe retains the
conservative970 allowance. The same enumeration gives `|U_component|<=19`
and `|U|<=1843`.

At the component level, increasing x by1089 leaves D unchanged and increases
U by1. Thus the periodic coordinate retains a separate integer winding;
it does not discard the sheet. The public audit checks all571 component
pairs over the native interval, every rounding boundary/open cell, the
period relation, and reconstruction modulo2,11,22,99,121,198 and65537.

## Shared-precharge errors must stay correlated

The same encrypted source is used in both views. Combining their public
weights FIRST produces exactly the same ciphertext as the encrypted linear
combination. That equality holds bit for bit in every native output limb.
The error certificate can therefore charge the smaller combined public
polynomial l1 norm; it does not invent independent errors or reset to eta.

Let V_pre be the full fresh source-precharge error, r=Q_outer mod p and
W0/W1 the combined signed public polynomials. The public certificate is

`V_out <= V_pre * ||W1||_1 + r * ||W0||_infinity`.

V_pre includes the complete encryption error and floor-Delta remainder.
The certificate is computed before client observation. The native run gives:

| Quantity | Result |
| --- | ---: |
| Source coefficient count checked per view | 8192 |
| Outer odd zero coefficients checked per view | 8192 |
| Observed hidden sheets | -9 through10 |
| Z99 observed / bound magnitude | 3327 /16005 |
| Z121 observed / bound magnitude | 2728 /13095 |
| D observed / bound magnitude | 142 /970 |
| U observed / bound magnitude | 344 /1843 |
| D public polynomial l1 norm | 27429 |
| U public polynomial l1 norm | 61964 |
| D observed / direct error bound | 39 /49 bits |
| D bound from separate-view triangle inequality | 57 bits |
| U observed / direct error bound | 40 /50 bits |

Both original encrypted Z views reconstruct from encrypted U/D bit for bit.
Neglecting the negacyclic wrap changes7995 Z99 values and7992 Z121 values.
The small N16 version also checks both reconstructions and the same error
accounting, with explicitly insecure parameters.

In the isolated accepted run, constructing D from its public weights takes
0.168637seconds and U takes0.210950seconds on this machine. Those timings
cover the signed polynomial multiplication and public addition after public
weights/precharge preparation. They exclude setup, residue preprocessing,
client checks, nonlinear evaluation and return. Constructing U/D directly
needs two public polynomial multiplications and no selector-key expansion;
the reference Z views in the test exist to verify the exact identities.

## The remaining nonlinear problem is precise

The same D value occurs with different hidden K values in6824 native
negative-control comparisons. D alone cannot identify K. The inverse chart
retains the information needed for an exact integer map such as

`K = round(99*(11*U+5*D)/32768)`

on the admitted source phase window. The native test checks that identity
with a CLIENT oracle. It does not evaluate that integer map homomorphically.
The U coordinate still has an ideal g/Q contribution. Returning a linear
function of U alone would preserve old phase dependence.

The next required step is an encrypted, batched chart map on this actual
bounded (U,D) domain, with a complete polynomial/encoding/noise and key-cost
ledger. Its output must support the certified return, useful next operation
and another native refresh. The existing per-coefficient clock is a
correctness reference with impractical native switch count; it is not used
to claim a practical result here. No low-degree bivariate gate has yet been
proved or compiled for the entire reachable native chart domain.

Source attack-model coverage, joint/KDM key security, authenticated key,
domain, epoch and history, and intact S8/Root211 capability integration remain
requirements for admission. The completed24 configured source estimates and
their161.34-bit minimum do not remove those requirements.

Implementation: `crates/nine65/tests/research/batched_lift_phase.rs` and its
registration in `sparse_source_encapsulation.rs`. Reproducible public cell
audit: `python3 scripts/paired_composite_lift_chart.py`. Exact evidence and
scope flags are in `artifacts/execution/2026-10-23/batched-paired-lift/`.
The complete focused Rust harness passes30 tests and the five Python suites
pass31, for61 local unit checks; the isolated paired run and public cell
audit also pass. The focused harness links the unchanged Cargo-built library
with debug assertions and overflow checks enabled. No package-wide build or
hosted Rust CI success is claimed.
Production refresh remains fail-closed; no external backend or lint is added.
