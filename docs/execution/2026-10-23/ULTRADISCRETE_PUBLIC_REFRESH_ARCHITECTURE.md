# Public refresh variables and the remaining lift gate

This is the current variable map for issue #95, combining the source phase,
the tropical sheet, the native paired chart, the 11-adic section, and the
candidate K-Elimination consumer. It keeps the CRAM-native route in scope.
The linked experiments are research evidence; none currently admits public
refresh.

## Variable map

| Symbol | Meaning in the refresh path | Current representation and evidence | Open condition |
|---|---|---|---|
| `Q_s` | Source ciphertext modulus product | Native source phase and source-to-outer chart probes | Authenticate exact basis, level, key domain, and source history |
| `S=R0+R1*s` | Secret-dependent source phase before centered reduction | Research probes form public-weighted views from an encrypted source precharge | Prove the coefficientwise map from the live BFV component-rounding residuals into the chart input; wire that producer into public Phase 1 |
| `V_s` | Certified source phase error, including encryption, scale floor, and prior work | Source bounds and phase caps are recorded per probe | Carry an enforceable producer certificate through the whole route |
| `K_s=round(S/Q_s)` | Covering-space sheet / hidden carry | Rank-one tropical theta minimizer; Safe-Basis K-Elimination is tested when paired coordinates are supplied | Produce the required paired coordinates from the live source without a clear lift oracle |
| `g=S-Q_s*K_s` | Centered torus representative | Defined by the lift; local chart and source phase windows are checked | Preserve or recover its high-encoding representative with bounded error |
| `T_Q(S)` | Rank-one tropical theta lift | `argmin_n(Q_s*n^2+2*n*S)=-K_s`; finite difference is `-2K_s-b` | No encrypted native theta-difference producer yet |
| `Z99,Z121,Z143` | Publicly weighted integer chart views | Batched research probes construct 99/121/143 views from one source precharge | Production dense outputs, their common encrypted root/history, and the nonlinear readout remain open |
| `U,D,E_chart` | Unimodular chart coordinates | Integer Jacobian has determinant 1; `D,E_chart` cancel ideal sheet direction, `U` retains winding | Information preservation alone does not contract ciphertext error or recover canonical `K_s` |
| `Phi_121,W_11` | 11-adic ring section and Witt quotient | Native section is invariant under `+11H`; chart identity checked coefficientwise | `W_11` is not the coefficientwise integer lift or canonical residual |
| `K99` | Candidate chart carry `floor((99*Z99+M/2)/M)` | Clear exact oracle covers 10,411 source-correlated points; one-root encrypted-selector fixture checks `K mod p` and `e99 mod p` for `[-48,-1,0,1,48]`, including the composite-98 residue | Same-root dense producer for the common-p low tray is missing; direct K-Elimination needs no separate signed-centering operation |
| `K_phase,j` | Actual Phase 1 correction between combined BFV rounding and independent component rounding, coefficient `j` | Defined by the `bootstrap.rs` phase oracle; current public gate refuses because this secret-dependent correction has no producer | Derive and prove the coefficientwise bridge from `K_phase,j` to the chart carry `K99`; the chart fixture does not establish this identity |
| `r=X mod M`, or `a=X mod (M+1)` | Canonical low tray for `X=99*Z99+M/2` | `M=32768`; the adjacent-tray oracle proves `X=(M+1)K+a` on all 10,411 source-correlated chart points, with `(M+1)^(-1)=2 mod p`; bounded encrypted fixture checks `a` with `X_p` on five carries | Produce the low tray from the actual dense chart/root/history in common `p=65537` encoding with a producer-issued error bound |
| `X_p=X mod p` | High residue of the same integer `X` | Linear from `Z99` in the public chart encoding | Must share the exact source/history binding of `r` or `a` |
| `e99=99*Z99-M*K99` | Centered chart remainder; equivalently `r-M/2` or `a+K99-M/2` | Exact zero sheet derivative; source-correlated bound is 5313 | Establish a correction consumer and a full error/reset certificate |
| `V_out` | Error after residual correction and return | Existing scale-locked probes carry source residual into the return | Must pass return, next dense multiplication, and a second refresh with issued bounds |

`K_phase,j`, `K_s`, and `K99` are distinct variables. `K_s` and `K99` have
the same value only under the chart's certified source correlation. The
paired-chart work has not yet proved that the actual BFV component-rounding
correction `K_phase,j` equals either one, coefficient by coefficient. The
`Root211` selector fixture is test-only and starts from a bounded synthetic
row set; it does not implement a public producer for `K_phase,j` or `Z99`.
Likewise, `D` and `E_chart` are chart residual coordinates; they are not
automatically the centered source phase `g` or the return residual `e99`.

## Bridge from the disabled Phase 1 target

`ClockworkBootstrap::modswitch_to_t` independently scales the public `c0` and
`c1` polynomial coefficients. The Phase 1 test oracle separately forms the
combined phase with the secret and measures the plaintext-ring difference
between that combined switch and the component switch. That coefficientwise
difference is the correction the public evaluator must supply. It depends on
the source rounding remainders and the secret convolution; a chart carry is a
candidate representation of it only after an explicit integer map and bound
are proved for the live ciphertext, active `Q_level`, and every coefficient.

This is the first unresolved bridge, before issuing the dependent `M+1` tray.
The tray equations show how to consume a valid `Z99` carry. They do not create
`Z99` from the `c0/c1` rounding remainders, nor authenticate it to the source
ciphertext. Consequently the current implementation order is: (1) derive the
source-to-chart map for `K_phase,j`; (2) implement its same-history encrypted
chart and low-tray producer with a per-coefficient error certificate; (3)
apply the linear K-Elimination consumer; and (4) prove that residual correction
reduces the returned ciphertext error through the next product and a second
refresh. The fail-closed gate must remain closed until all four pass.

## Candidate CRAM-native gate

The exact chart oracle establishes `X=99*Z99+M/2`. With the original low tray,
`X=r+M*K99`; since `p=2M+1`, `M^(-1)=-2 mod p`, so phase-locked
common-encoding residues give

```text
K99 = 2*(r-X_p) mod p.
e99 = 99*Z99-M*K99 = r-M/2.
```

The adjacent tray `A=M+1` also gives a direct lift on the certified source
window: the residual bound proves `X=A*K99+a` with canonical `a`, and
`2*A=p+1` gives `K99=2*(X_p-a_p) mod p`. This route recovers `e99` as
`a+K99-M/2` in the same ring.

The bound `|K99|<=48<p/2` selects a unique signed integer, while the ciphertext
can retain `K99 mod p`; that is already the correct plaintext-ring encoding
for both signs. `e99` has zero finite difference along the sheet direction.
These are ordinary linear ciphertext operations after the low residue exists.
They directly match the
owner's one-root / dependent-tray design: the root supplies its 2 and 11
roles; `2^15`, 99, and 121 are dependent views, not new Safe-Basis roots.

The Rust selector fixture confirms both direct carry formulas and the residual
formula under the same test root for five carries. The fixture starts from a
bounded synthetic row set selected by encrypted one-hot indicators. It does
not issue the low residue from the production dense chart source, authenticate
its history, or supply the production projection error certificate.

An alternative small tray follows from `Y=198*Z99=p*K99+(2*e99-K99)`.
The source-correlated bound puts the second term inside the centered p cell.
With `A=98=2*7^2`, `p mod A=73`, and `73^(-1)=47`, the residues `Y mod A`
and `center(Y mod p) mod A` determine `K99 mod A`; `|K99|<=48` selects its
unique centered lift. The exact oracle checks this over 10,411 source-correlated
chart points. A bounded encrypted selector fixture checks the modular
identity at five carries, but centers the result only in its client oracle.
It avoids requiring the full `2^15` low tray, but still requires both
composite-98 views from the same dense-source history, centering of the p
residue used to form `w`, and a signed lift from `K mod 98` into the p ring.

Splitting the composite tray as `98=49*2` gives an exact signed reconstruction:
`k49=((Y49-w49)*47) mod 49`, `k2=(Y2-w2) mod 2`,
`c=(k49-k2) mod 2`, and `K=k49-49*c`. In the bounded carry range, `c=1`
exactly for negative `K`. The integer oracle checks this on the same 10,411
source-correlated points. This isolates the residue-to-signed lift on the
composite route: after centering `Y mod p`, the encrypted path must produce
canonical `k49` and its parity, then apply the correction to obtain `K mod p`.
Those centering and canonicalization/sign gates have not been implemented or
tested on the dense chart. They are not required by the direct `2^15`/p
K-Elimination route.

The existing `Root211` test capability can attach arbitrary moduli up to the
plaintext capacity and emits those views in one common plaintext encoding.
The new encrypted probe confirms the original K-Elimination arithmetic for
five boundary carries, but its source is still a bounded encrypted selector
state. The composite98 identity has clear-oracle and bounded selector-fixture
coverage, but no dense-producer coverage.
The native 99/121/143 producer instead starts from a dense encrypted-source
polynomial and emits chart ciphertexts. The missing bridge is an operation
that produces `Enc_p(r)` or `Enc_p(a)` from that actual dense state while
preserving the same root, source, and history binding. A standalone ciphertext
with plaintext modulus `M` does not satisfy the equation: it cannot be
relabeled as `Enc_p(r)`. The composite-98 alternative instead needs same-history 49/2
and p residue views, encrypted centering of `Y mod p`, and the
canonicalization/sign gate described above.

Even after that bridge, `e99` is not a claimed refresh reset. Its 5313 bound
is a bound on the chart residual under the source-correlation assumptions;
it is not a producer-issued bound for the whole return path and next product.
The return consumer must prove how this residual reconstructs the original
plaintext while reducing the incoming phase error. The scale-locked tray
experiment shows that recovering a carry once still leaves enough source
residual to fail the following dense square.

## Required implementation order

1. Integrate one existing Safe-Basis root with the actual public chart state;
   attach views at `M+1`, 99, and 121 without adding a root or accepting
   caller-supplied phase snapshots.
2. Produce `a=X mod (M+1)` in common p encoding; the adjacent-tray
   K-Elimination result already represents signed K in `Z_p`. The equivalent
   `M=2^15` view remains available. If using the composite 49/2 route, produce
   same-history views and certify both the p-residue centering and K lift.
   Charge source precharge error, public polynomial norms, scale-floor terms,
   tray canonicalization, and key switches before output. Refuse if the
   producer certificate does not fit.
3. Compute `K99` and `e99` linearly. Check all coefficients, both signs,
   chart-cell boundaries, nonzero source error, all RNS lanes, and odd zero
   coefficients against an independent client oracle.
4. Connect `e99` to the existing canonical high-encoding residual/removal
   consumer. Issue an immutable bound; do not reset error on the strength of
   the integer identity or a client measurement.
5. Return to the work key and run the next dense multiply, a second refresh,
   corrupted-root/history negatives, and the exact security/admission checks.

Until all five gates pass, issue #95 remains open, production refresh remains
fail-closed, and the execution plan's R00--R03 admission gates remain active.

Related evidence: [tropical lift and K-Elimination](../2026-10-22/TROPICAL_LIFT_K_ELIMINATION.md),
[paired chart K-Elimination](PAIRED_CHART_K_ELIMINATION.md),
[batched paired chart](BATCHED_PAIRED_LIFT.md),
[three-view chart](TRIPLE_LIFT_DOMAIN.md),
[11-adic section](FROBENIUS_CHART_SECTION.md), and
[scale-locked tray](SCALE_LOCKED_CARRY_TRAY.md).
