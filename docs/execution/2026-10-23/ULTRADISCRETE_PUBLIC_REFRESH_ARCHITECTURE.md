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
| `K_s=round(S/Q_s)` | Covering-space sheet / hidden carry for the source phase | Rank-one tropical theta minimizer; paired-coordinate K-Elimination consumer tested; 99-chart quotient equals `K_phase` for all native sparse-source coefficients | Encrypted quotient/readout and source-history-bound certificate |
| `g=S-Q_s*K_s` | Centered torus representative | Defined by the lift; local chart and source phase windows are checked | Preserve or recover its high-encoding representative with bounded error |
| `T_Q(S)` | Rank-one tropical theta lift | `argmin_n(Q_s*n^2+2*n*S)=-K_s`; finite difference is `-2K_s-b` | No encrypted native theta-difference producer yet |
| `Z99,Z121,Z143` | Publicly weighted integer chart views | Encrypted research producer constructs the 99/121 pair for all native coefficients from one sparse-source precharge; 99 quotient matches `K_phase` on its admitted envelope | Production key/history binding and encrypted nonlinear readout remain open |
| `U,D,E_chart` | Unimodular chart coordinates | Integer Jacobian has determinant 1; `D,E_chart` cancel ideal sheet direction, `U` retains winding | Information preservation alone does not contract ciphertext error or recover canonical `K_s` |
| `Phi_121,W_11` | 11-adic ring section and Witt quotient | Native section is invariant under `+11H`; chart identity checked coefficientwise | `W_11` is not the coefficientwise integer lift or canonical residual |
| `K99` | Chart quotient `floor((99*Z99+M/2)/M)` | The native batched 99-chart producer now matches `K_phase` on all 8,192 coefficients for the same source ciphertext, key, and component-rounding residuals; `|K|<=48` under source weight 96 and phase cap `Q/16` | Evaluate this bounded integer quotient homomorphically with a producer-issued bound and bind it to the source/root/history; the current comparison uses a client oracle |
| `K_phase,j` | Actual Phase 1 correction between combined BFV rounding and independent component rounding, coefficient `j` | For `S=R0+R1*s` and `Q_s=Q_level`, it is exactly `K_s=round(S/Q_s)`; a deterministic N32 oracle and native N8192 batched-chart cross-check verify the identity and chart map | Turn the encrypted 99-chart value into `K_phase` without a clear quotient/readout, then connect it to the public Phase 1 consumer |
| `r=X mod M`, or `a=X mod (M+1)` | Optional low tray for a K-Elimination readout of `X=99*Z99+M/2` | `M=32768`; adjacent-tray integer identity and bounded encrypted consumer are checked; native `Z99` already has a direct quotient map to `K_phase` | If used, produce its same-root common-`p` view with a producer-issued bound; it is not needed for the direct quotient identity |
| `X_p=X mod p` | High residue of the same integer `X` | Linear from `Z99` in the public chart encoding | Must share the exact source/history binding of `r` or `a` |
| `e99=99*Z99-M*K99` | Centered chart remainder; equivalently `r-M/2` or `a+K99-M/2` | Exact zero sheet derivative; source-correlated bound is 5313 | Establish a correction consumer and a full error/reset certificate |
| `V_out` | Error after residual correction and return | Existing scale-locked probes carry source residual into the return | Must pass return, next dense multiplication, and a second refresh with issued bounds |

When `S` is the exact component-rounding residual polynomial
`R0+R1*s` and `Q_s` is the active `Q_level`, `K_phase,j` and `K_s` are the
same quotient by definition. The native N8192 experiment now also checks that
the *actual batched 99-chart integer* yields that quotient for every
coefficient under its declared source contract: source-secret weight at most
96, source phase-error cap `Q/16`, `M=32768`, and chart representative
`|Z99|<=16005<p/2`. In this domain, with `z=Z99`,

```text
z = M/99 * (K_s + g/Q_s) + epsilon,
|epsilon| <= (96+1)/2,
|g/Q_s| <= 1/16,
|99*z/M - K_s| <= 1/16 + 99*48.5/32768 < 1/2.
```

Therefore `round(99*z/M)=K_s=K_phase`. The carry radius tightens to 48:
`|S| <= 97*Q/2` and `|g|<=Q/16` exclude `|K|=49`. This closes the earlier
scale/lift identity gap for this producer and sparse-source envelope. The
experiment independently reconstructs `R0,R1` from the live source
ciphertext and compares the chart quotient with `round((R0+R1*s)/Q)` at all
8,192 coefficients. Its quotient comparison remains a client oracle; the
evaluator still needs an encrypted readout. The general dense work-key path
has secret weight up to N and does not inherit the radius-48 contract until
the sparse-source transform and its authenticated history are included.

The `Root211` selector fixture remains a separate test-only consumer: it
checks K-Elimination and tray arithmetic after receiving bounded selector
rows. It does not implement the nonlinear readout of the dense chart. `D`
and `E_chart` are chart residual coordinates; they are not automatically the
centered source phase `g` or the return residual `e99`.

The new exact oracle
[`phase1_tropical_k_elimination.py`](../../../scripts/phase1_tropical_k_elimination.py)
uses the N32 research parameters `Q=5,000,003`, `t=65,537`. Across 40 full
polynomial cases (1,280 coefficient checks), it forms the actual component
rounding residuals, computes the secret convolution, and confirms that the
difference between combined-phase rounding and independent component
rounding is `round((R0+R1*s)/Q)` at every coefficient. It then recovers that
signed carry through trays `2^15`, `2^15+1`, and `t`, including all carry
values in `[-16,16]` and centered-cell endpoints. This establishes the clear
algebraic bridge to the Phase 1 target. The test oracle knows the secret and
constructs both residues directly; it does not test the encrypted producer.

## Bridge from the disabled Phase 1 target

`ClockworkBootstrap::modswitch_to_t` independently scales the public `c0` and
`c1` polynomial coefficients. Its Phase 1 soundness comment defines the
correction as `K_phase,j=round((R0_j+(R1*s)_j)/Q_level)`, where `R0,R1` are
the component-rounding residuals. Set `S=R0+R1*s` and `Q_s=Q_level`; then
the tropical lift's `K_s=round(S/Q_s)` is exactly the needed correction, per
coefficient. The rank-one theta minimizer therefore names the right hidden
carry. The native N8192 batched chart cross-check now proves that its bounded
99-view quotient is this same carry under the sparse-source contract. The
remaining Phase 1 gate is an encrypted quotient/readout with a bound and
source-history binding; direct paired `S mod A`, `g mod A` production remains
an alternate route, not a prerequisite for the chart route.

The chart readout must work from the actual encrypted `Z99` and the existing
Safe-Basis root or a phase-locked dependent tray. It must not center or round
the decrypted value in the evaluator. Check every coefficient, signed
boundary, source error, and active RNS level against the client oracle. Then
connect the result to the residual return and prove error reduction through
the next product and a second refresh. Keep the public gate closed until the
encrypted readout and return certificates pass.

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

1. Bind the existing Safe-Basis root and the batched 99/121 chart output to
   the actual source key, history, phase cap, and active RNS level. Keep 121
   as the paired chart check; do not add another root or accept caller-
   supplied phase snapshots.
2. Implement the encrypted bounded quotient `round(99*Z99/32768)` or an
   equivalent 2/11 phase-locked K-Elimination readout in the common
   plaintext-65537 encoding. Prove its support and certify chart error,
   source precharge, public polynomial norms, scale floors, tray
   canonicalization, and key switches before output. Refuse if the
   certificate does not fit.
3. Add the encrypted carry to the affine Phase 1 result and check all
   coefficients, both signs, chart-cell boundaries, nonzero source error,
   all RNS lanes, and odd zero coefficients against an independent client
   oracle.
4. Connect the corrected phase to the canonical high-encoding
   residual/removal consumer. Issue an immutable bound; do not reset error on
   the strength of the integer identity or a client measurement.
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
