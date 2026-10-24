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
| `K_s=round(S/Q_s)` | Covering-space sheet / hidden carry for the source phase | Rank-one tropical theta minimizer; composite scale-locked BFV readout decodes the native 99-chart ciphertext as `K_phase` at every doubled-ring coefficient | Typed source/history/level binding and issued producer certificate |
| `g=S-Q_s*K_s` | Centered torus representative | Defined by the lift; local chart and source phase windows are checked | Preserve or recover its high-encoding representative with bounded error |
| `T_Q(S)` | Rank-one tropical theta lift | `argmin_n(Q_s*n^2+2*n*S)=-K_s`; finite difference is `-2K_s-b` | No encrypted native theta-difference producer yet |
| `Z99,Z121,Z143` | Publicly weighted integer chart views | Encrypted research producer constructs the 99/121 pair from one composite-scale sparse-source precharge; multiplying `Z99` by 99 and decoding under `p` returns `K_phase` | Production key/history/level binding and certified residual return remain open |
| `U,D,E_chart` | Unimodular chart coordinates | Integer Jacobian has determinant 1; `D,E_chart` cancel ideal sheet direction, `U` retains winding | Information preservation alone does not contract ciphertext error or recover canonical `K_s` |
| `Phi_121,W_11` | 11-adic ring section and Witt quotient | Native section is invariant under `+11H`; chart identity checked coefficientwise | `W_11` is not the coefficientwise integer lift or canonical residual |
| `K99` | Chart quotient `floor((99*Z99+M/2)/M)` | The native batched producer matches `K_phase` at all 8,192 source coefficients; its composite-scale ciphertext decodes to `K_phase` at all 16,384 doubled-ring coefficients under the same RNS key | Bind the scale-`T` precharge and its noise bound to production source history and level |
| `K_phase,j` | Actual Phase 1 correction between combined BFV rounding and independent component rounding, coefficient `j` | For `S=R0+R1*s` and `Q_s=Q_level`, it is exactly `K_s=round(S/Q_s)`; N32 oracle and native N8192 tests verify carry readout and affine-plus-carry recovery | Bind the research precharge to production source history and connect the corrected result to the certified residual return |
| `r=X mod M`, or `a=X mod (M+1)` | Optional low tray for a K-Elimination readout of `X=99*Z99+M/2` | `M=32768`; adjacent-tray integer identity and bounded encrypted consumer are checked; native `Z99` already has a direct quotient map to `K_phase` | If used, produce its same-root common-`p` view with a producer-issued bound; it is not needed for the direct quotient identity |
| `X_p=X mod p` | High residue of the same integer `X` | Linear from `Z99` in the public chart encoding | Must share the exact source/history binding of `r` or `a` |
| `e99=99*Z99-M*K99` | Centered chart remainder; equivalently `r-M/2` or `a+K99-M/2` | Exact zero sheet derivative; live `Q/16` source-correlated bound is 6849 | Establish a correction consumer and a full error/reset certificate |
| `K_T` | High-encoded carry residue modulo `T=p*A` | Paired-coordinate K-Elimination consumer passes oracle-injected N512/N1024 tests; one-root S8 clear oracle derives K mod T from odd-lane M residues plus the 2-lane M+1 tray at all 13,423 source points; live-chart M-tray consumer returns exactly at N512, N1024, and native N8192 when `r_M` is oracle encrypted, with centered inverse | Produce same-history chart/sister-tray ciphertext residues and evaluate the bounded signed lift into T; certify tray and carry noise |
| `R_T=x_T-A*K_T` | T-encoded chart residual | Oracle-injected K-Elimination subtraction removes `r/A` from the p-view return | Bind the residual to the same chart capability and include both chart and carry errors in its certificate |
| `V_out` | Error after residual correction and return | Paired `(S,g)` oracle control: 70/77 bits at N512 and 83/84 bits at N1024; low-tray oracle route: 79/87, 85/92, and native 96/104 bits; low-tray square passes at N512/N1024 but the next product fails at 948/1024 and 2047/2048 coefficients; native first square fails at 69/16384 | Public same-history `g_T` or low-tray producer, noise contraction/certificate, return to work key, refresh after the first product, and a second admitted refresh remain open |

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
8,192 coefficients. A second native test places the precharge at
`T=p*(M+1)=2,147,581,953`, scales the chart ciphertext by 99, and decodes the
same components under the `p=65,537` view. All 16,384 doubled-ring
coefficients, including odd zeros, return `K_phase`; the largest observed
`|99*Z99-(M+1)K|` is 2,574, inside the certified 6,897 bound. The four-prime
`N=16,384` outer chain passes the repository's 128-bit screen under both
models. The general dense work-key path has secret weight up to N and does not
inherit the radius-48 contract until the sparse-source transform and its
authenticated history are included.

The `Root211` selector fixture remains a separate test-only consumer: it
checks K-Elimination and tray arithmetic after receiving bounded selector
rows. The composite scale lock now supplies a dense encrypted carry readout
without that selector root. `D` and `E_chart` are chart residual coordinates;
they are not automatically the centered source phase `g` or the return
residual `e99`.

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
carry. The native N8192 batched chart plus composite scale lock now emits a
ciphertext that decodes to this carry under the p view. The native test also
adds it to the affine component result and recovers the original source
plaintext across all 16,384 doubled-ring coefficients. The remaining Phase 1
gate is a typed producer bound to the actual source key, history, phase cap,
and level; direct paired `S mod A`, `g mod A` production remains an alternate
route, not a prerequisite for the chart route.

Bind the composite-scale chart precharge to the actual source key, history,
phase cap, and active RNS level. The evaluator uses public polynomial
weighting, a scalar-by-99 operation, and affine-plus-carry ciphertext
addition; p-view decoding is ordinary BFV decryption of the resulting
ciphertext. Check both signs, chart boundaries, all RNS lanes, and odd zero
coefficients against the client oracle. Then connect the corrected phase to
the residual return and prove error reduction through the next product and a
second refresh. Keep the public gate closed until those return certificates
pass.

## Direct ultradiscrete carry route at the doubled degree

There is a second route to the same `K_phase` that avoids applying a
polynomial quotient to `Z99`. The existing native phase clock directly selects
the signed carry from the public component residuals and the encrypted sparse
source trits. For source degree8192, use its already present doubled outer
degree16384, source period
`Q60=998244353*985661441`, source error cap `V<=Q60/16`, and odd clock
coordinate99. Its certified twice-window is

```text
ceil(2*(2*16384)*(Q60/16)/Q60) + 99*(96+1)
= 4096 + 9603
= 13699 < 16384.
```

The source phase bound proves the carry radius: `|S| < 97Q/2`, while
`|K|=49` and `|g|<=Q/16` would imply
`|S| >= 49Q-Q/16 = 783Q/16 > 776Q/16 = 97Q/2`. Thus `K` is in `[-48,48]`;
`99 > 2*48` makes its signed representative unique. The integer geometry
exhausts every admitted rotation on all 97 carry plateaus and refuses the
dense-source window. This identifies the same hidden sheet as the native
`Z99` identity and supplies an ultradiscrete lookup geometry without a
polynomial quotient.

This direct-clock route resolves the *geometric support/window* question. The
current test helper `evaluate_clock` accepts one scalar
phase and one weight per source-key position, then returns that coefficient's
constant-term readout; it is not a batched 8192-coefficient evaluator. Naively
calling it once per target coefficient with 8192 hidden source positions
would make 67,108,864 selector steps. Each step performs four tensor
relinearization calls, or 268,435,456 calls before the final traces. The
batched 99/121 chart plus composite scale lock is the CRAM carry-readout path;
the direct clock helper is not needed online. Neither geometry nor carry
readout proves the corrected return, repeat, or admission.

The exact Python mirror checked all 97 plateaus, 13,423 admitted rotations,
and the dense-source refusal. The encrypted scale-lock test passed at both
`N=512` and native `N=8192`; its opt-in native case ran across all source and
doubled-ring coefficients. This is carry-readout evidence only, not repeated
refresh or public-refresh admission.

## Composite scale-locked carry readout

The dense chart no longer needs a low-residue tray to emit the carry. Set
`A=M+1`, `T=p*A`, and `x=99*Z99`. The source-correlated chart identity is

```text
x = A*K + (e99-K),
|e99-K| <= 6849+48 = 6897.
```

Precharge the same sparse source under plaintext scale `T` and form `Z99` with
the public chart weights. If `phi_T` is the centered phase and
`B=|T*phi_T-Q*x|<Q/2`, the same ciphertext decoded under `p` yields

```text
round(p*phi_T/Q) = round(x/A + (T*phi_T-Q*x)/(A*Q)) = K.
```

For the native chart, `M=32768`, `A=32769`, and `T=2,147,581,953`. The
worst-case integer condition is strict:
`2*6897+1=13795 < 32769`; valid T-scale BFV noise contributes less than
`1/(2*A)`. Thus the p decoder returns K in its ordinary signed-residue
encoding. The evaluator constructs the chart, multiplies the ciphertext by
99, and decodes under p. It does not evaluate a clear quotient, center a
residue, or require another Safe-Basis root.

The focused encrypted tests passed at `N=512`; the native `N=8192`, weight-96,
`Q/16` test passed for all 8,192 source coefficients and all 16,384 doubled
ring coefficients, including odd zeros. The affine-plus-carry Phase 1
consumer also recovered the source plaintext at every doubled-ring
coefficient. It observed a maximum
`|99*Z99-A*K|=2574`, within the source certificate 6,897. Its four-prime
outer chain passed the repository's 128-bit security screen under both
models. These tests prove carry readout and the affine Phase 1 consumer for
that research source contract. They do not bind the precharge into a
production capability or prove return noise contraction.

## Tray-based K-Elimination alternatives

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
unique centered lift. The exact oracle checks this over 13,423 source-correlated
chart points. A bounded encrypted selector fixture checks the modular
identity at five carries, but centers the result only in its client oracle.
It avoids requiring the full `2^15` low tray, but still requires both
composite-98 views from the same dense-source history, centering of the p
residue used to form `w`, and a signed lift from `K mod 98` into the p ring.

Splitting the composite tray as `98=49*2` gives an exact signed reconstruction:
`k49=((Y49-w49)*47) mod 49`, `k2=(Y2-w2) mod 2`,
`c=(k49-k2) mod 2`, and `K=k49-49*c`. In the bounded carry range, `c=1`
exactly for negative `K`. The integer oracle checks this on the same 13,423
source-correlated points. This isolates the residue-to-signed lift on the
composite route: after centering `Y mod p`, the encrypted path must produce
canonical `k49` and its parity, then apply the correction to obtain `K mod p`.
Those centering and canonicalization/sign gates have not been implemented or
tested on the dense chart. They are not required by the direct `2^15`/p
K-Elimination route.

The existing `Root211` test capability still verifies its tray formulas for
bounded selector states, and composite98 remains an alternate route requiring
same-history 49/2 and p views, encrypted centering, and signed canonicalization.
Neither tray route is needed by the scale-locked carry producer. A standalone
ciphertext at plaintext modulus `M` still cannot be relabeled as an `Enc_p`
tray; the composite method instead changes the BFV scale of the precharged
source and uses the same ciphertext components under p.

The carry readout and affine Phase 1 addition do not reset error. `e99` is
bounded by 6,849 under the live `Q/16` source-correlation assumptions, and the
p-view readout retains the fraction `(e99-K)/A`. A new isolation control
shows the cancellation form: if `S=Q_s*K+g` and `S_T,g_T` are supplied in the
same T encoding, public K-Elimination yields `K_T=(S_T-g_T)*Q_s^(-1) mod T`.
Then `R_T=x_T-A*K_T` is a ciphertext for the chart residual, and subtracting
it from affine-plus-chart removes the p-view residual. That control uses a
key-holder oracle for `g_T`. A new exact one-root route instead derives K in
each S8 lane using the M tray on odd lanes and the M+1 tray on lane2, then
uses the bounded lift to project `K mod T`; its 13,423 checks cover both carry
boundaries. The encrypted same-history trays and bounded lift remain open. At N512 the
corrected ciphertext survives a square and another product; at N1024 the
square passes and the next product fails at 2045/2048 coefficients. The
larger case therefore needs another refresh before that product, with a
producer-issued bound at each step.

The new diagnostic measures this term directly. With `r=99*Z99-A*K` and
`V_T` the phase error around the T-scale plaintext `A*m+r`, the same ciphertext
viewed under `p` has

```text
V_p = |p*phase-Q*m| <= (Q*|r|+V_T)/A.
```

At native `N=8192`, the measured p-view error is 121 bits against a 125-bit
outer modulus, while input error is 56 bits against the 60-bit source modulus.
That matches the incoming `Q/16` envelope and shows that reading `K` plus
adding it to the affine result preserves plaintext correctness without
contracting phase error. The oracle ablation gives the required residual
consumer and error target; the authenticated public `g_T` producer is still
the missing part.

## Required implementation order

1. Bind the composite-scale precharge and batched 99/121 chart output to the
   actual source key, history, phase cap, and active RNS level. Keep 121 as
   the paired chart check; reject caller-supplied phase snapshots.
2. The scale-locked carry readout passes in the research producer. Turn its
   T-scale error bound and same-key phase relation into a typed production
   certificate; refuse if the scale, support, or noise inequality does not fit.
3. Preserve the tested affine-plus-carry Phase 1 consumer in the typed
   production path. Extend its checked envelope to both signs, chart-cell
   boundaries, nonzero source error, every RNS lane, and odd zero coefficients
   against the client oracle.
4. Produce the same-history T-encoded `r_M` (or the S8/M/(M+1) phase-locked
   views) for the live `X_T`. Apply centered-inverse K-Elimination or the
   bounded S8 lift to `K_T`, subtract `A*K_T`, and issue an immutable bound.
   The exact CRT oracle and separately encrypted tray are not encrypted tray
   producers and cannot reset the certificate.
5. Return to the work key and require an exact native next multiply, then a
   second refresh and the repeat multiply. The current native oracle-tray
   output misses 69/16,384 coefficients on its first square, so it is not
   admitted. Also run corrupted-root/history negatives and the exact
   security/admission checks.

Until all five gates pass, issue #95 remains open, production refresh remains
fail-closed, and the execution plan's R00--R03 admission gates remain active.

Related evidence: [tropical lift and K-Elimination](../2026-10-22/TROPICAL_LIFT_K_ELIMINATION.md),
[paired chart K-Elimination](PAIRED_CHART_K_ELIMINATION.md),
[batched paired chart](BATCHED_PAIRED_LIFT.md),
[three-view chart](TRIPLE_LIFT_DOMAIN.md),
[11-adic section](FROBENIUS_CHART_SECTION.md), and
[scale-locked tray](SCALE_LOCKED_CARRY_TRAY.md).
