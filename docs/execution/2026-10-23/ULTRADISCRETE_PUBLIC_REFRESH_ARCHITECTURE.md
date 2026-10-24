# Public refresh variables and the remaining lift gate

This is the current variable map for issue #95, combining the source phase,
the tropical sheet, the native paired chart, the 11-adic section, and the
candidate K-Elimination consumer. It keeps the CRAM-native route in scope.
The linked experiments are research evidence; none currently admits public
refresh.

## Current execution checkpoint — 2026-10-24

Issue #95 remains open and public Phase 1 remains fail-closed. The full-bound
native experiment now verifies the second K-Elimination carry introduced by
the high lift. Direct scaling of the original `high_delta` supplies the
same-history `e+B` composite view, so the earlier offset-producer gap is
closed for this experiment. The unresolved join is specifically the live
Safe-Basis selector/root producer for `M_pJ*K_lift`, starting from the
encrypted `K_lift mod p` view.

The medium N512 and native N8192 carry-corrected consumer tests pass. Native
results: `max |K_lift|=127` against the derived 8,193 bound; zero mismatches
when recovering `K_lift mod p` through the `A^-1` p-view; 169-bit corrected
residual error; 49-bit carry error; 52-bit Phase 1 error; and exact square
and following product. The correction in those integrated tests is still a
clear test oracle. A separate symbolic weighted-selector projection passes
at `K_lift=+-8,193` and the observed `+-23`, but it does not derive selectors
from the live encrypted carry. Full-T exact multiplication now initializes
at native N=16,384: 9 transient auxiliary lanes provide 283 bits for the
266-bit requirement, and native `CarryRuntime`/root preflight passes. A
separate live N=4 encrypted-trit projection normalizes its `-32` trace scale
modulo `p^2` and emits `M_pJ` with 83-bit measured error; it does not yet
consume `K_lift`.

A medium follow-up now carries the same-history `K_lift mod p` through a
componentwise K-Elimination lift toward `T`. It preserves all p residues but
returns `K_lift+p*J_q`, a second hidden quotient winding; the observed maximum
is 22 at output degree 1,024, below the 513 degree bound. The next
Safe-Basis job is to scale the live correction beyond the small-ring fixture.

An isolated one-root path now computes `J_q` from the same quotient
remainders using nine precharged two-trit words. At N=4, `J_q=1` is recovered;
the modeled/measured error is 66/65 bits, the p-scaled correction bound is 82
bits, and the full-T bound is 112 bits, admitted. At N=8, `J_q=1` is also
recovered and the p² correction is admitted at 130 bits, but the support tree
has 6,549 rows and 6,723 exact selector products. Its 160-bit full-T bound is
refused against a 126-bit radius even though the secret-holder fixture
measures 112-bit error and decrypts exactly. This exposes a real scaling and
budget gap; the measured value does not replace admission. The producer is
still a private research test and is not joined to the medium consumer.

The medium dependent-product test still uses a clear carry correction. Issue
#95 remains open, and this evidence is not a public refresh or production
certificate.

At the remote check for this checkpoint, `main` was `6c6a305`, issue #95 was
open, no CI statuses were attached to that commit, and the only open PR was
#187 on a separate automated issue-resolution branch.

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
| `r_p` | Same-history p-encoded sister-tray residue for K-Elimination | Native consumer test uses `M*=2^16=p-1`; `L=2` scales `99*Z99`, and `K=-(X_p-r_p)`; returned phase is 51 bits at N8192 and survives two products | Produce/authenticate `r_p` through the one-root Safe-Basis 2/11 phase lock; current tray is a client oracle |
| `X_p=X mod p` | High residue of the same integer `X` | Linear from `Z99` in the public chart encoding | Must share the exact source/history binding of `r` or `a` |
| `e99=99*Z99-M*K99` | Centered chart remainder; equivalently `r-M/2` or `a+K99-M/2` | Exact zero sheet derivative; live `Q/16` source-correlated bound is 6849 | Establish a correction consumer and a full error/reset certificate |
| `K_T` / `K_p` | K-Elimination carry left by the high lift, read in the common p tray | Full-bound same-history lift returns `pJ+M_pJ*K_lift`; its p view is `A*K_lift mod p`, and multiplication by `A^-1` recovers every native `K_lift mod p` coefficient. The centered component/ternary-key bound is `|K_lift|<=8,193<p/2`; native observed maximum is 127 | Replace the clear test correction with live selectors/root projection from the encrypted p residue into `Enc_T(M_pJ*K_lift)`, bound its native noise, and bind it to the high-lift history |
| `J_q` | Second quotient winding from componentwise `Enc_p(K_lift)` to `Enc_(p^2)(K_lift+p*J_q)` | Same-remainder one-root correction recovers a nonzero carry at N=4 and N=8; N=8 has 6,549 support rows, 6,723 products, and a refused full-T error bound | Replace ternary-word enumeration with a scalable composite-basis carry projection; join it to the medium/native sibling and bind its history/noise |
| `R_T=x_T-A*K_T` | T-encoded chart residual after K-Elimination correction | Direct same-history offset construction now yields exact `pJ mod M_pJ`; correcting the high lift by clear test-oracle `M_pJ*K_lift` gives zero plaintext mismatches | Make the bounded selector/root correction live; issue a history-bound residual/noise certificate; return to the work key |
| `V_out` | Error after residual correction and return | Full-bound native test: corrected residual error 169 bits, carry/Phase 1 errors 49/52 bits, square and following product exact. The `e+B` offset comes from the original `high_delta`; only `K_lift` correction remains a clear test oracle | Live K selector/root producer, certificate propagation, work-key return, second refresh, and repeat-cycle admission remain open |

## New p-locked winding result

The wide-step experiment now isolates the winding left by the exact centered
`L`-tray quotient. With `p=65,537`, `M=p+1=65,538`, `L=211*p*M`, and
`T=pL`, it builds same-history p and M ciphertext views. A public offset equal
to the residual bound keeps `e+B` nonnegative. In the M view, the difference
between the high residual candidate and the p-view residual is `pJ mod M`;
because `p=-1 mod M`, multiplying by the centered inverse `-1` yields a
ciphertext for `J mod M`. The extraction operations do not use clear `e` or
`J`.

At N=8192/H=96, all 16,384 doubled-ring coefficients pass, with observed
`max |J|=115` inside M's centered radius 32,768. A conservative bound follows
from the quotient construction: each centered component quotient is bounded
by `Q/(2L)+1/2`, and convolution with the ternary output secret adds at most
`n_out` terms. Under `Q>=L*(n_out+1)`, `B<p`, and
`T>2*p*(n_out/2+1)`, the decoded winding satisfies
`|J|<=n_out/2+1=8,193`. Since `p+1=65,538>2*8,193`, the same-history
`J mod (p+1)` view sign-lifts the entire declared range. This bound assumes
the key's ternary domain and the
exact active Q/L/T tuple; those properties are not yet issued as a production
certificate. The same-history sibling
error is 153 bits and the ciphertext-only J output error is 165 bits, both
under the 174-bit `Q/2` limit; the tuple passes the 128-bit parameter screen.
The final Phase 1 correction in this J-only control still uses clear J. The
composite pJ route below avoids that operation for its observed values but
currently uses a test-oracle `Enc_M_pJ(e+B)`. A symbolic Safe-Basis fixture
also projects `pJ` from the p+1 winding tray directly into T at the full bound;
the live ciphertext-to-root binding, native projection certificate, work-key
return, and repeat-refresh admission remain open.

## Composite `pJ` tray result

The winding can be carried and lifted as `pJ` directly, avoiding multiplication
by `p` after lifting `J`. With `A=517=11*47`, `M1=p+1`,
`M_pJ=A*M1=33,883,146`, and `T=p^2*M_pJ=145,531,445,121,188,874`, the tray
radius is 16,941,572. The native N8192/H96 run observes `max |J|=147`, so
`p|J|=9,633,939` fits. The full-bound value
`p*8,193=536,944,641` does not fit; this composite tray is an observed
consumer diagnostic, not the worst-case route.

The earlier same-history `M_pJ` consumer used a test-oracle encoding of the
bounded `e+B`, yielding a 62-bit corrected residual and 116-bit carry/Phase 1
errors. The revised full-bound test forms `e+B` directly from the original
`high_delta`, because `M_pJ` divides the Jacobian step. The remaining oracle
is the second high-lift carry `K_lift`, described below.

This isolates the last producer needed by this route. Direct componentwise
conversion of the existing `p+1` offset view to `M_pJ` is wrong in 16,197 of
16,384 native slots. The one-root symbolic fixture projects offsets 0, 129, and
258 into `M_pJ`, but it is not yet attached to the live Jacobian
source/history. Thus this is a native consumer/product result, not an admitted
public refresh.

The direct-root alternative uses the existing p+1 view: its centered radius
32,768 contains the tighter bound 8,193. A symbolic one-root fixture receives
`J mod (p+1)` and directly projects `pJ` into T at `J=+-16,386`, `+-147`, and
zero; the endpoint test deliberately stresses above the new bound. This avoids
the smaller observed-value tray, but the input winding is still supplied as a
clear support row. The missing producer must bind the live p+1 ciphertext,
Safe-Basis root, output key, and history together and certify the projection
noise.

## Full-bound composite `pJ` tray

The full bound fits a larger tray that retains the 11 anchor:
`A=16,390=2*5*11*149`, `M_pJ=A*(p+1)=1,074,167,820`,
`L=p*M_pJ=70,397,736,419,340`, and
`T=p^2*M_pJ=4,613,656,451,714,285,580`. The radius is 537,083,909; it holds
`p*8,193=536,944,641` plus the native offset span `2B=258`. The three
63-bit NTT-prime chain has 189-bit Q and passes the in-tree 128-bit screen.
At N8192, `max |J|=132`; direct scaling of the original same-history
`high_delta` gives `e+B` at `M_pJ` because `M_pJ` divides the scale step. The
resulting `pJ` residue has zero plaintext mismatches and 69-bit measured
error. The raw K-Elimination lift carries an additional `M_pJ*K_lift` in
16,156 of 16,384 coefficients, with observed `max |K_lift|=127`. Its p view
recovers `A*K_lift`, and `A^-1 mod p` recovers the full encrypted p residue
exactly. Applying the clear test correction produces a 169-bit residual,
49-bit carry and 52-bit Phase 1; the dependent square and following product
decode exactly. The raw `p+1`-to-`M_pJ` conversion remains a negative control
and fails in 16,183 of 16,384 coefficients.

The symbolic linear selector projection covers the full signed bound
`+-8,193`, but its one-hot rows are clear support. The live bridge still needs
to derive those selectors from the encrypted `K_lift mod p` residue and bind
them to the high-lift history. A direct component quotient from p to T keeps
the p residue but adds the second winding `p*J_q`; removing it is the next
isolated gate. Full-T planning and native-degree root initialization now
pass with the widened multiplier and U512 main-only fallback. Work-key
return, second refresh, and admission are subsequent gates.

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

The tropical finite difference supplies a more specific lift target. If
`D_theta=T_Q(S+1)-T_Q(S)=-2K-b`, the 2-view gives `b=D_theta mod 2`, and each
odd composite tray gives `K mod m=-(D_theta+b)/2 mod m`. The new clear
native-corridor check uses the one-root sisters 49, 121 and 25: their period
148225 uniquely lifts every `K` in `[-4096,4096]`. This supports the owner's
arbitrary composite-tray approach without adding a root. It does not produce
`D_theta` from the live encrypted chart or make the CRT result a common-p
ciphertext. The next encrypted gate is that same-history derivative producer,
its 2/11 boundary phase and tray error certificate, followed by a certified
common-p lift and the corrected return.

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

The direct scale-locked quotient diagnostic at `T=pA` reads `K` but retains
its chart residual. The power-of-two sister-tray K-Elimination control gives
a stronger return: with `M*=2^16=p-1`, chart multiplier `L=2` at N8192, and
an oracle-supplied same-key tray, it cancels the chart ciphertext exactly and
returns with 51-bit observed p-view error. Its square and following product
are exact.

### Same-history low tray and adjacent-scale winding

A new producer now builds the `2^16` chart from the live source ciphertext
and same evaluation key. It constructs `x mod 2^16` without a tray oracle.
Since `x=2^16*K+e` and `|e|<2^15`, reading that ciphertext at `p=65537`
returns the correct signed `e`; subtracting `x` recovers `K` exactly. The
integer producer and carry-decode checks pass at N512 and native N8192.

That adjacent-scale read does not give a low-noise `Enc_p(e)`. If `V_t` is
the measured tray error, the p-view phase error obeys

```text
V_p <= (Q*|e| + p*V_t) / 2^16.
```

The `Q*|e|/2^16` term dominates. N512 observed 43-bit tray noise but 121-bit
p-view, carry, and return noise; native N8192 observed 47-bit tray noise and
the same 121-bit p-view, carry, and return noise. Carry decoding is exact,
but the same-history return fails its square and following product. The
p-encoded oracle-tray control returns at 47/51 bits and passes both products.
So cross-modulus decoding closes the integer lift check, not the public
refresh gate.

The RNS component K-Elimination scale converter can divide each component
exactly, but separate component conversion leaves a secret-dependent winding.
The remaining producer must correct that winding through the same source
history and one Safe-Basis root, then pass the carry, return, square, and
next-product checks. Production remains fail-closed.

## Required implementation order

1. Replace the N=4/N=8 ternary-word support enumeration with a bounded,
   phase-locked carry projection using the composite sister trays and
   Jacobian/ultradiscrete structure. The new state/multiplication counts and
   high-T admission must fit before any native integration.
2. Connect the scalable producer to the actual same-history
   `K_lift mod p` sibling, remove the clear correction, and join it to the
   tested same-history consumer. Require
   exact `pJ` recovery, zero `K_lift` correction mismatches, the native
   residual/carry/Phase 1 error bounds, and dependent square plus following
   product. Keep raw p+1-to-composite conversion as a negative control.
3. Bind the batched 99/121 chart and direct `high_delta` offset construction
   to typed source key, history, phase cap, and active RNS level. Preserve the
   scale-difference and offset noise bounds as producer-issued certificates;
   reject caller-supplied phase snapshots.
4. Return the corrected ciphertext to the work key and run the exact refresh
   acceptance ladder, including a second refresh and repeat product, under
   admitted parameters. Add corrupted-root, wrong-history, boundary, both
   sign, all-lane, and odd-zero negatives. Production remains fail-closed
   until these gates and the R00-R03 admission checks pass.

Until all five gates pass, issue #95 remains open and production refresh
remains fail-closed.

Related evidence: [tropical lift and K-Elimination](../2026-10-22/TROPICAL_LIFT_K_ELIMINATION.md),
[paired chart K-Elimination](PAIRED_CHART_K_ELIMINATION.md),
[batched paired chart](BATCHED_PAIRED_LIFT.md),
[three-view chart](TRIPLE_LIFT_DOMAIN.md),
[11-adic section](FROBENIUS_CHART_SECTION.md), and
[scale-locked tray](SCALE_LOCKED_CARRY_TRAY.md).
