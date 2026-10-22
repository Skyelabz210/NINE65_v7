# Tropical covering-space lift through K-elimination

Research construction, 2026-10-22. This investigates the owner's proposed
lift through ultradiscrete/tropical coordinates. It uses CRAM's existing
K-elimination and arbitrary-target projection primitives. It covers a clear
native-width lift, a conditional encrypted lift consumer, and a bounded local
encrypted chart transition. The native refresh construction remains open.

## The exact correspondence

Inoue–Takenawa define a tropical Jacobian `J(Omega)=R^g/(Z^g Omega)` and a
min-plus theta function on its covering space, with a quasi-periodicity law.
See Section 1.4 and Remark 1.5 in
[the primary paper](https://arxiv.org/html/0902.0448).
Here `Omega` names their period matrix, to avoid confusing it with CRAM's
winding K. Restrict first to a rank-one integer period Q and double theta
to avoid fractions:

```text
T_Q(z) = min_(n in Z) [Q*n^2 + 2*n*z].
z = g + Q*K,  -(Q-1)/2 <= g <= (Q-1)/2, Q odd.
argmin T_Q(z) = -K,
T_Q(z) = -2*K*g - Q*K^2.
```

To verify the minimum, set `n=-K+d`. The objective minus its value at `-K`
is `Q*d^2+2*d*g`, strictly positive for every nonzero integer d. Thus the
bounded BFV nearest quotient `round(S/Q)` is precisely the cell index of
this rank-one tropical theta lift when `z=S`. This supplies a concrete
connection between the tropical covering-space lift and refresh's integer
quotient. It does not identify an arbitrary tropical Toda trajectory with a
BFV circuit.

The sheet correction is a cocycle:

```text
c_Q(g,K) = -2*K*g-Q*K^2
c_Q(g,K+L) = c_Q(g,K) + c_Q(g+Q*K,L).
```

Consequently the lift can be represented by phase-consistent coordinates
and derived on demand. Enumerating all assignments of secret trits is not
required by this algebraic representation.

## How CRAM supplies the lift

Suppose the live coordinates supply the same state's centered chart g and
`r_A = S mod A`. If `gcd(Q,A)=1`, existing CRAM modular primitives give

```text
K mod A = (r_A - (g mod A)) * Q^-1 mod A.
```

With a proved corridor `|K|<=B` and `2B<A`, this residue uniquely identifies
the signed sheet. The native work-Q value
`348959453350711275087786864768188417` is coprime to the intact S8 product
`A=9699690`, which is ample for `B=4096`. Here Q is the quotient period and
the root is its anchor; this does not require an inverse between a root
factor and the entire root product. Once the lift is resolved, every sister
target b receives `g_b + Q_b*K_b mod b` through `project_with_lift`, including
even, composite and shared-factor targets. No inverse modulo b is needed.

For the refresh source `S=R0+R1*s`, centered component residues have magnitude
at most `h=(Q-1)/2`. With ternary secret weight H, each coefficient obeys
`|S|<=(H+1)*h`, so its nearest quotient has
`|K|<=floor((H+2)*h/Q)`. At H=N=8192 this is 4096. The native test covers
the entire rectangular corridor `|K|<=4096, |g|<=h`, a superset of these
actual convolution states.

The native test never forms `S=g+Q*K`, which can exceed i128. It obtains each
coordinate with modular products. The existing general `k_eliminate` also
returns a reconstructed `value`; the native test therefore uses its modular
primitives directly, and cross-checks the general function on smaller cases.

## A specific 2/11 relation at tropical cell boundaries

For integer z and odd Q, define `D=T_Q(z+1)-T_Q(z)`. If `z=g+Q*K` in the
centered chart and `b=1` exactly when `g=(Q-1)/2`, then

```text
D = -2*K-b
b = D mod 2
K mod 11 = -(D+b)*6 mod 11.
```

This gives the owner's 2/11 phase relationship a precise candidate role:
parity identifies the boundary event and the 11 coordinate reads the sheet
residue from the theta difference. Additional root coordinates preserve the
larger sheet corridor. Computing D from an already known K does not generate
an encrypted K; the identity identifies what a tropical state producer would
need to supply. The test includes the wall event, rather than assuming a
derivative remains constant across it.

## Conditional encrypted lift kernel

The new `encrypted_tropical_lift_consumes_paired_coordinates_without_slot_transforms`
test in `crates/nine65/tests/coefficient_slot_gate.rs` consumes encrypted
`S mod A` and `g mod A` under the same BFV key, encoding and plaintext modulus
A. It subtracts these ciphertexts and scales by `Q^-1 mod A`. This returns
an ordinary BFV encryption of `K mod A`. The modular inverse is taken in the
plaintext coordinate ring, and its scalar noise amplification is charged.
Both inputs are supplied by the fixture; the evaluator does not receive a
secret or run a centering oracle.

The toy uses N=8, period Q=31 and composite coordinate A=17^2=289, with full
ciphertext masks and ordinary encryption error. For the input constructor's
ideal-grid error bound V_fresh, the linear lift has
`V_lift <= 2*(Q^-1 mod A)*V_fresh`; the test checks `2*V_lift<Q_ciphertext`.
It checks every output coefficient, an increment crossing a tropical cell
wall, an omitted-chart negative control, and a subsequent ring square against
an independent negacyclic product. The square is a decryption check rather
than a certified repeat-refresh result. This test uses supplied coordinates
in one composite ring; it does not construct the entire encrypted S8 frame.

## Endogenous local chart transition

The follow-up in
`crates/nine65/tests/research/tropical_chart_transition.rs` computes the cell
crossing from ciphertexts, after setup supplies the initial source/chart
pair and encrypted source trits. No fresh chart or crossing is supplied at
the transition. This is a local period-13 chart, distinct from the 119-bit
work-Q chart needed by full refresh.

Let `Q_local=13`, `A=17^2=289`, `h=6`, and
`G(z)=product_(r=-6..6)(z-r)`. For a hidden ternary increment u,

```text
z = g+u, |g|<=6, |u|<=1
C1(z) = G(z)/13! = 40*G(z) mod289
g' = z-13*C1(z), K' = K+C1(z), S' = S+u.
```

G vanishes at every chart interior point, and its values at 7 and -7 are
13! and -13!. Thus C1 supplies the exact signed crossing on [-7,7]. The
encrypted gate uses two coefficient/slot transforms and a balanced product
with four multiplication layers. The linear K-elimination consumer then
checks that the updated source/chart pair yields the same updated winding.

Applying that polynomial again to the noisy updated chart fails in the
deterministic follow-up: its observed ideal-grid error V has 126 bits against
a 119-bit Q. This is an actual decryption failure in the fixed negative
control; no error counter is reset.

Composing two hidden increments before the nonlinear gate succeeds. For
`z=g+u+v`, the widened support is [-8,8] and the exact polynomial is

```text
C2(z) = G(z)*(65-30*z^2) mod289.
```

More generally, with `c=(Q_local!)^-1`, the quadratic coefficients are
`a=-Q_local*c/((Q_local+1)*(Q_local+2))` and
`b=c-a*((Q_local+1)/2)^2`. At the two positive endpoints G is Q_local!
and (Q_local+1)*Q_local!, so the quadratic normalizes both crossings to
one. Oddness supplies the negative crossings. The compiler checks every
required inverse before ciphertext work. Combining the quadratic (already
at depth one) with the linear factors in order of depth keeps the degree-15
circuit at four layers; two sequential degree-13 gates would use eight.

The encrypted test covers all 117 `(g,u,v)` combinations, preserves the
initial encrypted coordinates throughout each trajectory, and checks both
updated source/chart/winding states and 30 subsequent ring squares. The
maximum **observed**, not producer-certified, scaled-error sizes are:

| Output | One increment | Two increments composed |
| --- | ---: | ---: |
| Crossing | 88 bits | 86 bits |
| Centered chart | 92 bits | 90 bits |
| Winding | 88 bits | 86 bits |
| Following ring square | 98 bits | 96 bits |

These use N=8 and the existing four-prime ciphertext modulus (119 bits).
The second column starts from the original chart and both encrypted
increments; it does not feed the first column's noisy chart into another
polynomial. This finite batching does not reset noise for the next batch.

There is also a precise composite-domain limit. Three increments require
support [-9,9]. Inputs -9 and 8 agree modulo17, while their desired carries
are -1 and +1. Every ordinary polynomial over Z/289 preserves congruence
modulo17, so no such polynomial can implement this larger domain in that
single coordinate ring. This is a limitation of this representation, not of
all multi-tray constructions. Arbitrary sister targets remain valid for
projection after a lift; gate evaluation has its own unit/domain conditions.

## Native follow-up checks

The small composite supports primitive 16th roots, which enable the toy's
N=8 transforms. An exact search shows no primitive 16384th root modulo289,
so this dense transform cannot simply run at N=8192. The native plaintext
65537 does have that root geometry, verified with `81^8192=-1 mod65537`.
An implementation at native size needs a compatible encoding or an admitted
coefficient-local construction that does not require these slot roots.

As a conditional budget check, reusing the existing constant-projection
envelope at N=8192, plaintext65537 and the screened five-prime boot tuple
gives a 42-bit projected input allowance. The successive square bounds are
84,126,168 bits against a 137-bit half-Delta, refusing the third layer. The
calculation uses the current hybrid-switch bound, the documented -8 trace
preconditioner, a conservative setup error `3*(2N+1)`, and a maximum chart
coefficient deposit 48. This is a comparison with the existing envelope,
not a new certificate for the dense chart transform or a universal lower
bound. It cannot admit the four-layer local circuit at native size.

## Remaining native encrypted construction

For refresh, `S=R0+R1*s` is a negacyclic secret-dependent sum. The precharged
root path already computes encrypted residues of S. The other coordinate
in the formula, `g mod A` for `g=center_Q(S)`, must be produced or preserved
as authentic encrypted state. Centering S is the cell-selection operation;
calling a clear CRT rank kernel on decrypted residues would skip that work.

The next construction target is therefore a commuting encrypted lift:
the input ciphertext's Q-phase, the root's S coordinates, and the tropical
chart/difference coordinates must represent the same S under a proved
range. A public evaluator must derive the lift from those ciphertexts with
certified encoding/error bounds. The natural variables to track are the
chart coordinate, the sheet residue, and the cell-boundary event, rather
than one selector per possible partial sum. A higher-rank period matrix
would additionally need an exact lattice-coordinate reduction contract;
scalar K-elimination alone does not implement that matrix reduction.

K-elimination resolves this lift when its paired coordinates are available.
The tropical lift interpretation identifies those coordinates and the
branch observable explicitly; it is a constructive research direction for
CRAM. No production refresh gate changes follow from the clear-state tests.

The theta difference gives a compact candidate state: for the native
`|K|<=4096`, `|D|<=8193` and `b` is one bit. Both fit the work plaintext
65537 without one selector per possible secret sum. The remaining research
step is an encrypted state transition that supplies this difference or the
matching centered-chart coordinate through real operation history. The
compact representation alone does not compute that transition.

The local transition above now supplies such a computation on a small
chart. The outstanding work is a native chart/coordinate encoding and error
contract, its connection to actual weighted secret convolutions and the
intact root, and a complete return/repeat path. Local period13 normalization
alone does not compute the quotient by Q_work.

## Reproduction

`cargo test --locked --offline -j1 -p exact_transcendentals --test tropical_theta_k_lift`

Six tests exercise the existing modular/projection primitives, independent
theta minimization, cocycle composition, 2/11 wall events, all 8193 native
sheet indices at seven chart points, arbitrary sister targets, missing-range
aliases, and even-period ties. Source assignments are never enumerated.

`cargo test --locked --offline -j1 -p nine65 --test coefficient_slot_gate encrypted_tropical_lift_consumes_paired_coordinates_without_slot_transforms -- --nocapture`

This is the conditional encrypted consumer and its dependent multiply.

`cargo test --locked --offline -j1 -p nine65 --test coefficient_slot_gate tropical_chart_transition -- --nocapture`

Three follow-up tests check chart units/support, native slot geometry, and
the encrypted one-/two-increment transitions with dependent squares and an
explicit sequential-noise negative control.
