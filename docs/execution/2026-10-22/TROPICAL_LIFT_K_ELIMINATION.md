# Tropical covering-space lift through K-elimination

Research construction, 2026-10-22. This investigates the owner's proposed
lift through ultradiscrete/tropical coordinates. It uses CRAM's existing
K-elimination and arbitrary-target projection primitives. It is a clear-state
algebraic bridge; an encrypted implementation remains to be constructed.

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

## Remaining encrypted construction

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

## Reproduction

`cargo test --locked --offline -j1 -p exact_transcendentals --test tropical_theta_k_lift`

Six tests exercise the existing modular/projection primitives, independent
theta minimization, cocycle composition, 2/11 wall events, all 8193 native
sheet indices at seven chart points, arbitrary sister targets, missing-range
aliases, and even-period ties. Source assignments are never enumerated.

`cargo test --locked --offline -j1 -p nine65 --test coefficient_slot_gate encrypted_tropical_lift_consumes_paired_coordinates_without_slot_transforms -- --nocapture`

This is the conditional encrypted consumer and its dependent multiply.
