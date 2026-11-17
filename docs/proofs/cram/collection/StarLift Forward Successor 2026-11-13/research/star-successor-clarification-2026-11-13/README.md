# Forward counting, StarLift and a concrete next-star transfer

The user's clarification specifies an oriented, forward-only process: counted
units advance successively, while winding supplies an operational ordering of
that process. This is more specific than unrestricted signed histories. The
reversal controls in the earlier winding investigation do not refute this
admitted model. Its tick coordinate is well-defined without presupposing a
physical number-line ontology. Converting that coordinate into elapsed seconds
still requires a rate or calibration law.

This follow-up inspected and executed the actual remaster source at
`ad0c8380f02b1d0c4f05a3e00726be3bc9680058`. It establishes a concrete
residue-only transfer from the **36/37** star pair to the **72/73** pair, given
one authentic additional reading modulo **584**. The constructive formula was
verified across the entire combined observation period of **194,472** states.
The new statements below have written proofs and executable checks; this
follow-up adds **no new Lean declarations** or physical observations.

## 1. Derive a coordinate from successive transitions

Begin with an oriented cycle having M states, a designated initial state, and
one permitted transition to the next state. Let n be the number of transitions
from that initial state. This is a coordinate derived from the permitted
history. For n >= 0, define

    r_n = n mod M,    K_n = floor(n/M).

Then, with c_n equal to 1 exactly when r_n = M-1,

    r_(n+1) = (r_n + 1) mod M,
    K_(n+1) = K_n + c_n.

Thus the base process advances one unit at a time; the winding advances once
per lap. Its orientation follows from the selected transition law. It does not
follow from the residue set alone. A residue is a state/class; calling it an
irreducible unit does not by itself specify an algebraic atom or prime.

The existing `arrow.js` implements both `stepForward` and `stepBackward` and
explicitly distinguishes orientation from entropy production. Allowing only
the former is a legitimate model restriction. The separate `tray.js` function
`arrowOfTime` checks basis saturation and adjacency; it returns
`depth_unbounded: true` and supplies no dynamics argument. Its `instantiated`
flag is therefore not an independent proof of a physically preferred direction.

Counting one event must also be distinguished from the implementation's
`UNIT_LANE = 1`: the ring Z/1 has one state and carries no event-count information.

## 2. Successor transport is exact, including at wraps

Let A=M+1, M>=2. On the finite reading space Z/M x Z/A use canonical
representatives and define

    F(r,s) = (r,q),    q = (r-s) mod A.

This is a bijection: its inverse is `(r,q) -> (r,(r-q) mod A)`.
If both readings advance by one, then

    F((r+1) mod M, (s+1) mod A)
      = ((r+1) mod M, (q + [r=M-1]) mod A).

Proof: write r'=r+1-cM, s'=s+1-dA, where c and d are their wrap indicators.
Then r'-s' is congruent to r-s-cM, which equals r-s+c modulo A because
M=-1 modulo A. This proves the update formula, independently of any scalar
reconstruction. For authentic same-source readings, q=K mod A by the existing
StarLift theorem.

The source module `cram.js:adjacencyRecover` was checked on every reading pair
for M=2 through 64: **91,518 states**. A separate forward residue producer
executed **5,328 transitions** at M=36; its test-loop count supplied only the
expected-answer oracle and never entered the readout or state update.

| Count n | n mod 36 | n mod 37 | K mod 37 | True K, used only as oracle |
|---:|---:|---:|---:|---:|
| 35 | 35 | 35 | 0 | 0 |
| 36 | 0 | 36 | 1 | 1 |
| 37 | 1 | 0 | 1 | 1 |
| 72 | 0 | 35 | 2 | 2 |
| 1296 | 0 | 1 | 36 | 36 |
| 1331 | 35 | 36 | 36 | 36 |
| 1332 | 0 | 0 | 0 | 37 |

Operand reversal gives (-K) mod 37, so its displayed orientation is reversed
at winding steps. This does not reverse the admitted base process.

The finite reading pair repeats after 36*37=1332 transitions. Continuing
execution is unlimited; exact unbounded history does not fit in this fixed
pair. A wider admissible window, additional authentic readings or additional
history state is needed for queries that distinguish those repetitions. The
table's full K is not being introduced as a permanent runtime register.

## 3. The star family really is in the source

`fixture.js:starNumber` defines S_n=6n(n-1)+1. For n>=2 its shell and anchor are

    M_n = S_n-1,    A_n=S_n=M_n+1.

Consequently every nondegenerate member supports the subtraction readout,
including composite star numbers. The n=1 member has shell zero and is not a
division shell; `starLiftBasis` excludes it.

| n | Star S_n | Shell M_n | Gap to S_(n+1) |
|---:|---:|---:|---:|
| 2 | 13 | 12 | 24 |
| 3 | 37 | 36 | 36 |
| 4 | 73 | 72 | 48 |
| 5 | 121 | 120 | 60 |
| 6 | 181 | 180 | 72 |
| 7 | 253 | 252 | 84 |

Subtracting the polynomial gives S_(n+1)-S_n=12n, and the second difference is
12. These increasing gaps are exact geometric growth. Selecting those
positions in a unit walk produces a sparse observation/event sequence; it does
not change the underlying successor into a jump.

The particular equality between shell and next star gap,

    S_n-1 = S_(n+1)-S_n,

reduces for n>=2 to 6n(n-1)=12n and hence n=3. The 36/37 seed has this special
alignment. It was **already documented** in `tray.js` and its tests; it is not a
new historical or priority discovery. The equality is not shared by every star
pair, although adjacent-anchor recovery is.

`anchor.js:starLiftBasis(3)` returns the three mutually coprime lanes
`[4,9,37]`, with shell 4*9=36. This is a concrete three-lane structure to compare
with the user's phrase "triple Pack." The phrase's intended meaning has not
been definitively identified.

### Tower depth and star index are different coordinates

`fixture.js:windingTower` repeatedly sets T_(d+1)=floor(T_d/M) at a **fixed**
shell. Increasing the star index instead changes the shell itself. A third
operation increases the observation resolution while keeping the query fixed.
These operations can be composed, but they need separately specified inputs.

Each tower level's decoder is local once its own readings exist. The current
`windingTower` demonstrator produces deeper inputs through scalar division of
T; `levelsAreIndependent` recomputes a level from that already available scalar
T. These checks do not establish a residue-only producer of every deeper
observation. At X=1332 the first level returns class 0 and true quotient 37;
its second level is supplied the scalar 37 by the demonstrator.

## 4. A rigorous lift from 36/37 to 72/73

Pose an explicit target: given authentic readings of an unrestricted integer
X modulo 36 and 37, compute its readings modulo 72 and 73. This compares the
next two adjacent pairs in the actual star family; it is a proposed application
of the clarification, not a claim that this is already a manuscript operation.

The source period is P=1332=2^2*3^2*37. The target period is
D=5256=2^3*3^2*73. The old pair alone is insufficient: X=0 and X=1332 have the
same old readings and target readings (0,0) and (36,18), respectively.

For a **single additional authentic reading X mod a**, unrestricted exact
transport exists precisely when

    D divides lcm(P,a).

Proof: all integers with a given compatible observation differ by multiples of
lcm(P,a); the target pair identifies integers modulo D. Constancy on those
fibers is exactly the displayed divisibility. This is the universal
observation/query criterion specialized to the new source and target.

P lacks the required third factor of 2 and the factor 73. Therefore every
sufficient positive a must contain 2^3*73=584. Conversely a=584 supplies both.
Thus 584 is the **least sufficient additional modulus by divisibility**. This
is not a lower bound on all possible encodings or on conditional information
bits; the restriction to one raw X-mod-a channel matters.

The earlier factorization-free anchor saturation construction gives the same
answer:

    a_0 = D/gcd(P,D) = 146,
    a_(j+1) = gcd(D,a_j^2),
    146 -> 292 -> 584 -> 584.

This instantiates the already machine-checked general least-anchor theorem in
`../swarm-campaign-2026-11-13/proofs/mathlib/AnchorSaturation.lean`.
The particular numeral instance was executed here, not added as a new Lean
declaration. Merely using D/gcd(P,D) as the new X-modulus is insufficient:
146 and 292 both leave an ambiguity, witnessed by X=0 and X=97236.

### Direct constructor, with no full X or K

Let r=X mod 36 and t=X mod 584 be canonical, authentic same-source readings.
Their difference is divisible by 4. Define

    e = ((t-r)/4) mod 2,
    u = r + 36e,
    v = t mod 73.

Then u=X mod 72 and v=X mod 73. Indeed write X=r+36k. Since
X-t is a multiple of 584=8*73,

    (t-r)/4 = 9k - 146j == k (mod 2).

Thus u selects exactly the parity of the 36-winding that the 72-reading needs.
It lies in [0,72), and v is correct because 73 divides 584. The next-level
quotient query is then `(u-v) mod 73 = floor(X/72) mod 73`.

The executable constructor in `experiments/star_transport.mjs` takes only r and
t. It checks canonical input types/ranges and the shared-modulus condition;
it does **not** certify their source, frame or epoch. Producer binding remains
a prerequisite for any NINE65 integration. The old 37-reading can be preserved
in the source state, although this target constructor does not need to read it.

Across all old-plus-extra observations, the joint period is
lcm(1332,584)=194472. Its ratio to 1332 is 146: part of the 584-channel overlaps
information already in the old readings. All 194,472 states passed; these cover
**5,256 distinct constructor input pairs**, each repeated over the 37 possible
retained old-lane states. Five signed/256-bit representatives and five
malformed-input refusals were also checked.
This is clear arithmetic research, not an encrypted execution or a timing claim.

The value 584 is also the integer Venus synodic table value in the supplied
corpus. Here it is forced by the chosen algebraic source/target periods. That
coincidence supplies a concrete comparison to investigate; it is not independent
evidence that the manuscript authors used this transport or that its arithmetic
establishes a physical influence. A source/page/operation correspondence would
need to be documented independently of this construction.

## 5. A structural prediction about star prime divisors

Primality is a multiplicative property. The star formula yields an exact
structural filter, while leaving a distinction between star numbers and those
star numbers that are prime. For example, S_5=121=11^2 and S_7=253=11*23;
both remain valid adjacent anchors. All 14,520 source values in the 120/121
window passed the existing adjacent readout.

For any prime p>3,

    p divides S_n  iff  3(2n-1)^2 == 1 (mod p),

because 2S_n=3(2n-1)^2-1. Hence a solution exists iff 3 is a quadratic residue
modulo p. Quadratic reciprocity gives exactly p=1 or 11 modulo 12; in those
cases there are two index classes modulo p. For completeness,
(3/p)=(p/3)(-1)^((p-1)/2), whose four cases modulo 12 give that classification.
Neither 2 nor 3 divides any star number. Therefore primes congruent to 5 or 7
modulo 12 can never be star-number divisors.

| Divisor candidate p | Forbidden star-index classes n mod p |
|---:|---|
| 5 | none |
| 7 | none |
| 11 | 5, 7 |
| 13 | 2, 12 |
| 23 | 7, 17 |
| 37 | 3, 35 |

The actual `starNumber` implementation was evaluated on **76,127 index
classes** for all **168 primes <=997**, agreeing with this prediction.
The universal proof above uses standard quadratic reciprocity; this work
makes no priority claim for the number-theoretic observation.

This gives an index-space sieve: mark the two relevant classes for each
admitted trial prime. Exclude a star number as composite only when the divisor
is proper: n=2 gives S_2=13, which is divisible by 13 and is itself prime.
Complete trial-division certification still requires coverage through the
square root (or a separate primality proof); a fixed small residue basis alone
does not certify arbitrarily large prime candidates.

## 6. What the clarified model unlocks next

* A transition-preserving clock adapter: the commuting successor equation
  specifies exactly how the unit walk and quotient-class readout agree.
* A concrete 36/37 -> 72/73 query constructor: the 584 observation supplies
  precisely the missing resolution, with no full integer reconstruction.
* A star-index sieve: geometry exposes admissible prime-divisor classes before
  expensive divisibility checks, with explicit completeness limits.
* A manuscript test with a defined target: identify a particular operation and
  its input observations, then test whether it performs the specified transfer.
  Matching numerical constants alone is not that test.

The transfer with the extra observation is a many-to-one target query, not an
isomorphism of complete state spaces: 194472 source classes map to 5256 target
classes, losing the independent modulo-37 factor if it is discarded. Preserving
that lane alongside the target readings yields a concrete isomorphism:

    compatible (r36, s37, t584) <-> (u72, v73, s37).

Its inverse is

    r36 = u72 mod 36,
    t584 = v73 + 73*((u72-v73) mod 8),

with s37 retained. The latter is canonical modulo 584 and has the required
readings modulo 8 and 73. The forward formula selects the unique corresponding
72-reading, so both composites are identities. Both sides describe the same
X modulo 194472; therefore the map also commutes with advancing every source
reading by one, and with admitted integer addition/multiplication on the
compatible residue states. This supplies an algebraic operation-preserving
correspondence, beyond a numerical resemblance.

`restoreStarSource` implements that inverse. **194,472 complete-frame
roundtrips** and five malformed inverse-input refusals passed. The roundtrips
share the forward enumeration and are not additional independent source states.
This finite representation isomorphism has no asserted physical interpretation
or historically established manuscript counterpart.

## Reproduction and evidence

From this NINE65 checkout:

    node research/star-successor-clarification-2026-11-13/experiments/verify.mjs

For a standalone copy, set `ASTRO_CORE` to the pinned remaster's
`project/src/core` directory. `evidence/verification.json` records the actual
source commit, hashes of all core JavaScript files, experiment hashes, counts,
trace and failure witnesses. The archived packet includes this addendum, the
interpretation note and the pinned core JavaScript needed to reproduce it;
the full repository snapshot remains in the prior Dresden investigation packet.

The original frozen winding protocol and prior measured evidence remain
unchanged. The new interpretation note records that the user's clarification
has now been received. No repository runtime, security gate, public branch or
original user document was modified by this follow-up.
