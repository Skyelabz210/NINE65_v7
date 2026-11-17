# Discovery and return paths from universal query transport

This campaign delivers four new domain investigations, twelve selected compositions, two executable outward applications, and a concrete external import. Its strongest mathematical result is an **actual evolution intertwining** between the finite nearest-neighbor box-ball system (BBS) and a continuous path transform. A second useful result compiles target queries from possibly noninvertible matrix observations over composite residue rings, returning either executable weights or a verifiable ambiguity witness. A third uses Hasse jets to recover quotient evaluations where value-only observations erase them.

These results have written proofs and executable finite checks. They are not new Lean declarations or production FHE integrations. Historical priority is unadjudicated. Known ingredients, derived connections, and implemented models are distinguished below.

## Scope and evidence

The inherited inventory contains 22 innovation families and eight external domain mappings. `discoverygraph.json` preserves the family-specific semantic states, supplied/required capabilities, source paths, and composition guards. It screens all **231 unordered pairs in both directions: 462 directional screens**. Forty-five directions have an explicit matching capability; the rest require an intermediate construction. This rule-based screen is reproducible prioritization, not a proof of 231 discoveries or exhaustive verification of every source file.

The prior `CROSS_INNOVATION_MAP.md` explicitly left the actual BBS evolution bridge open in §9; C05 discharges that written-proof obligation under the stated nearest-neighbor and boundary assumptions. C02 makes its §8 matrix/lattice query proposal executable for composite residue rings. C08 extends the §6 polynomial branch using multiplicity-sensitive observations. These are traceable advances from existing portfolio questions, rather than relabeling previously supplied connections as new work.

The twelve deeper candidates have stable IDs C01–C12 in `candidates.jsonl`. Four are practical returns, four are frontier/generalization investigations, and four are internal compositions. Potential and readiness are separate five-factor 0–5 assessments. They are research judgments tied to each record's assumptions, evidence and blockers, not statistical scores or novelty grades. The four added domains are exact computational geometry, integer-module/linear-congruence constraints, local algebra and jet precision, and integrable-system dynamics. Some were previously mentioned as opportunities; the advance here is a precise construction or tested boundary, not discovery of the domain itself.

For each scoring factor, zero means no supporting route; one means analogy only; two means a specific plausible route with major unspecified obligations; three means a defined mechanism with a material unresolved connection; four means a direct concrete mechanism/attachment with bounded remaining work; five means an explicit decisive route or evidence within the declared model scope. Thus a five for the producer of a clear research model does not mean a production ciphertext producer exists. Potential factors are owner benefit, generalization reach, portfolio return, mechanism distinctiveness, and test information gain. Readiness factors are precise statement, authentic producer, mathematical premises, implementation seam, and decisive experiment. Each candidate links a separate textual reason for each factor.

Primary-source search comprised five queries requesting 25 result slots. There were 25 distinct result URLs, including mirrors of the same work. Six bounded fetches covered five source documents; this is **not** a review of 25 papers. `sources.json` states exactly what was read. In particular, the normal-form paper was checked through its abstract/bibliographic record, while its certificate algebra below is proved independently.

## Universal interface and the cost boundary

For an abelian source group, let an authentic observation be `B(k)` and a target query be `C(k)`. A homomorphism on the observed image computes the query exactly if and only if `ker B ⊆ ker C`. This describes *which query* survives observation. It does not, by itself, produce the observation, prove a range, preserve a source epoch, or bound implementation cost.

For `X=r+MK`, a unit anchor supplies `K mod A = M⁻¹(v_A-r) mod A`; adjacent `A=M+1` reduces this to `(r-v_A) mod A`. The state in our residue models remains the authentic observations. The quotient is read only when a consumer needs it. A one-subtraction readout therefore does not imply constant-time acquisition, arbitrary-width arithmetic, all comparisons, or arbitrary division. Nonlinear observations such as G/H require their own producer and domain proof before this interface applies.

## C02: composite-module queries from verified diagonal certificates

Let `B` be an integer `r×n` observation matrix, `C` an integer target row, and `m>0`. Suppose public integer matrices `U,V` are unimodular and `S=UBV` is diagonal, possibly rectangular. Canonical Smith divisibility is unnecessary for this constructor. Write `x=Vz`, `y=Bx mod m`, and `t=CV`. Then

```text
Uy = Sz mod m,       Cx = tz mod m.
```

For column `j`, put `s_j=S_jj`, or zero for a column beyond the available rows. The target is recoverable exactly when

```text
gcd(s_j,m) divides t_j    for every j.                 (1)
```

**Sufficiency.** Under (1), the scalar congruence `w_j s_j=t_j mod m` has a solution. Its reduced form divides both sides and the modulus by `gcd(s_j,m)` and inverts the remaining unit. Rows beyond the diagonal receive zero weight. Consequently `wS=t mod m`, and runtime weights `D=wU` satisfy `DB=C mod m`. The query is the direct readout `Dy mod m`; no source vector is reconstructed.

**Necessity and a certificate of failure.** If (1) fails at column `j`, let `g=gcd(s_j,m)` and choose `z=(m/g)e_j`. Then `Sz=0 mod m`, whereas `tz=t_j m/g` is nonzero modulo `m`. The vector `x=Vz mod m` is an explicit witness with `Bx=0` and `Cx≠0`. Any decoder would give the same answer on source zero and this source, which is impossible.

For example, use `m=6`, `B=[[2,4],[0,3]]`, `U=I`, and `V=[[1,-2],[0,1]]`. The diagonal is `(2,3)`. The target `C=(2,1)` becomes `(2,-3)` and is recovered by `D=(1,1)`, although neither the matrix nor the full source is invertible. Target `(1,0)` fails and receives a collision witness. Modulus one and rectangular unused coordinates are included in the implementation's test cases.

The imported method is integer normal-form certificates [D02]. The derived contribution is the certificate-to-query/obstruction compiler with a concrete NINE65 public-planning interface. `models.py` verifies dimensions, integer entries, unimodularity, and actual diagonalization. It deliberately supports small dimensions 1–6 and uses cofactor determinants. It does not implement Kannan–Bachem's polynomial-time algorithm or claim scalable preprocessing. The runtime dot product is linear in the number of observed coordinates in modular-operation count; bit costs and source production remain explicit.

## C03: an exact geometry consumer without determinant reconstruction

For three integer points with coordinates in `[-H,H]`, let

```text
D = (b_x-a_x)(c_y-a_y) - (b_y-a_y)(c_x-a_x),
B = 8H².
```

Each product has magnitude at most `4H²`, hence `|D|≤B`. Choose an adjacent frame `A=M+1` with `MA>2B`. The outward application computes the two determinant residues directly from coordinate observations, shifts both by `B`, and obtains the observations of `Y=D+B`. Now `0≤Y≤2B<MA`, so the adjacent readout `k=(Y mod M - Y mod A) mod A` is the exact quotient of `Y` by `M`. Comparing `(k,Y mod M)` lexicographically with the public pair `divmod(B,M)` determines the sign of `D`. It never constructs `D` as a full scalar.

This imports Shewchuk's predicate-oriented exactness principle [D01], while the implementation uses integer residue arithmetic, not his adaptive floating-point code. It is a demonstrator for geometry and a usable bounded-sign consumer specification for Triad/public admission. The clear ingress `observe_point` is explicitly separated from the consumer. The coordinate-bound contract must come from an authentic producer; the consumer cannot infer it from finite observations. A dishonest bound can invalidate the answer. There is no ciphertext implementation or speedup claim.

<a id="bbs"></a>

## C05: actual BBS evolution and a continuous path transform

Let a finite binary configuration be `η_1,…,η_N`, with an empty carrier at the left boundary. Define its height by `H_0=0` and `H_n-H_(n-1)=1-2η_n`. Let `M_n=max_{0≤j≤n}H_j` and `W_n=M_n-H_n`. The ordinary BBS carrier rule is

```text
η'_n = min(1-η_n, W_(n-1)),
W_n  = W_(n-1)+η_n-η'_n.
```

These formulas agree with the path representation in [D04]. To check the identity, there are three cases. A ball lowers `H` by one and raises `W` by one, without increasing `M`. An empty box with positive carrier raises `H` by one, keeps `M` fixed, and lowers `W` by one. An empty box with zero carrier raises `H` and `M` together and keeps `W=0`. The output increments are therefore those of `2M-H`, so

```text
H' = T_Z(H) := 2M-H.                                  (2)
```

Let `E` be piecewise linear interpolation at integer spatial sites, and define the continuous path transform

```text
T_R(f)(t) = 2 max_{0≤s≤t} f(s) - f(t).
```

For these integer nearest-neighbor paths,

```text
max_{0≤s≤t} E(H)(s) = E(M)(t)   for every real t.       (3)
```

On a downward unit segment, the old maximum remains fixed. On an upward unit segment starting below the old maximum, the integer gap is at least one, so the segment never exceeds that maximum before its endpoint. On an upward segment starting at the maximum, both running maximum and interpolated height increase together. These cases exhaust each unit segment, proving (3) at every real coordinate, not just sampled rational points. Linearity of interpolation and (2)–(3) yield the actual evolution intertwining

```text
E(T_Z(H)) = T_R(E(H)).                                (4)
```

This is stronger than constructing a continuous interpolation of a pair of arbitrary snapshots. Both sides of (4) execute their respective evolution rule. Its nearest-neighbor premise is essential: for `H=(0,-1,1)` at `t=5/4`, the left side is `1` and the right side is `1/2`. The running maximum can begin rising partway through a larger upward jump, defeating (3).

Finite-prefix evolution may leave an outgoing carrier. A full finite configuration successor must retain that carrier or append enough empty sites to drain it. The executable checks append `n` empty boxes to each `n`-bit input. The implementation itself stores only two carrier residues under the public bound, updates them by ±1, and tests zero using the pair. It never maintains scalar `W`; the scalar carrier in `run_models.py` is an independent test oracle. The adjacent winding is inspected only on demand.

Equation (4) is a continuous-*space path* theorem with discrete-time evolution. It is not a continuum-time PDE limit, a KdV solution theorem, a statement about arbitrary real paths, or an infinite stochastic construction. Iteration requires applying the same boundary convention at every step; no finite buffer may silently discard its carrier. A Lean development of the interpolation lemma and refinement to the runtime remains an explicit next action.

<a id="jets"></a>

## C08 and C06: local quotient observations and precision lifting

For a polynomial `P`, the Hasse derivative `H_j(P)(a)` is the coefficient of `z^j` in `P(a+z)`. This is the characteristic-independent jet definition used in multiplicity coding [D05]. Suppose

```text
X=r+MK,      M=(t-a)^ν U,      U(a) is a unit.
```

The multiplier's jets below order `ν` vanish and its order-`ν` jet equals `U(a)`. The coefficient product rule therefore gives

```text
H_ν(X)(a)-H_ν(r)(a) = U(a) K(a),
K(a) = U(a)⁻¹ [H_ν(X)(a)-H_ν(r)(a)].                  (5)
```

Value-only observation at `a` annihilates `M` and cannot see `K(a)` when `ν>0`. The first nonzero jet repairs this exact ambiguity. Formula (5) requires only a unit, so the algebra also works over commutative coefficient rings with that unit premise. The executed examples use small prime fields. This is a concrete generalization beyond evaluating the original scalar unit at a point; it changes the observation to one that retains the required information.

Ordinary derivatives cannot replace Hasse derivatives indiscriminately. In characteristic three, `M=t³` has order-three Hasse derivative one at zero, while its ordinary third derivative is `3!=0`. The executable negative control checks that failure. Authentic jet generation and the vanishing/unit certificates are required; charging only (5) and ignoring their production would misstate the cost. This import is useful for polynomial lanes and the higher-order G/H research path, but no encrypted jet producer is claimed.

The companion precision model imports the simple-root Hensel step [D03]. If `f(a)=0 mod p^e` and `f'(a)` is a unit modulo `p`, set

```text
t = -(f(a)/p^e) f'(a)⁻¹ mod p,
a_new = a+p^e t.
```

Taylor's polynomial identity modulo `p^(e+1)` gives `f(a_new)=0`, and the unit derivative makes the correction unique modulo `p`. This isolates the extra information and producer obligation for every precision level; a result modulo `p²` does not automatically establish an encrypted refresh modulo `p³`. Our implementation validates the root and unit premise, and the test oracle checks both the new root and its uniqueness inside the previous class.

## Internal return paths and sharp boundaries

**C10, StarLift and theta.** For `Q>0`, `z=g+QK`, and `|2g|<Q`, completing the square shows that the unique integer minimizer of `Qn²+2nz` is `n=-K`. At `|2g|=Q`, there are two adjacent minima and a tie policy or set-valued answer is necessary. Adjacent residues of `z` and the **centered reference `g`** return `(-K) mod(Q+1)`. Canonical Euclidean remainder and centered-chart reference are not interchangeable. Thus the negative-winding query has a real consumer, but a finite residue does not provide the entire unbounded minimizer without a range certificate. Integer model checks do not manufacture observations of an arbitrary real chart.

**C09, MAA and folded dynamics.** Replacing `k_i` by `2Σ_(j≠i)k_j-k_i` is an integer linear involution preserving `2Σk_i²-(Σk_i)²`. Reduction modulo a common modulus commutes with this map. It provides a concrete invariant operator family for modular orbit queries, rather than a claim that every projection is dynamically closed. A smaller observed subspace still needs an invariant-kernel proof, and machine arithmetic needs the corresponding bounds.

**C11, energy and coordinate bounds.** Exact energy certificates survive a useful repair. The rational rotation `[[3/5,-4/5],[4/5,3/5]]` sends `(1,1)` to `(-1/5,7/5)`: squared Euclidean norm remains two but maximum coordinate magnitude grows from one to `7/5`. Therefore energy neutrality alone does not imply nonincrease of the maximum norm. Use the actual norm conversion, monotonicity or Lyapunov bound in admission. The private corpus contains an earlier overclaim and a later blueprint explicitly leaving continuum regularity open (`drive-nsproof`, `drive-blueprint`). This counterexample narrows the inference while retaining the exact quadratic invariant; it does not dismiss the discrete substrate.

**C12, conserved normalization and aggregation.** Integer largest-remainder apportionment rounds down each ideal allocation and gives the deficit to the largest exact fractional remainders. The output has exactly the requested total and each coordinate differs from its ideal by less than one. It composes with private-feedback aggregate invariants. This is a known allocation method, not a novelty claim. It is a distinct policy from assigning all correction to a maximal output. Encrypted sorting/selection is additional work.

C01 source-bound consumer capabilities, C04 fixed-schedule GCD/rational normalization, and C07 future-query minimal state are explicitly linked to the parallel runtime/formal tracks. Their statuses here are `SPECIFIED`; this directory does not count their workers' pending evidence as executed results. In particular, an arbitrary gate family need not preserve a compressed quantum state family.

## Reproduction and practical order

Run `python run_models.py`, `python -m unittest -v test_models.py`, `python build_registry.py`, and `python verify_discovery.py` from this directory. All discovery models use the Python standard library. `model-evidence.json` records source hashes and these actual finite checks:

| Model | Executed coverage |
|---|---:|
| Composite module queries | 640 certificates; 312 decoders; 328 obstructions; 11,335 source vectors; 4 fixed controls |
| Exact orientation | 15,625 ordered triples: 6,444 positive, 6,444 negative, 2,737 collinear |
| BBS evolution | 2,046 configurations; 36,868 carrier prefixes; 149,518 rational interpolation checks |
| Jet/Hensel | 1,560 jet instances; 48 Hensel steps; characteristic-three derivative counterexample |
| Internal bridges | 2,100 theta charts; 300 walls; 2,500 MAA reflections; 1,240 allocations; one rational norm counterexample |

Finite checks are independent-oracle evidence, not substitutes for the general proofs above. The models have no cryptographic dependency and establish no security reduction or performance result.

`python run_all.py` runs all four commands, binds their outcomes and logs to source hashes, and produces `execution-evidence.json`. Eight additional admission tests exercise invalid normal-form certificates, malformed observations, capacity limits, outgoing carrier retention and local-unit requirements. One deliberate false-bound example confirms that the geometry consumer cannot authenticate a source range from finite residues alone.

The immediate import is C02: make public preprocessing emit a verified query constructor or an explicit obstruction. C03 exercises a bounded sign consumer with a useful external workload. C05 provides a rigorous target for the tropical/continuum formalization, and C08 supplies a new observation family for the polynomial/local-algebra branch. Their common return to NINE65 is a richer set of *on-demand consumer constructors* with explicit authenticity, range and closure obligations. They do not require a permanently maintained scalar winding ledger.

## Source register

| ID | Source and verification scope |
|---|---|
| D01 | Shewchuk (1997), [Adaptive Precision Floating-Point Arithmetic and Fast Robust Geometric Predicates](https://people.eecs.berkeley.edu/~jrs/papers/robustr.pdf). Introduction and predicate definitions retrieved; performance results not adopted. |
| D02 | Kannan and Bachem (1979), [Polynomial Algorithms for Computing the Smith and Hermite Normal Forms of an Integer Matrix](https://doi.org/10.1137/0208040). Publisher abstract/bibliography verified; full algorithm not inspected or implemented. |
| D03 | Conrad, [Hensel's Lemma](https://kconrad.math.uconn.edu/blurbs/gradnumthy/hensel.pdf). Author exposition, Theorem 2.1 and induction read; not claimed as the original historical paper. |
| D04 | Croydon and Sasada (2020), [Discrete integrable systems and Pitman's transformation](https://ar5iv.labs.arxiv.org/html/2007.06206). Path transform and carrier definitions read; scaling-limit theory not audited. |
| D05 | Kopparty (2015), [List-Decoding Multiplicity Codes](https://theoryofcomputing.org/articles/v011a005/v011a005.pdf). Definitions 2.1–2.2 of Hasse derivatives/multiplicity read; coding complexity not adopted. |

Private lineage identifiers `drive-nsproof` and `drive-blueprint` resolve through the corpus registry; `sources.json` carries their file IDs, dates, inspected ranges and the narrow derived use. No private full source text is duplicated here.
