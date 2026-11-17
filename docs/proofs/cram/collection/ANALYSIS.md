# K-Elimination: rigorous generalization, prior art, and proof-update audit

Research snapshot: 12 November 2026. Prepared before changing the proof repository.

**Expanded-corpus update:** start with [EXPANDED_ANALYSIS.md](EXPANDED_ANALYSIS.md) for the subsequent 22 attachments and newly traced current division paths. That review adds constructive residue-only divmod/GCD closure, polynomial/ideal generalization, nine freshly compiled abstract Lean theorems, and 52 passing current NINE65 tests including actual encrypted integer division. The source-specific findings below are retained; they are not a claim that the newer division paths are absent.

The defensible conclusion is that K-Elimination admits a broad, precise generalization as **recovery of a hidden quotient or lattice displacement from jointly informative observations**. The bounded coprime integer identity is sound. Its shared-factor and coupled-anchor extensions are sound with a reduced resolution. The NINE65 rank-one tropical-theta experiment realizes a genuine instance of sheet recovery. A later source refinement also proves an exact piecewise-linear continuum embedding of a supplied conservative binary transition, with bounded flux queried through K-Elimination. None of these facts establishes recovery from insufficient information, a unique inverse to tropicalization, or a universal decomposition theorem across all mathematical structures.

The supplied survey should not be adopted as the basis for a proof update without corrections. It misstates sign detection, conflates modular inverse with integer division, mixes quotient resolution with total dynamic range, confuses parallel time with work, and misattributes some prior art. Conversely, calling the entire architecture “just mixed radix” would also be imprecise: an algebraic identity can underlie different representations, schedules, state policies, and encrypted realizations. These must be compared separately.

The recommended foundational theorem is an observability/injectivity theorem, with integer RNS, shared-factor recovery, lattice sheets, and typed transduction as separate specializations. A formal theorem should say exactly what observations suffice and what ambiguities remain.

**Novelty scope clarified after the author's correction:** a shared modular identity, or resemblance to one Garner step, does not establish that Garner anticipated K-Elimination as an architecture or general lifting framework. This audit attributes the proposed K-Elimination/CRAM framework to Anthony Diaz and identifies specific mathematical antecedents without transferring authorship of that framework. Earlier wording gave those shared ingredients too much weight in assessing the complete contribution. No finding here establishes plagiarism or an earlier equivalent of the entire mechanism. Generalization and constructive connections can themselves be contributions; novelty is not restricted to implementation packaging or speed.

## Evidence and scope

The public target was inspected at commit [`0400092096962e3da45a8e5cbb82185a3c2c38fe`](https://github.com/Skyelabz210/k-elimination-lean4/tree/0400092096962e3da45a8e5cbb82185a3c2c38fe). The existing clean NINE65 checkout was inspected at [`88a7bdadbf0e1f8fbfdb2b37e9843101b8db3484`](https://github.com/Skyelabz210/NINE65_v7/tree/88a7bdadbf0e1f8fbfdb2b37e9843101b8db3484). No repository source changes or external publication were made. All 20 supplied files, including the subsequently uploaded tropical report, were inventoried and hashed in [input-manifest.json](evidence/input-manifest.json); PDFs and DOCX files were extracted locally. Review is of the mathematical claims and relevant code, not an independent replication of every experiment claimed in those documents.

Detailed supporting analyses are [corpus mathematics](evidence/corpus-math.md), [proof audit](evidence/proof-audit.md), and [tropical bridge](evidence/tropical-bridge.md). The [proof-update specification](PROOF_UPDATE_SPEC.md) separates necessary theorems and acceptance gates. Local research artifacts are not a new canonical NINE65 implementation contract.

Evidence labels used here: **PROVED** means a written argument with explicit premises; **EXECUTED** means a fresh test or build in this session; **SOURCE OBSERVED** means a document or implementation was read; **OPEN** means the stated evidence does not establish the claim. A finite exhaustive check is exhaustive only over its declared finite domain. A literature search cannot establish that no earlier work exists.

**Follow-up incorporated:** the user supplied the tropical FHE document as `Untitled.docx`, titled *CRAM, NINE65 and Tropical FHE*, dated 25 October 2026. It has now been read in full. The [tropical FHE addendum](TROPICAL_FHE_ADDENDUM.md) records the revised continuum assessment, fresh checks, valuation qualifications and historical/current FHE distinction. The previous report is archived under `history/2026-11-12-before-tropical-paper/`. Wang's external encryption construction remains unavailable beyond the verified talk abstract; that separate gap must not be confused with the now-reviewed user document.

## 1. What the integer theorem actually says

Let M,A be positive integers, X an integer, and use Euclidean remainder:

    X = r + MK,   0 <= r < M,   K = floor(X/M),   s = X mod A.

Then always

    MK = s-r (mod A).

When gcd(M,A)=1, multiplying by the modular inverse gives

    K = (s-r) M^(-1) (mod A).

This congruence is valid for every integer X, including negative values and arbitrarily large values. What is bounded is the conversion from a congruence to one exact integer K. For example, 0 <= X < MA implies 0 <= K < A, so the least nonnegative solution is K itself. More generally, an interval containing at most A consecutive possible K-values determines K uniquely when the observed class intersects that interval. A signed interval [-B,B] is sufficient when 2B < A.

This distinction resolves several recurring arguments in the corpus: outside the window, the identity remains true as a residue identity, but the nonnegative representative need not equal the actual winding.

The proof is three steps: Euclidean division, reduction modulo A, cancellation of a unit. The same equation appears as a scaling step in established RNS algorithms. Hitz–Kaltofen explicitly describe subtracting U mod M from U and multiplying by the inverse of M in the extension base to obtain quotient residues [R3, §IV, “Division by M (Scaling)”]. This establishes an antecedent for that isolated modulus-scaling operation, including the cost of obtaining its remainder input. It does not establish an earlier equivalent of K-Elimination's complete representation, on-demand query method, source bindings, or geometric/encrypted constructions. Those claims require their own comparisons; the common equation alone cannot decide them.

### Noncoprime anchors

Let d=gcd(M,A), m=M/d, and a=A/d. Authentic residues of the same X satisfy d | (s-r). Dividing the congruence by d gives

    K = ((s-r)/d) m^(-1) (mod a).

For a=1 this says only K=0 mod 1, i.e. there is no quotient information. Otherwise m is invertible modulo a. Consequently the quotient resolution is A/d and the total X period is

    M(A/d) = lcm(M,A).

This is a linear-congruence theorem, not an approximate recovery algorithm. If d does not divide s-r, the observations are inconsistent. Coprimality is unnecessary for partial information, but determines whether a single anchor provides its full nominal resolution.

### Coupled-anchor law

For authentic observations modulo A1,...,At of the same X and a canonical r=X mod M, define

    L = lcm(A1,...,At)
    R = L / gcd(M,L).

Two candidate windings K,K' are observationally identical exactly when Ai divides M(K-K') for every i. This is equivalent to L dividing M(K-K'), hence to R dividing K-K'. Therefore:

    quotient resolution = R
    total X period = MR = lcm(M,A1,...,At).

Equivalently R=lcm_i(Ai/gcd(M,Ai)); this follows prime by prime from valuations. Generalized CRT consistency is automatic for authentic observations. Arbitrary supplied observations still need validation.

The attachment's formula R=lcm(anchors)/gcd(M,lcm(anchors)) is correct for **K**. The pasted survey's lcm(M,anchors)/gcd(M,anchors) formula for total capacity is not. For M=6,A=4 there are 12 distinguishable X classes, not 6; the winding resolution is 2.

### Adjacent and unit anchors

For A=M+1, M^(-1)=-1 mod A, so K=r-s mod A. This holds for composite adjacent pairs as well as prime pairs. The exact condition for this subtraction collapse is M=-1 mod A; adjacency is sufficient but not necessary, as M=9,A=5 shows.

The supplied unit-anchor whitepaper uses **unit-inverse anchor** to mean M^(-1)=+1 or -1 mod A. For A>1 these conditions are respectively equivalent to A dividing M-1 or M+1. They give K=s-r or r-s mod A without a modular multiplication. This is a useful implementation specialization; it does not change the information or range requirements.

Separately, M=1 makes K=X and the observation is simply X mod A. An anchor A=1 contributes no information. Neither degenerate modulus should be confused with the whitepaper's unit-inverse terminology.

## 2. Corrections to the Nine-Plus Acts

| Act | Correct mathematical contract | Relevant antecedent and comparison still needed |
|---|---|---|
| 1. Division by a basis modulus m | With r=X mod m available, output q_i=(x_i-r)m^(-1) mod m_i on surviving coprime lanes. These are floor(X/m) mod m_i for every X. A global range bound makes the quotient representation unique. | Classical modulus scaling, explicitly used by Hitz–Kaltofen. A true advantage is the cheap lane-local step when its inputs already exist. No bound q<A is needed merely to obtain q mod A. |
| 2. Magnitude on demand | Derive K mod A, or exact K under a certified uniqueness window. | A two-modulus quotient recovery; historical quotient and quotient-on-demand RNS work must be compared. A>M alone does not imply exact K. |
| 3. Sign | Choose the total representation period P and a signed convention. Let T=ceil(P/2) for the usual centered interpretation. For U in [0,P), U<T iff (floor(U/M),U mod M) is lexicographically below (floor(T/M),T mod M). | Sign is an order query on a chosen representative, not intrinsic to a residue class. The survey's M/2 and A/2 statements are incorrect as written. |
| 4. Comparison | Exact canonical tuples (K,r) compare lexicographically. If K or r is itself only an RNS vector, its ordering still requires an algorithm. | Standard quotient/remainder ordering. No free comparison follows from lane-wise equality tests or modular K alone. Didier et al. explicitly pay for one mixed-radix conversion. |
| 5. Overflow tracking | A persistent scalar-ledger variant has K_add=K1+K2+floor((r1+r2)/M), and K_mul=r1K2+r2K1+MK1K2+floor(r1r2/M). | These identities are valid, but persistent scalar K is superseded by the current on-demand architecture. Rao–Trehan and Gilbert prevent a defensible “no previous quotient/magnitude state” claim. Their exact implementations need comparison. |
| 6. Constant division | Multiplication by c^(-1) gives modular division. It gives the residue of X/c when c divides X and c is a unit in that lane. For floor division, first subtract r_c=X mod c, then multiply by c^(-1). | Standard modular arithmetic. When Y=X/c and r'=Y mod M, the new winding is (Y-r')/M, not Y. Shared-factor lanes require a different contract, not a nonexistent inverse. |
| 7. Lossless transfer | Transfer a uniquely identified admissible state. Target capacity and source observability must suffice. Residues in two coprime codices identify X modulo their product. | Exact base extension already exists without scalar binary reconstruction or MRC in all cases; Shenoy–Kumaresan is an explicit example. Schema/provenance transport may be additional engineering semantics. |
| 8. FPD | Specify exact division versus floor division; identify authentic auxiliary residues, good moduli, bound, reconstruction/projection, and verification. For exact X=bY, inverse residues on good lanes determine Y uniquely if their LCM exceeds the permitted Y interval width. | General RNS division already handles arbitrary nonzero divisors in bounded domains. Hitz–Kaltofen do not assume gcd(Y,M)=1 for the divisor. Specific fused construction remains a comparison question, not established novelty. |
| 9. Anchor tower | Independent observations of the same K give the resolution R above. A recursively represented quotient requires its own recurrence and source bindings. Pairwise floor(X/Mi) mod Mi+1 readings are not nested digits automatically. | Mixed-radix coordinates and recursive RNS are relevant but distinct prior art. Hollmann et al. implement arithmetic recursively on non-bottom layers; that is not identical merely because both use layers. |
| Transduction | Invertible encodings of the same admissible semantic state can be composed; schema changes need explicit commuting diagrams and recovery of metadata. | Identity/composition can be proved under precise encoding hypotheses. A four-field tuple alone is no theorem of invertibility, cryptographic key switching, or O(n) work. |
| Chimera | Each branch must prove the same requested result under a decidable guard; a dispatcher must cover the requested domain. Multiple algorithms may be valid simultaneously. | Algorithm overlap does not obstruct deterministic dispatch. “Different kernels” does not establish disjoint validity domains. Single-cycle execution needs a hardware/circuit model. |
| Operational completeness | Prove closure for a declared language and representation, including failed divisions, growth, source integrity, and bounded queries. | Finite-range modular closure is easy; exact unbounded integer computation needs growing state. RNS difficulty historically means cost/architecture obstacles, not a theorem that division or universal computation was impossible. |

Concrete sign counterexamples: M=10,A=11,X=9 gives K=0<A/2 but X is above M/2. Even interpreting the intended split as MA/2 does not fix the rule: M=4,A=5,X=11 gives K=2<2.5 while X>10. The remainder matters when the midpoint crosses the interior of a quotient block; with an odd anchor there need not be a case K=A/2 at all.

Concrete inverse counterexample: modulo 5, 3/2 interpreted as 3·2^(-1) gives 4, whereas floor(3/2)=1. The latter requires the remainder 1: (3-1)·2^(-1)=1 mod 5.

The Act 1 worked example is correct: basis {7,11,13}, X=500, divide by 7, remainder 3, quotient residues (8 mod 11,6 mod 13), representing 71 in the surviving range. This valid example should be preserved.

### FPD implementation evidence

The following findings concern these particular helpers at the inspected snapshot. The later [runtime review](expanded-corpus/reviews/runtime.md) also traces `RankResidueDivider::divide_floor`, the live exact BFV scaling route and the actual encrypted `divide_integer` API at the same commit. Those support general quotient/remainder contracts, with distinct clear-residue and encrypted-word inputs; the limitations of the helpers below must not be generalized to all division APIs.

* `exact_transcendentals/src/k_elim.rs::fpd` accepts a scalar `a_int`, computes `a_int/b`, and performs an auxiliary consistency check. It is a scalar reference, not evidence of an entirely residue-native producer.
* `cram_ct.rs::fpd_one_coefficient` computes quotient residues in good/auxiliary lanes, performs a weighted CRT fusion, centers the candidate, and checks bad lanes and a bound. The wrapper restricts the divisor relative to the squarefree S8 product and requires sufficient auxiliary resolution. This is meaningful bounded exact-division code; it does not establish arbitrary floor division.
* `nine65/src/arithmetic/kelim_residue_divider.rs` implements the coupled resolution calculation and scalar reconstruction internally; its documentation acknowledges the conflict with a stricter no-reconstruction trait contract.

For a clean proof of the good/auxiliary-lane method, assume X=bY, |Y|<=B, good moduli ni with gcd(b,ni)=1, and L=lcm(ni)>2B. Every good lane determines Y mod ni; if two candidates in [-B,B] agree, L divides their difference, whose absolute value is less than L, so they are equal. This does not require b to be coprime to every main lane. It does require authentic auxiliary observations of X. Producing those observations after information has already been discarded is a separate problem.

An `error_bound=gcd(P,M)` field is not a numerical-error theorem on its own. The gcd measures lost congruence resolution in a particular equation; absolute error between integer representatives can be unbounded without a range. The certificate needs a stated proposition and a verifier.

## 3. The strongest general theorem

At the level of arbitrary sets, let U be a state space, O:U→D the available observation, and F:U→T the exact answer requested. There exists a decoder d:O(U)→T satisfying F=d∘O **if and only if**

    O(x)=O(y) implies F(x)=F(y), for every x,y in U.

Necessity follows by applying d to the equal observations. For sufficiency, define d(o)=F(x) for any x with O(x)=o; the condition makes this well-defined and unique on O(U). This standard factorization-through-fibers theorem requires no ring, order, or factorization assumptions. It describes the broadest exact-recovery principle here, without establishing novelty or computational efficiency. For full-state recovery F=id, it reduces to injectivity of O. A particular query can be recoverable even when the full state is not.

The additive version supplies an explicit kernel test and connects directly to K-Elimination:

Let G be an abelian group, Λ a subgroup, π:G→G/Λ the quotient map, and σ a chosen representative function with π(σ(c))=c. For x in G, let

    r = σ(π(x)),       ℓ = x-r ∈ Λ.

Let h:G→H be an observer homomorphism. Knowing π(x) and h(x) yields

    h(ℓ) = h(x)-h(r).

If admissible lifts lie in S⊂Λ, they are uniquely recoverable exactly when

    (S-S) ∩ ker(h) ⊆ {0}.

**Proof.** Two lifts ℓ1,ℓ2 give the same observation iff h(ℓ1-ℓ2)=0. Thus a collision is precisely a nonzero element of (S-S)∩ker(h). This proves both necessity and sufficiency. For nonempty S, the displayed inclusion is equivalently equality with {0}; the inclusion also handles the empty admissible set. Existence additionally requires that the observed value belong to h(S); authentic inputs provide it. A recovery *algorithm* additionally requires an effective representation and inversion procedure. The theorem does not assert that this inverse is cheap.

For G=Z, Λ=MZ, σ the Euclidean representative, and h reduction modulo A, write ℓ=MK. The observer restricted to the lift is K↦MK mod A. Its kernel in K-coordinates is (A/gcd(M,A))Z, producing the exact integer law above. Combining observers takes an intersection of kernels, producing the coupled-anchor law.

For a lattice Λ=BZ^d in R^d or Q^d, write x=r+Bk. Additional congruences can identify k if the induced matrix observation map is injective over the admissible k-set. A square matrix invertible modulo A is sufficient for recovery modulo A; invertibility of its real determinant alone is not sufficient modulo A. In a general system, Smith normal form and kernel/quotient structure replace one scalar gcd. A real chart coordinate r must still be supplied or represented; finite residues do not encode an arbitrary real number exactly.

This formulation explains why the same pattern can occur in arithmetic, phase unwrapping, encoders, lattice-period ambiguities, and tropical coverings. The common structure is a hidden displacement and an observer that distinguishes candidates. It does not depend on unique prime factorization, and it is not equivalent to a claim that every object in mathematics factors uniquely.

### Tree coordinates: a useful additional theorem

On a rooted tree of modulus lanes, with each edge (i,j) satisfying gcd(mi,mj)=1, retain the root residue and define

    k_ij = (r_j-r_i) mi^(-1) mod mj.

Recover children recursively by r_j=(r_i+mi k_ij) mod mj. Thus root plus edge readings is a bijective coordinate transformation of the residue tuple. This makes a valid statement about pairwise winding observations without pretending they are nested exact quotients. If all lanes observe one integer, the total capacity remains their LCM. A coordinate change does not add information.

A bijection from a uniform finite product space to another full product space preserves the uniform distribution. Algorithmic dependency is different from statistical dependence: standard mixed-radix digits of a uniformly distributed X on the full CRT range are also independent uniform digits. A serial calculation alone does not refute IID. Any CRAM IID claim needs its actual random process and domain, not just a graph of computational dependencies.

## 4. Tropical systems and the continuum claim

The local experiment uses the rank-one tropical theta function

    T_Q(z) = min over n∈Z of (Q n² + 2 n z),       Q>0.

Write z=g+QK with |g|<Q/2 and K an integer. Substitute j=n+K:

    Qn²+2nz = Qj²+2jg - QK² - 2Kg.

For j≠0, Qj²+2jg >= |j|(Q|j|-2|g|)>0. Therefore j=0 is the unique minimizer, so

    argmin n = -K,
    T_Q(g+QK) = -QK²-2Kg.

For the modular specialization, take positive integral Q and A with gcd(Q,A)=1. With an authentic chart coordinate g, an observation of z modulo A, and a suitable signed K bound, K-Elimination identifies the sheet and therefore the minimizing index. The analytic identity itself allows real g and positive real Q. At g=±Q/2, minimizers can tie; a boundary convention or set-valued statement is necessary. The repository also studies theta differences and a carry cocycle; see the companion report for the precise finite test coverage.

This is a genuine bridge to a covering-space coordinate of a tropical theta function. Higher-rank quasi-periodicity has established theory: Inoue–Takenawa [R11] work with the tropical Jacobian and ultradiscrete periodic Toda. Inoue–Kuniba–Takagi [R10] distinguish real-valued tropical evolution from integer-valued ultradiscrete evolution. Tokihiro–Nagai–Satsuma already studied inverse ultradiscretization of BBS in 1999 [R12]. These are required comparisons, not reasons to dismiss a specific new observer implementation.

The newly supplied October 25 report explicitly identifies this construction and leaves a general Toda-trajectory/BFV correspondence open. Independent fresh enumeration reproduced its advertised 77,760 theta cases, plus the discrete difference and signed-anchor recovery on that domain. The analytic wall is g=Q/2; the report's g=(Q-1)/2 is the last integer chart point before a crossing, not the real wall.

The follow-up also located a second positive theorem in the repository's October 31 `PUBLIC_REFRESH_LIFT_REFINEMENT.md`, §4. Given two finite binary configurations b,b' with equal total mass B and a fixed zero left-boundary flux, set

    U_i=sum_(j<i)b_j,       V_i=sum_(j<i)b'_j,
    C_i=U_i-V_i,           H_i=i-2U_i,       H_new_i=i-2V_i.

Then H_new_i=H_i+2C_i, |C_i|<=B, and b'_i-b_i=C_i-C_(i+1). Linear interpolation gives the same height identity for every real coordinate between grid vertices. This is an exact continuous spatial embedding. With coprime M,A and 2B<MA, authentic prefix views yield the residues of Y_i=C_i+B; K-Elimination then recovers the bounded flux or projects it to a target modulus. The current oracle retains both snapshots. It does not choose b' from b or produce encrypted prefix views. A periodic boundary needs a reference flux, and identifying this C with an FHE correction needs a source theorem. All nine existing refinement tests passed, including every one of 924 six-cell conservative pairs and 16,632 rational interior checks. The [addendum](TROPICAL_FHE_ADDENDUM.md) gives the complete derivation and scope.

The following claims must therefore be distinguished:

1. **Lift a torus point to a covering space.** Valid once the chart representative and sheet are determined. The rank-one proof above establishes this instance.
2. **Embed a supplied conservative transition into continuous spatial height functions.** Established by the prefix-flux construction above, with the stated source, capacity and boundary premises.
3. **Construct a continuous or positive-variable dynamical system whose tropicalization has a given BBS behavior.** Possible for specified integrable families, but requires an evolution map and dynamical compatibility proof beyond the supplied-transition embedding.
4. **Uniquely recover the pre-tropical system, or prove convergence to a continuum PDE.** Not established. For example exp(-u/ε) and 2exp(-u/ε) have the same tropical limit u. The limiting map discards the prefactor. A PDE limit additionally requires scaling, topology, stability/compactness, consistency, and a convergence theorem.

The profinite inverse limit of compatible finite residue systems is another distinct construction. It is totally disconnected, whereas R is connected. Hence the natural profinite completion is not the real continuum with its ordinary topology. A bridge may add an Archimedean component, rational approximation with certified error, or additional analytic structure. Such a bridge has to be specified; arbitrarily many finite residue views do not prove it automatically.

The new report's valuation laws are valid, but cancellation prevents replacing v_p(x+y)>=min(v_p(x),v_p(y)) by unconditional equality. Also p and p² have identical mod-p residues and different valuations. Thus a lane supplies limited p-adic information, not automatically a full valuation or exact tropical simulation of arbitrary additions. The existing G/H prime-power lift retains additional leading-residue information and has its own source-bound identity. The addendum also records a now-available general Holte reversibility proof, the integer-weight condition for ordinary tropical-rational ReLU networks [R18], and the distinction between linear product work and logarithmic product depth in the local chart gate.

## 5. Information, transduction, and growth

A fixed finite residue observation has a finite period. X and X+lcm(all observed moduli) are indistinguishable. No stateless deterministic query can give different exact answers on identical input states. This is a restriction on available information, not on whether K is temporarily derived or persistently stored.

For example, X=0 and X=30 have identical residues modulo 6 and 5, but different residues modulo 7. A new mod-7 coordinate cannot be inferred correctly for both from that old pair after aliasing. Adaptive expansion must happen while the old state is still injective on the admitted domain, or draw on an authentic external observer, retained history, or another information source. It cannot create the missing distinction.

Recursive residue encodings can support any *finite* required precision by growing state. Fixed small moduli can be reused in multiple levels, but the levels themselves must carry new distinguishable state. “Unbounded with fixed anchors” is meaningful only if some other state or level count grows. It is false for a fixed-size snapshot.

For typed transduction, let e_A:S→E_A and e_B:S→E_B be bijections onto valid representations of the same semantic state space S. Then

    T_AB = e_B ∘ e_A^(-1)
    T_BC ∘ T_AB = T_AC
    T_BA ∘ T_AB = id.

This supplies a groupoid of presentations. To carry operator semantics, require T_AB∘F_A=F_B∘T_AB. To carry metadata, include that metadata in S and show the map preserves/reconstructs it. Independently reversible lane maps can describe a reversible product-state computation without corresponding to one ordinary integer arithmetic operator. Both interpretations are legitimate; the theorem must identify which applies. This abstract proof prescribes neither scalar reconstruction nor a fast residue-native algorithm.

No lossless bijection exists between two unrestricted finite state spaces of different cardinalities. Restricted valid subsets, extra state, or growing representations can restore the required correspondence. A pair of coprime codices alone is also not an error-detecting code over its whole product range: every residue pair denotes a valid class. Detection requires redundancy, a narrower permitted domain, or independently checked source bindings.

Rational arithmetic is another valid specialization when numerator and nonzero denominator are explicitly represented with adequate bounds. Modular inversion alone cannot select a unique rational from all Q: modulo 5, both 1/2 and 3/1 map to 3. Bounded rational reconstruction or numerator/denominator state is needed; reduction to lowest terms and growth costs remain operations to account for.

## 6. Literature findings and novelty assessment

| Source | Verified result relevant to this audit | What it does not establish |
|---|---|---|
| Garner, 1959 [R1] | Historical reference for residue arithmetic, mixed-radix conversion and the magnitude/division problem. | A similar quotient-digit step does not establish the same state model, on-demand observer mechanism, general lifting construction, or architectural priority. |
| Szabó–Tanaka, 1967 [R2] | Foundational RNS text; general division algorithms are explicitly cited and discussed by Hitz–Kaltofen. | The full book was not acquired here; the survey's blanket coprimality attribution is not established by it. |
| Rao–Trehan, 1970 [R4] | Abstract explicitly states a magnitude index is maintained for all arithmetic operations and gives sign/overflow algorithms. | Abstract-level evidence does not prove their index and CRAM's exact proposed state are identical. |
| Shenoy–Kumaresan, 1989 [R5] | Redundant-modulus CRT base extension without traditional MRC; logarithmic table-lookup latency under their hardware model. | Does not establish unrestricted O(n) total work for arbitrary target bases. |
| Gilbert, 1991 [R6] | Thesis abstract explicitly names RNS-Q and RNS-QD, “quotient-on-demand.” | Full thesis algorithm comparison remains open; terminology alone is insufficient to assert identity. |
| Hitz–Kaltofen, 1995 [R3] | General integer quotient/remainder for 0<=X<M, 1<=Y<M; doubled RNS range; Newton reciprocal; explicit scaling formula. Text explicitly says no other X,Y restrictions. | It is not an O(1) primitive: conversions/comparison have stated processor and depth costs. |
| Bajard–Didier–Kornerup, 2001 [R7] | Full RNS Montgomery arithmetic; base conversions O(n) time on O(n) processors. | This is not “Bajard–Imbert 2001” nor O(n) total-work evidence. |
| Bajard–Imbert, 2004 [R8] | Full RNS RSA; message stays in RNS. Gives approximately quadratic base-extension multiplication counts. | Full RNS RSA is not general operational completeness or FHE. |
| Hollmann et al., 2018 [R9] | Recursive RNS arithmetic on non-bottom layers, ultimately executed with small bottom moduli. | It is not necessarily the same recurrence as a winding tower; a separate 2026 version was not verified. |
| Didier et al., 2025 / arXiv 2026 [R13] | Full-range comparison with one redundant modulus and one mixed-radix conversion, O(n²) stated work; parallel time is a separate quantity. | Does not imply a scalar-r/known-K comparator has identical input costs. |
| Inoue–Kuniba–Takagi; Inoue–Takenawa; Tokihiro et al. [R10–R12] | Established BBS/Toda/tropical Jacobian, quasi-periodicity and inverse-ultradiscretization connections. | They do not prove the user's specific unpublished FHE construction or its cost/security. |

Novelty must be assessed at the level of the contribution actually asserted. A new generalization can contain a classical special case. A new algorithm can use classical algebra. A constructive connection between two settings can contribute something that neither antecedent states. These possibilities do not require an asymptotic speedup, and they should not be reduced in advance to “integration” or “workflow.”

The comparisons in this audit have four distinct scopes:

| Claim being assessed | What the reviewed evidence establishes | What remains to compare |
|---|---|---|
| Isolated modular quotient identity | The arithmetic relation and modulus-scaling operation have classical antecedents. | This finding is limited to that relation/operation. |
| Representation and execution method | CRAM's intended contract uses authentic phase-related views and derives K on demand, with no persistent scalar winding ledger. Some inspected paths satisfy narrower contracts or remain reference implementations. | Match available inputs, stored state, producer dependencies, requested outputs, reconstruction boundaries and scheduling before equating algorithms. |
| Generalization and constructive bridges | The reviewed mathematics supports shared-factor/coupled recovery, tropical sheet recovery, conservative spatial embedding and polynomial digit lifting under their stated premises. | Determine which earlier source, if any, supplies the same generality and constructive correspondence. Finding CRT, theta quasi-periodicity or Taylor expansion separately does not establish an earlier complete construction. |
| Encrypted realization and resource claims | There are existing conditional Lean arithmetic proofs and scoped NINE65 encrypted research results. | Compare the actual encrypted producer/consumer, encoding, parameter and security models, noise behavior and total costs. Shared plaintext algebra does not equate cryptosystems. |

The reviewed evidence does **not** establish that the complete K-Elimination framework was already disclosed by Garner or another cited author. It also does not certify historical priority for every component. A definitive assertion either way needs a claim-by-claim match to earlier sources. Abstract-only references to “magnitude index” or “quotient-on-demand” are leads for that comparison, not proof of architectural identity. The standard observer/injectivity abstraction in §3 is a useful specification of the scope; it must not be substituted for an analysis of the concrete mechanisms that realize it.

A contribution statement consistent with the evidence is: **Anthony Diaz's K-Elimination framework develops on-demand recovery of quotient and lift observables from authentic complementary representations, with explicit capacity conditions and constructive arithmetic, tropical/geometric and encrypted-arithmetic specializations.** The individual statements should then identify established mathematical ingredients, the precise new construction claimed, and its proof or execution evidence. This formulation neither attributes the whole framework to Garner nor declares every ingredient new.

### Correct complexity accounting

If r=X mod M and s=X mod A are already canonical words, M^(-1) mod A is precomputed, and arithmetic fits the word width, one K query needs a fixed number of word operations. This is a valid O(1) **query** model. If r is only represented in n small lanes, obtaining r mod A can itself be base extension. An anchor observation of X is not generally an observation of r, since r differs by MK.

Similarly, n surviving lanes give O(n) modular work for scaling, with constant arithmetic depth under independent processors and free broadcast; realistic fanout, reductions, memories, and wiring can change depth. An O(log n) hardware tree and O(n) processor array must not be described interchangeably. If moduli or K grow with the input, integer multiplication/reduction cost grows with bit width. The input/output size alone precludes uniformly constant bit complexity for arbitrarily long exact values.

The 2004 full-RNS paper explicitly counts k²+2k modular multiplications for one base extension and k²+3k+1 for the other before special-modulus optimizations. These are direct counterevidence to the survey's generic O(n)-work base-conversion claim. They do not prove every possible conversion needs quadratic work; faster algorithms and different input representations must be evaluated on their own terms.

The Lean functions named `k_elimination_complexity` and `mrc_complexity` merely define k+l and k*k. Proving k<k*k for k>1 verifies the arithmetic of those definitions, not that a real implementation has either cost.

## 7. FHE and the supplied implementations

A plaintext modular identity does not directly turn into a two-level encrypted circuit. One must specify how authentic same-source residue coordinates of a secret-dependent lift are computed, what arithmetic the ciphertext supports, how modular reduction/centering/comparison are evaluated, the scale and noise bounds, and the key setup. Coefficient RNS arithmetic is not automatically homomorphic plaintext division.

The February bootstrap whitepaper, attachment 8, has a direct correctness inconsistency. Its algorithm rounds V/q, but its proof later appeals to rounding V/Δ for Δ=floor(q/t). For a noiseless q=100,t=5,m=2,V=40, round(V/q)=0 and the intended plaintext is 2. Exact modular recovery cannot repair an incorrect decoding formula. A standard BFV formulation uses round((t/q)[c0+c1s]_q) mod t with its chosen centering and correctness conditions; round(V/Δ) is not an interchangeable formula in every parameter regime.

The supplied Python file 13 repeats the missing-scale problem, reconstructs scalar integers, uses the plaintext secret key, computes a quotient directly from the scalar input, and calls a list of three descriptions a depth measurement. Its “infinite-depth” test sets an assumed growth factor and bootstrap cost; it is not an encrypted circuit execution. The observed decryption failure is therefore a failure of this historical model, not a counterexample to the bounded K identity.

There is also an odd-q rounding bug: the condition remainder>=q//2 rounds 2/5 upward, although 2/5<1/2. Correct nearest half-up rounding uses 2*remainder>=q. Python's ties-to-even round is a different convention, so a half-tie disagreement alone does not disprove an explicitly half-up algorithm. For negative values, the Euclidean quotient and tie convention must be specified consistently. Product(RNS)>=q alone also does not guarantee reconstruction of an arbitrary input V outside that product range.

“First exact bootstrapping; all earlier schemes approximate” is false. BFV/BGV and Boolean FHE can recover exact discrete plaintexts under correctness conditions. Arithmetic approximation error, cryptographic noise, and decryption-failure probability are different concepts. Fan–Vercauteren [R14] gives bitwise rounding and explicit depth bounds; TFHE [R15] supplies bootstrapped Boolean gates and lookup-table evaluation. Neither supports the survey/whitepaper's universal degree-50 polynomial baseline.

The current NINE65 status file dated 4 November 2026 explicitly describes a separate `PublicRefreshCircuit` research backend with archived encrypted executions, while legacy/default entry points remain gated. That is newer evidence than the Python examples. This session did not rerun the expensive native FHE sequence or perform a whole-system confidentiality audit. The inspected status distinguishes functional observations, deterministic bounds, related-key confidentiality, timing, and production admission; those distinctions remain in force. No historical toy failure here invalidates a later scoped implementation result.

The tropical-document follow-up also freshly compiled the five existing NINE65 standard-library Lean arithmetic modules and passed their transitive axiom audit. In particular, `PublicRefreshDigit` proves the polynomial G/H quotient identity for arbitrary integer coefficient lists and all signed K under explicit root/unit certificates; `PublicRefreshNativeLift` proves the producer bound and adjacent-query arithmetic. This is substantive formal arithmetic evidence to reuse. It does not verify Rust refinement or ciphertext security, and it is separate from the public target repository's failed root build. Logs, exact premises and hashes are in the [addendum](TROPICAL_FHE_ADDENDUM.md).

The supplied Rust crate has useful correct bounded functionality. All 10 original tests passed, and the encoder passed all 1,260 states. Its type is i128, however, not unbounded integer arithmetic. An additional reproducible negative control uses M=2,A=2^126+1,X=2^127-2: all input quantities fit i128, but the internal modular product overflows in debug and returns a wrong value under release wrapping. A safe implementation needs a wider/checked modular multiply or an explicit supported-width bound.

The comparison helper in that crate reconstructs `delta=v_m+k*m` and requires both operands in the lower half-window. Its passing tests do not establish full-range comparison or strict no-scalar-intermediate conformance. A test named “independent coordinates” checks numerical coordinate equality, not a probabilistic IID law.

Attachment 14 explicitly reports a historical Garner/U256 implementation. That history must not be treated as current compliance with the on-demand/no-Garner architecture. Attachment 15's inference from parallel computation to zero power leakage is invalid without a leakage model: a branch-free multiplication by a public constant can leak a secret-dependent operand. Its fault-detection claim also needs genuine redundancy; CRT consistency against a number reconstructed from the corrupted full-range tuple detects nothing. These are scope errors in that compendium, not a new security assessment of all NINE65 modes.

## 8. Physical, image, and universal-factorization claims

The encoder demonstration is a clean cross-domain arithmetic application: two exact periodic observations recover position in a 1,260-state supercycle. It does not yet cover physical sensor error, calibration, gear ratios, or timing misalignment. Robust CRT and phase-unwrapping literature explicitly studies those conditions [R16].

The luminance report, attachment 6, computes L=floor((R+G+B)/3), then divides L by 37. This partitions already observed luminance into bins. It does not recover hidden pigment layers from independent modular observations. Red (255,0,0) and blue (0,0,255) both produce L=85 and bin 2. Therefore luminance-bin identity cannot by itself identify pigment, prove a blank page was never erased, or establish codicological intent. The images, calibration, and independent material evidence would need separate study. This conclusion leaves the user's reported discovery provenance intact while separating it from mathematical and historical verification.

“Universal decomposition” covers many inequivalent statements: unique factorization of elements, CRT decomposition of quotient rings by comaximal ideals, direct-sum decompositions, coordinate expansions, and reconstructibility from observations. K recovery is not contingent on Z being a UFD. It extends to suitable groups/modules even where prime factorization is not the right language. Conversely, tropical addition lacks additive cancellation, noncommutative settings require sided hypotheses, and general modules need not split canonically. The valid unification is the observer-kernel theorem; automatic universal factorization is not its consequence.

## 9. Fresh execution results

| Check | Result | Scope |
|---|---|---|
| Original supplied Rust suite | 10 passed, none ignored | Fixed exact-arithmetic cases and supplied deterministic samples |
| Encoder demonstration | 1,260/1,260 positions recovered | Exact 35/36 residue sensors |
| Independent generalized congruence | 1,183,744 cases passed | M=1..32,A=2..33, X=-2MA..2MA; includes shared factors and negatives |
| Bounded generalized recovery | 217,748 cases passed | Valid nonnegative LCM windows within the preceding enumeration |
| Coupled-anchor identity/injectivity/alias | 1,728 triples each passed | M,A1,A2=1..12 |
| Exact threshold comparison | 35,107 cases passed | Multiple even/odd periods and threshold boundaries |
| Basis-lane scaling | 9,606 lane checks passed | Three small bases, all inputs in their product windows |
| Auxiliary exact division | 820 cases passed | b=1..20, signed Y=-20..20, adequate good-lane capacity |
| Additional independent corpus model | 732,328 checks passed | Signed/shared-factor resolution, coupled capacity, unit anchors, bounded squarefree FPD, subgroup separation and tree coordinates |
| Matrix and tropical generalization model | 49 unit-observer states, 16 fused-observer states, 441 rank-two theta cases passed | Exact rational arithmetic; explicit wall ties and finite-observer aliases also checked |
| Added Rust negative controls | 3 passed in debug and 3 in release | Expected alias/window failure and actual intermediate overflow |
| Supplied Python bootstrap model | 7/8 rounding cases; decryption test fails | Tie-policy mismatch plus separate scaling/model problems; not FHE |
| Supplied edge script | Reports 12 failures | Mixture of rounding errors, intentionally rejected parameter choices, and wrong decryption scaling; not 12 failures of the theorem |
| NINE65 tropical theta target | 7 passed, none ignored | Real existing test target at pinned snapshot; clear arithmetic and specified samples |
| Target Lean build | Fails at import ordering | Pinned toolchain; latest source is not freshly build-verified |
| Basic.lean direct compile | Fails two proof steps | Separate file not imported by the main root |
| Patched Basic.lean in scratch copy | Passed | Minimal patch supplied; full repaired root and axiom audit remain unverified |
| Follow-up theta report domain | 77,760 cases passed, plus difference/anchor checks | Independent exact model; original `trop.rs` not supplied |
| Follow-up conservative lift suite | 9 tests passed | Includes924 supplied conservative transitions and9,603 native G/H cases; clear arithmetic |
| Follow-up existing NINE65 Lean slice | Five modules and axiom audit passed | Standard-library arithmetic/model proofs; separate from the public target root |
| Follow-up Holte and other models | Passed within recorded finite domains | Complete counts, written proofs and limitations in the tropical FHE addendum |

Raw outputs are in `evidence/`; independent experiment code is in `experiments/`. The snapshot, commands, and limitations are recorded in the supporting reports. Passing negative-control tests means the expected limitation was reproduced, not repaired.

## 10. What to update in the proof project

First restore a reproducible build: change the pre-import module documentation into an ordinary comment, or place it after imports; fix and compile `Basic.lean` explicitly. Preserve the correct main modular-subtraction formula. The PDF/FAQ Nat-subtraction variants are not safe substitutes: natural subtraction truncates at zero.

Next formalize, in order: the unbounded quotient-congruence identity; exact signed/unsigned recovery under intervals; true uniqueness of all admissible candidates; noncoprime resolution; the finite coupled-anchor kernel; alias impossibility; exact division versus floor division; comparison thresholds; tree coordinates; then the abstract subgroup/observer theorem and lattice specialization. Treat tropical theta quasi-periodicity, chart boundaries, and the commuting evolution diagram as a separate layer.

Current `kElimination_unique` only states that a bounded quotient equals its own remainder modulo A. It does not itself quantify over two candidates. Current Coq covers the division identity, bounds, and congruence; it is not a second proof of the inverse-based extraction. The theorem names and README should accurately reflect those scopes.

Only after those mathematical specifications should the project claim refinement to a residue-native Rust implementation, an encrypted circuit, a measured cost model, or FHE security. Each needs its own theorem/test interface. The full proposed modules and acceptance criteria are in [PROOF_UPDATE_SPEC.md](PROOF_UPDATE_SPEC.md).

## References and retrieval limits

Primary papers were preferred. Web-extracted PDFs can contain OCR errors; cited conclusions above were checked against their explicit prose and relevant formulas. Locally retained extracts support review. Abstract-only entries are clearly marked. Search coverage is not a proof of nonexistence of prior art.

* **R1.** H. L. Garner, “The Residue Number System,” 1959, [journal DOI](https://doi.org/10.1109/TEC.1959.5219515); [conference version](https://doi.org/10.1145/1457838.1457864). Abstract and conference text retrieved.
* **R2.** N. S. Szabó and R. I. Tanaka, *Residue Arithmetic and Its Applications to Computer Technology*, 1967. Bibliographic confirmation and discussion in R3/R8; full book not read.
* **R3.** M. A. Hitz and E. Kaltofen, “Integer Division in Residue Number Systems,” *IEEE Transactions on Computers* 44(8), 983–989, 1995. [Author PDF](https://users.cs.duke.edu/~elk27/bibliography/95/HiKa95.pdf), [DOI](https://doi.org/10.1109/12.403714). Relevant division, scaling, complexity sections read.
* **R4.** T. R. N. Rao and A. K. Trehan, “Binary Logic for Residue Arithmetic Using Magnitude Index,” 1970. [DOI](https://doi.org/10.1109/T-C.1970.223026). Abstract-level evidence only.
* **R5.** A. P. Shenoy and R. Kumaresan, “Fast Base Extension Using a Redundant Modulus in RNS,” *IEEE Transactions on Computers* 38(2), 292–297, 1989. [Institutional record](https://digitalcommons.uri.edu/ele_facpubs/710/), [DOI](https://doi.org/10.1109/12.16508). Original abstract plus algorithm exposition in R8.
* **R6.** D. E. Gilbert, *Investigation into Efficient Conversion Methods Between Residue and Binary Systems*, Naval Postgraduate School thesis, September 1991. [DOI/report ADA245227](https://doi.org/10.21236/ADA245227). Abstract retrieved; full-text mechanism comparison remains open.
* **R7.** J.-C. Bajard, L.-S. Didier, P. Kornerup, “Modular Multiplication and Base Extensions in Residue Number Systems,” ARITH 2001. [Author PDF](https://webusers.imj-prg.fr/~jean-claude.bajard/MesPublis/ARITH15.pdf), [DOI](https://doi.org/10.1109/ARITH.2001.930104). Some indexes show later online dates; conference year is 2001.
* **R8.** J.-C. Bajard and L. Imbert, “A Full RNS Implementation of RSA,” *IEEE Transactions on Computers* 53(6), 769–774, 2004. [Author PDF](https://www.lirmm.fr/~imbert/pdfs/rsa_rns_ieeetc_2004.pdf), [DOI](https://doi.org/10.1109/TC.2004.2).
* **R9.** H. D. L. Hollmann, R. Rietman, S. de Hoogh, L. M. G. M. Tolhuizen, P. Gorissen, “A Multi-layer Recursive Residue Number System,” 2018. [arXiv:1801.07561](https://arxiv.org/abs/1801.07561). No separate 2026 publication verified in this audit.
* **R10.** R. Inoue, A. Kuniba, T. Takagi, “Integrable structure of box-ball systems: crystal, Bethe ansatz, ultradiscretization and tropical geometry.” [arXiv:1109.5349](https://arxiv.org/abs/1109.5349), especially §4.1 and tropical Toda discussion. Relevant sections, not the complete review, read.
* **R11.** R. Inoue and T. Takenawa, “Tropical Jacobian and the generic fiber of the ultra-discrete periodic Toda lattice are isomorphic,” [arXiv:0902.0448](https://arxiv.org/abs/0902.0448). The theta definition and quasi-periodicity were examined for the companion analysis.
* **R12.** T. Tokihiro, A. Nagai, J. Satsuma, “Proof of solitonical nature of box and ball systems by means of inverse ultra-discretization,” *Inverse Problems* 15(6), 1639–1662, 1999. [DOI](https://doi.org/10.1088/0266-5611/15/6/314). Abstract and references verified, not complete proof replication.
* **R13.** L.-S. Didier, N. El Mrabet, L. Glandus, J.-M. Robert, “Residue Number System Comparison revisited, a software perspective,” ICECET 2025, [DOI](https://doi.org/10.1109/ICECET63943.2025.11472042); [arXiv:2605.18415](https://arxiv.org/abs/2605.18415), posted 2026, manuscript dated May 2025. Relevant algorithm, theorem, and cost sections retrieved.
* **R14.** J. Fan and F. Vercauteren, “Somewhat Practical Fully Homomorphic Encryption,” 2012. [IACR ePrint 2012/144](https://eprint.iacr.org/2012/144). Abstract and bootstrapping/decryption excerpts retrieved.
* **R15.** I. Chillotti, N. Gama, M. Georgieva, M. Izabachène, “TFHE: Fast Fully Homomorphic Encryption over the Torus,” [IACR ePrint 2018/421](https://eprint.iacr.org/2018/421), full version of Asiacrypt 2016/2017 work. Abstract and relevant functional descriptions retrieved.
* **R16.** W. Wang and X.-G. Xia, “A Closed-Form Robust Chinese Remainder Theorem and Its Performance Analysis,” 2010. [DOI](https://doi.org/10.1109/TSP.2010.2066974). Abstract-level evidence; a pointer for the separate noisy-observation problem.
* **R17.** Yutong Wang, “Towards Privacy-Preserving Universal Approximators via Tropical Rational Functions,” Illinois Tech seminar, 18 February 2026. [Official abstract](https://datasys.cs.iit.edu/seminar/wang-2026-02-18.html). Announcement verified; cryptosystem construction not available in that source.
* **R18.** L. Zhang, G. Naitzat, L.-H. Lim, “Tropical Geometry of Deep Neural Networks,” ICML2018, PMLR80. [Paper and proceedings](https://proceedings.mlr.press/v80/zhang18i.html). Definitions, integer-weight assumptions and Theorems5.2–5.4 examined.
* **R19.** Y.-S. Chu and Y.-C. Kuo, “From Universal Approximation Theorem to Tropical Geometry of Multi-Layer Perceptrons,” 2025. [arXiv:2510.15012v1](https://arxiv.org/html/2510.15012v1). Relevant definitions and Proposition3.15 examined; ordinary versus generalized tropical slopes require the qualification in the addendum.
* **R20.** P. Diaconis and J. Fulman, “Carries, Shuffling, and Symmetric Functions,” [arXiv:0902.0179](https://arxiv.org/abs/0902.0179), especially carry matrix and Eulerian stationary law; J. M. Holte, “Carries, Combinatorics, and an Amazing Matrix,” 1997, [DOI](https://doi.org/10.1080/00029890.1997.11990612). Relevant Diaconis–Fulman excerpts and Holte abstract retrieved; the all-arity nonreversibility induction was separately read in the pinned repository.
