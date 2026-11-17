# K-Elimination as a generalized observation, lift and computation framework

12 November 2026. This expands the earlier audit using the 22 subsequently supplied attachments, their relevant archive contents, and newly executed current-source tests. The source inventory and detailed reviews are linked below. The public Lean and NINE65 repositories remain unchanged.

The subsequent universal-theorem work is now the main result: [UNIVERSAL_THEOREM.md](UNIVERSAL_THEOREM.md) states and proves exact direct-query transport and its concrete constructors. Its [standalone package](universal-theorem/README.md) freshly checks 130 declarations, including the nine earlier specification theorems. The evidence below remains the source and application context for that theorem.

## What the expanded evidence changes

**The generalization is a substantive part of the proposed contribution.** The appropriate object of study is Anthony Diaz's complete construction: authentic residue observations, on-demand lift extraction, exact queries, frame transfer, and composition. Matching one scalar expression inside Garner does not establish that this construction was previously disclosed or that its cross-domain uses are merely renaming.

The long-form `ConfigurableResidueArithmeticMachines` document already contains a useful general theorem structure: §14 proves local-query sufficiency; §16 states finite-step exactness; §17 distinguishes exact finite refinement from its domain-specific analytic limit. The shorter monograph explicitly says that K is derived when needed and is not carried forward. These statements supersede the secondary survey's description of a persistent winding-register architecture. They should anchor the proof update.

The expanded review also closes an overly broad feasibility question: **full integer reconstruction is not inherently required for exact comparison, arbitrary nonnegative quotient/remainder, GCD, or compatible frame transfer on an admitted residue domain.** There are constructive implementations of those statements in the independent models, and current NINE65 has stronger division implementations than the earlier review had traced.

This is a positive mathematical conclusion. The distinct question of which efficient, encrypted, or production APIs implement each construction is answered separately below.

## The generalized theorem

Let D be the admitted source states, O:D→R the available observations, and F:D→Y the requested answer. An exact answer map on the observed states exists precisely when

\[
O(x)=O(y)\implies F(x)=F(y),\qquad x,y\in D.
\]

Necessity follows by applying the answer map. Sufficiency follows because F has one well-defined value on each observation fiber. The theorem concerns a requested query; it does not demand recovery of everything about x. Full-state recovery is the special case F=id, requiring injectivity of O.

This is a standard abstract factorization principle, now useful as the common specification for the proposed CRAM construction. **Its abstract generality alone is not the novelty claim or an efficient algorithm.** The constructive content lies in the chosen observations, their production, the actual query algorithms, the supported domains and the way they compose.

An arithmetic version makes the missing coordinate explicit. For additive abelian groups, suppose

\[
x=r+\iota(k),\quad k\in S,\qquad h(x)\text{ is observed}.
\]

Then

\[
(h\circ\iota)(k)=h(x)-h(r).
\]

Every compatible observation identifies at most one k in S exactly when

\[
(S-S)\cap\ker(h\circ\iota)\subseteq\{0\}.
\]

An effective inverse on the admitted image turns this into an on-demand query. Integers, polynomial coefficients, lattice coordinates and covering-space sheet indices provide distinct specializations. A tropical specialization must identify its chart and lifting group; it need not pretend that subtraction exists in every tropical semiring.

For a commutative ring R, an observer ideal J, and X=r+MK, the complete solution set is particularly concise:

\[
K_0+(J:M),\qquad (J:M)=\{u:Mu\in J\}.
\]

Two candidates have the same observation exactly when their difference belongs to this ideal. A unit M modulo J gives the familiar inverse formula. A nonunit is handled by its actual solution fiber rather than by a nonexistent inverse. Multiple observations replace J with the intersection of their ideals. The [portfolio review](expanded-corpus/reviews/portfolio.md) supplies the proof and constructive polynomial specialization.

## What follows constructively

| Operation or domain | Established construction and exact scope |
|---|---|
| Integer quotient/magnitude | X=r+MK with authentic observations modulo M and A gives K modulo A/gcd(M,A). A certified admissible window identifies its exact representative. K is a query, not a required persistent field. |
| Multiple, overlapping anchors | With L=lcm(A_i), quotient resolution is L/gcd(M,L); total source period is lcm(M,A_i). Coprimality is not a blanket admission requirement for this generalized solve. |
| Arbitrary target moduli | Once the needed lift is identified, X mod B=(r mod B+(K mod B)(M mod B)) mod B for every B>0, including shared-factor and composite B. No full X need be emitted. |
| Noncanonical main lifts | Any chosen lift L congruent to X modulo M works with its own correction K_L=(X−L)/M. Modular views of L suffice. This gives direct residue-to-residue transfer from small source lanes plus an authentic anchor. |
| Comparison | Exact transient K and canonical r give lexicographic order. An authentic direct 36/37 frame implements the K query by subtraction. |
| General nonnegative division | Comparison, lane-wise subtraction and lane-wise increment give terminating divmod for every nonzero admitted divisor, including shared factors and inexact division. The included simplest construction uses repeated subtraction. |
| GCD | Euclidean iteration over that divmod kernel returns the GCD in residue form. Every remainder decreases, so the original capacity bound suffices throughout. |
| Rational arithmetic | Encode numerator and nonzero denominator separately. Exact rational division does not require every denominator to be a unit in every lane. GCD can optionally canonicalize the pair. |
| Polynomial quotient | Over any field F, coprime polynomial anchors M,A give Q mod A=(s−r)M⁻¹ mod A. The degree window deg X<deg M+deg A makes Q exact. Shared factors use the ideal-quotient law. |
| Frame transduction | Concrete direct target projections preserve the represented value and compose on compatible admitted frames. Windings may change with the frame; metadata preservation must specify which fields are preserved. |
| Tropical/continuum instances | The previously verified theta-sheet identity and conservative prefix-flux construction give specific geometric applications. The latter extends exactly to real spatial coordinates by interpolation. General analytic dynamics require their own commuting evolution/limit theorem. |

These implications are more informative than a list of analogies. For example, the GCD construction has a complete invariant proof: initialize q=0,r=a; every division step preserves a=qb+r and decreases r; Euclid then preserves gcd(a,b)=gcd(b,r) and terminates. The runtime number object in the [reference model](expanded-corpus/experiments/compendium_residue_divmod_gcd.py) has exactly two fields, the two residues. Its operations never assemble r+MK or retain K. Ordinary integers are used for ingress and the independent test oracle only.

A query may need less information than the full K. For instance, if K is known modulo R, the target residue of r+MK modulo B is already well-defined whenever B divides MR: replacing K by K+R changes the expression by a multiple of B. This makes the query theorem useful even when full integer recovery is unavailable.

The model is deliberately simple and may take exponentially many iterations in the operand bit width. It proves existence and conformance for the bounded paired-view representation. It is not a performance claim, an encrypted circuit, or the current NINE65 implementation. If a supposed main residue exists only as many smaller channels, its producer must be implemented rather than assumed free. These distinctions preserve the useful conclusion: reconstruction is optional for these operations, while algorithm choice determines their cost.

The relative-lift construction is also explicit. For pairwise coprime main moduli m_i, let M_i=M/m_i and c_i=(r_i M_i⁻¹) mod m_i. The proof lift L=Σc_i M_i satisfies 0≤L<nM. If 0≤X<(Q+1)M, its correction lies in [−(n−1),Q]. An anchor with effective resolution at least Q+n therefore identifies that correction. Each requested target computes L mod B as a modular dot product; the implementation never constructs L or X. This direct construction costs O(nt) modular work for n source lanes and t targets. It uses CRT weights, so a stricter instruction policy must decide how those public constants are obtained; it is not a replacement imposed on the adjacency construction.

## Current NINE65 evidence

Frozen checkout: `88a7bdadbf0e1f8fbfdb2b37e9843101b8db3484`. The [runtime review](expanded-corpus/reviews/runtime.md) gives source paths, symbols, feature settings, commands and raw logs.

| Path | Current finding | Fresh verification |
|---|---|---|
| `RankResidueDivider::divide_floor` | Signed-interval quotient/remainder for nonzero u64 divisors, including shared factors; retains the full residue basis. Uses exact global rank and modular projection to divisor×target modulus. It does not assemble scalar X, but uses wide global scratch and is not a constant-work local lane query. | 8/8 targeted tests pass. |
| Recumbent rank-projection route | Calls that rank divider for experimental recumbent coefficient division. | 15/15 tests pass. |
| Main-Q `divide_integer` | Actual encrypted unsigned word quotient/remainder. Sealed Boolean words and exact BFV gates implement general division; it is a different algorithm from scalar modular inversion or a two-input K formula. | 8/8 tests pass, including a native N8192 test with t=3 and divisor 3; all 147,456 checked output coefficients pass. |
| Exact BFV scale/round | Dedicated exact residue path supporting the encrypted arithmetic. | 10/10 targeted tests pass. |
| Comparison kernel | Current dedicated comparison path; exact scope in the runtime report. | 11/11 targeted tests pass. |
| Exact-route source guard | Checks the named production routes for prohibited calls/patterns. | Pass over 4 sources/2,762 production lines; all 16 negative controls detected. Static source checks complement execution and are not a semantic proof by themselves. |
| Current GCD APIs inspected | `CRTBigInt::gcd` reaches scalar reconstruction/cached magnitude through `%`; an order-finding helper is ordinary u64 Euclid. No residue-native or encrypted GCD API was located in the searched evaluator modules. | The new reference model establishes derivability, not deployment of that API. |

The rank divider takes a **clear public u64 divisor**. The encrypted divider instead takes separately encrypted word bits. That word representation retains more information than a single plaintext-field element: dividing by plaintext modulus 3 does not attempt to invert zero in that field. Both distinctions are part of the successful APIs' contracts.

The encrypted division test also checks an encrypted zero-divisor result according to its defined flag/result policy. This must not be equated with silently accepting ordinary integer division by zero. Current admissions remain finite and depend on the actual word/circuit budget; an API's existence is not an all-width performance result.

The old uploaded “Exhaustive Audit Fallback Systems” names C, Python and Verilog paths absent from the frozen Rust repository and gives an 80% fallback figure without a reproducible run. It cannot substantiate that current-path claim. The uploaded `Crate 12` contains several historical Rust variants and a clearly labeled plaintext/noise-counter simulator. Their failures and passing tests are preserved in the runtime report; neither the simulator nor those variants characterize current encrypted NINE65.

The previous research-refresh evidence remains separate. No new full native five-cycle refresh experiment was run here. Arithmetic and division success do not supply a proof of the complete cryptographic key setup.

## Fresh Lean result and the proof update

The latest clean build covers 130 declarations: the earlier 75-declaration universal core and 55 new StarLift, combined-anchor, reference-change and complete concrete divmod/GCD declarations. See [the continuation](CLOSURE_PROOFS.md). The new core proves the exact target criterion ker B⊆ker C and an actual ring program that instantiates it. Integer constructors include chart-only readout, signed windows, star/adjacent anchors, nonunit reduction, and direct target transport even when full K is ambiguous. [Source hashes and axiom audit](universal-theorem/verification.json) and [compiler log](universal-theorem/verification.log) record the completed scope.

[ExactObservation.lean](expanded-corpus/ExactObservation.lean) now contains **nine freshly compiled theorems** under `leanprover/lean4:v4.27.0-rc1`, with no Mathlib dependency. The [axiom log](expanded-corpus/exact-observation-lean.log) reports Classical.choice only for the mathematical existence equivalence; the other eight theorems have no axioms. No `sorry` or custom axiom is used.

They cover query recoverability, preservation under authentic observation refinement, a precise collision obstruction, identity/composition of primitive refinements, finite-program correctness, an explicit injectivity upgrade to full-value identification, and transduction composition/roundtrip on valid encoded states. An independent statement review checked the specification and prompted the explicit injectivity qualification.

These are generalized specification theorems. They do not implement every decoder, prove the actual Rust kernels, or impose scalar reconstruction: the semantic encoding is proof-only. Partial operations, refusals and changing capacities need typed outcomes or a certified state domain. Metadata that appends history cannot automatically satisfy strict whole-state roundtrip equality.

The next concrete theorem layers, after the newly checked core and constructors, are:

1. An implemented coupled-anchor fusion decoder, using the now checked GCD/LCM resolution laws.
2. Concrete relative-lift producers and their capacity bounds, extending the checked arbitrary-reference and target-projection programs.
3. Production refinement of the now checked concrete comparison, quotient/remainder and Euclidean GCD algorithms; rational pair semantics.
4. Polynomial and lattice instances, then the specific tropical chart and continuous-height constructions.
5. Concrete representation/trace refinement for the intended no-persistent-K, no-Garner compute path.

This changes the formalization emphasis: lead with the generalized query/lift/composition theorem, then show how the existing integer result instantiates it. The previous public-root build problem at `0400092096962e3da45a8e5cbb82185a3c2c38fe` remains separately documented; this new standalone success does not claim that root was repaired or rebuilt. See the updated [proof specification](PROOF_UPDATE_SPEC.md).

## Source corrections and novelty assessment

The corpus is a sequence of working papers, historical implementations, secondary reviews and ideation transcripts. Its careful theorem statements and later corrections should control the synthesis. Several old errors already appear as retired claims in the supplied memory. Repeating them as current architectural limitations would be misleading.

In particular, the later arrow-of-time record explicitly retracts a stored-K description and accumulator witness, then records stateless extraction, signed windows, reduced noncoprime resolution and construction-based tower growth. It also distinguishes legitimate noninvertible operators from blanket reversibility. Those are documented refinements within the program itself.

The detailed reviews retain exact corrections before formalization: one reversed adjacency subtraction; a missing constructed-input range; the use of canonical K with a noncanonical CRT lift; signed Euclidean towers that do not terminate at −1; and confusion between exact finite refinement, profinite completion and a classical analytic limit. They also distinguish the explicit scalar reconstruction in the August division paper from the later implemented division paths. None is evidence that the correct on-demand query principle fails.

Generalization can be the mathematical contribution even when special cases and proof tools are established. A defensible contribution statement is:

> K-Elimination/CRAM organizes exact computation around authentic observations and on-demand lift queries. Under explicit identifiability and operation invariants, it supports magnitude/order, arbitrary residue projections, quotient/remainder, GCD and compatible frame changes without requiring full integer reconstruction during those computations. Its algebraic formulation admits integer, polynomial and geometric specializations.

The constructive domains and guarantees in that statement are what a novelty comparison must match. An earlier work supplying one CRT identity is an antecedent for that identity. Establishing an earlier equivalent of the complete framework would require matching its observations, state policy, algorithms, domains, outputs and guarantees. This review has not established such an equivalent, and does not certify priority for every component.

Historical division was a cost and architecture problem, not an absolute impossibility theorem. Hitz–Kaltofen (1995) and the newly inspected Hung–Parhami (1994) describe general or fixed-divisor quotient/remainder algorithms; the latter explicitly distinguishes which algorithm needs coprimality and which does not. Those comparisons should be accurate without erasing a different generalized construction. Primary-source details and remaining literature gaps are in the original analysis and [intake notes](expanded-corpus/ROOT_NOTES.md).

## Reproducibility and coverage

| Independent experiment | Fresh positive coverage |
|---|---:|
| Noncoprime/signed quotient observations | 474,060 cases |
| Complete linear-congruence solution sets | 13,950 cases |
| Relative-lift arbitrary-target projections | 1,287,900 target residues |
| General one-wave quotient residues | 423,125 cases |
| Polynomial exact quotient recovery | 343,600 cases |
| Polynomial arbitrary-target projection | 343,600 cases, plus separately checked alias controls |
| Residue-only comparison/GCD model | 37,701 pairs |
| Residue-only divmod model | 37,428 pairs, including 24,201 shared-factor divisors |
| Direct frame transfers/roundtrips/compositions | 369 / 369 / 1,107 cases |
| General query fiber criterion | 1,365 finite observation/query pairs |

Counts describe each experiment's finite domain, not universal proofs, aggregate independent applications, or speed measurements. The latest Lean package verifies the 130 explicitly inventoried declarations; remaining domain specializations have the written/experimental status recorded in [UNIVERSAL_THEOREM.md](UNIVERSAL_THEOREM.md). Failed historical runs and negative controls are preserved alongside successes.

Start with [coverage and provenance](expanded-corpus/COVERAGE.md). Detailed source reviews: [framework](expanded-corpus/reviews/framework.md), [division and safe basis](expanded-corpus/reviews/division.md), [portfolio and algebraic generalization](expanded-corpus/reviews/portfolio.md), [compendium and constructive GCD](expanded-corpus/reviews/compendium.md), [runtime](expanded-corpus/reviews/runtime.md). The earlier [analysis](ANALYSIS.md) and [tropical addendum](TROPICAL_FHE_ADDENDUM.md) remain part of the research record, with this expansion taking precedence for the newly traced division capabilities.
