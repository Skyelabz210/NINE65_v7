# Proof update specification

This is a reviewable research specification. The universal additive/ring theorem and constructive integer instances now have a freshly compiled standalone implementation; domain-specific integration remains. Preserve on-demand K, authentic phase-locked source state, and declared reconstruction boundaries. No persistent scalar ledger is prescribed.

Updated after reading the October25 tropical FHE report and the later conservative continuum construction. See [TROPICAL_FHE_ADDENDUM.md](TROPICAL_FHE_ADDENDUM.md) for the new proofs, scope and fresh execution evidence.

The subsequent 22-attachment review materially expands the proof target; see [EXPANDED_ANALYSIS.md](EXPANDED_ANALYSIS.md). Lead with the general query/lift/composition theorem and its constructive instances. The long-form CRAM source already states local-query sufficiency (§14) and finite-step exactness (§16). This structure should be visible in the updated proof rather than leaving the contribution framed as one integer identity.

## Newly checked universal theorem and constructors

[UNIVERSAL_THEOREM.md](UNIVERSAL_THEOREM.md) is now the primary proof target and result. The [standalone package](universal-theorem/README.md) passed a clean Lean4.27.0-rc1 build of 130 declarations, with all imports rebuilt and all theorem axioms audited. The first 75 declarations establish the core below; the latest [continuation](CLOSURE_PROOFS.md) adds 55 declarations for StarLift, reference changes, combined-anchor laws, and concrete divmod/GCD:

* `UniversalLift`: observed affine identity, complete kernel ambiguity, admitted-domain query equivalence, exact target factor iff kernel inclusion, uniqueness/additivity on the image, and constructive target transport.
* `RingReadout`: actual one-subtraction/one-multiplication formula for arbitrary rings with a sided inverse, right/left conventions, solution fibers and unit-kernel reduction.
* `IntegerSpecialization`: actual modular readout from supplied chart/source views, exact unsigned/signed windows, star/adjacent constructors, certified nonunit defect reduction and direct target-lane transport without exact K when the target annihilates the remaining period.
* `CostedReadout`: expression evaluation, literal arithmetic-operation counts and a proof that the fast ring formula instantiates the universal theorem.

The [verification manifest](universal-theorem/verification.json) and [log](universal-theorem/verification.log) identify all declarations and dependencies. There are no admissions or project axioms. Generic image-factor existence uses classical choice; actual ring/integer readouts are explicit programs. The package does not claim that every domain has a uniformly cheap decoder.

This discharges substantial parts of `QuotientCongruence`, `BoundedRecovery`, `NonCoprimeRecovery`, `ObserverLift`, `RelativeLiftProjection`, `ObservationLimits` and the readout `CostModel` below. The continuation now also proves exact coupled-anchor GCD/LCM resolution and complete divmod/GCD loops with every concrete primitive obligation discharged. Multi-anchor fusion implementation and refinement of the actual NINE65 implementation remain.

## Reused observation/composition specification

[ExactObservation.lean](expanded-corpus/ExactObservation.lean) contains nine theorems freshly compiled with Lean4.27.0-rc1: query recoverability iff fiber constancy, authentic observation refinement, query-specific collision obstruction, primitive identity/composition, finite-program encoded correctness, injective full-value identification, and frame-transfer composition/roundtrip. [Axiom output](expanded-corpus/exact-observation-lean.log): Classical.choice for the existence equivalence; no axioms for the other eight. No custom axiom or sorry is used. These are specification theorems, with a noncomputable existence direction, not executable decoders or Rust refinements. Original repository files remain unchanged.

The remaining or partially discharged arithmetic targets are:

* `IdealLift`: the solution fiber K0+(J:M), ideal closure and admitted-set uniqueness are now checked in generic ring form. A packaged multiple-observer/ideal-intersection instance remains to add.
* `PolynomialLift`: quotient extraction over F[t], a degree-window uniqueness theorem, shared-factor reduction, and arbitrary-target projection.
* `RelativeLiftProjection`: arbitrary affine references, chart-only readout and direct target-lane projection are now checked. Normalized CRT dot-lift producer bounds remain a written sufficient-window construction, separate from the intended adjacency producer.
* `OneWaveQuotientMod`: for every integer X and positive P,A, ((X mod PA)−(X mod P))/P = (X/P) mod A with Euclidean division. Exact quotient equality is a separate range corollary.
* `ResidueDivmodAndGcd`: the complete bounded comparison/subtraction and Euclidean loops, concrete paired-residue primitives, and zero-divisor refusal are now Lean-checked. Refinement to a selected NINE65 production API and its cost remains separate.
* `RankDivisionRefinement`: refine the current exact rank/projection implementation, including signed interval and public-u64-divisor semantics.
* `EncryptedWordDivision`: prove the finite-table/restoring compiler, encrypted zero-divisor policy, and the actual BFV gate/noise/capacity refinement. Existing encrypted executions are positive evidence, not a substitute for that proof.

The module list below remains a dependency guide. Reuse the checked universal core and constructors rather than re-proposing them as unimplemented. Finite composition needs total admitted-state semantics or explicit errors; full value identification needs faithful encoding; metadata-history changes need a stated equality notion.

## Immediate reproducibility repair

Pinned input: `0400092096962e3da45a8e5cbb82185a3c2c38fe`, Lean `v4.27.0-rc1`, Mathlib `3bdc7047b97538f795b725dc0713c28c0f53ed10`.

1. Apply/review [suggested-parser-and-basic.patch](proof-check/suggested-parser-and-basic.patch): use an ordinary opening comment before imports; supply the fundamental div/mod identity to Basic's proof; use `Nat.div_lt_of_lt_mul` for its range theorem.
2. Compile **every** Lean file, including `KElimination/Basic.lean`, not only the root. Patched scratch Basic passed; the whole repaired root has not been freshly checked.
3. Run `#print axioms` on the main soundness theorem and every new theorem. Report foundational axioms separately from project assumptions, `sorryAx`, declarations of axioms, and opaque imported certificates. The audit's axiom query file is unexecuted because Mathlib cache access failed and a complete source rebuild was not completed.
4. Rebuild Coq from `.v`; do not use bundled `.vo` files as fresh evidence. Either add a full inverse-extraction theorem or describe Coq as checking supporting lemmas only.
5. Generate public theorem snippets from compiled sources. Replace the FAQ and attachment-style natural-subtraction formula with the actual `ZMod`/`Int` formula or safely normalized natural subtraction.

## Proposed theorem modules, in dependency order

| Module | Required statements | Acceptance conditions |
|---|---|---|
| `QuotientCongruence` | For M>0 and X∈Z, X=r+MK with Euclidean r. In ZMod A: M*K=s-r. For unit M mod A, inverse readout equals K mod A without an X upper bound. | Positive, negative, X=0, X=MA, A=1 policy explicit. Use integer casts with tested normalization. |
| `BoundedRecovery` | A congruence class has at most one representative in an interval of integer width<A; existence from authentic X. Standard 0<=X<MA and signed 2B<A corollaries. | Actual two-candidate uniqueness theorem, not just `K%A=K`. Boundary alias at width A included. |
| `NonCoprimeRecovery` | d=gcd(M,A); consistency iff d divides s-r; solutions K modulo A/d, reduced unit inverse; modulus1 vacuous case. | No original nonunit inverse is used; inconsistent observations refused. |
| `CoupledAnchors` | L=lcm anchors, R=L/gcd(M,L)=lcm_i(Ai/gcd(M,Ai)); observation kernel RZ; total X period MR. | Repeated, overlapping, dividing and coprime anchors; input compatibility proof; interval uniqueness. |
| `ObservationLimits` | For arbitrary observation O and query F, an exact decoder on the image of O exists iff F is constant on every fiber of O. X and X+MR alias; no new distinguishing residue is a function of insufficient old state. | Countermodels formalized, including old moduli6,5 and requested modulus7; distinguish a recoverable query from full-state reconstruction. |
| `ExactAndFloorDivision` | Lane inverse correctness under b|X; floor division via subtracting the remainder; good/auxiliary-lane recovery under a true quotient bound. | Distinguish modular inverse, exact integer division, Euclidean division and signed truncation. b=0 rejected; prime-power divisibility not inferred from a single mod-p check. |
| `Ordering` | Lexicographic (K,r) order and threshold theorem for a specified total range and sign convention. | Odd/even periods, midpoint ties, equal quotient, full-range versus half-range difference comparison. |
| `TreeCoordinates` | Root residue plus edge quotient residues forms a bijection with the residue tuple under edge coprimality. | Prove inverse by tree induction; do not rename edge readouts as recursively nested floor digits. |
| `ObserverLift` | Chosen section of G/Λ; observer h; unique recovery on S iff (S-S)∩ker(h)⊆{0}; existence from compatibility. | Group axioms and section assumptions explicit; empty S handled; no efficiency conclusion from injectivity. |
| `LatticeLift` | Matrix observer acting on lattice coordinates; uniqueness iff kernel avoids admissible differences; invertibility mod A as sufficient special case. | Modular versus real invertibility distinguished; chart representative and boundary conventions explicit. |
| `TropicalThetaLift` | Rank-one minimum formula and tie boundary; rank-d quasi-periodicity; compatible coordinate recovery. | Show actual minimum argument, not only the desired value. Restrict to the correct theta/Voronoi cell for minimizer statements. |
| `ConservativeContinuumLift` | Equal-mass finite binary snapshots; prefix-flux continuity equation; real piecewise-linear height identity; bounded flux recovery from authentic paired prefix views. | Fixed absolute grid and boundary flux; distinguish given transition from successor rule. Coprime capacity2B<MA or proved generalized LCM capacity. Real interpolation proof separate from rational executable samples. |
| `ValuationPrecision` | Multiplicative valuation, nonarchimedean inequality, equality for unequal valuations, and information determined by reduction modulo p^e. | Explicit cancellation and p^e-versus-p^(e+1) aliases; no semiring-homomorphism claim for arbitrary source addition. |
| `Transduction` | Encodings of a common state set; round-trip and composition on valid images; operator-semantics commuting square. | Preserve schema/provenance where claimed; mismatched capacity/domain refusals; representation implementation separate. |
| `ExecutionRefinement` | Concrete state invariants, authentic source/epoch bindings, executable query algorithm refines mathematical observable. | No scalar X oracle or carried scalar K in the intended residue compute path; declared boundary operations explicitly typed. |
| `CostModel` | Instruction semantics or circuit DAG, preprocessing, word width, modular arithmetic cost, work/depth/space measures. | Derive counts from code; compare identical input/output contracts and setup amortization. Existing k+l versus k² proof retained only as a model lemma. |

A theorem package can reasonably stop after any layer with an explicit scope. It must not promote earlier layers into proof of the later ones.

Holte reversibility is an independent optional theorem family: the current source already gives an ordinary all-arity proof for IID uniform common-base digits. Formalizing it must retain that model, and it need not block the K/geometry developments. A geometric dynamics bridge should state the exact transition operator and prove that its embedding commutes with the proposed evolution. Connecting geometric flux to K_phase or K_native requires a separate producer equation.

For polynomial/shared-factor specialization, reuse the existing NINE65 `PublicRefreshDigit` and `PublicRefreshNativeLift` modules. The five-module standard-library arithmetic slice was freshly compiled and passed its axiom audit in this follow-up. Its root/unit certificates, source norm and noise/model premises remain explicit; this does not repair the separate public repository root or establish Rust refinement. A verified snapshot and checker are included in `proof-check/native-refresh-source/`.

## Encrypted implementation boundary

Keep FHE specialization separate from the arithmetic library. State its plaintext ring, ciphertext representation, evaluation keys, source quotient and remainder, signed bounds, noise invariant, and actual producer-to-consumer relation. Show that encrypted projection computes the intended **plaintext** observable, rather than only coefficient-level modular arithmetic. Include every reduction, selection, scale conversion, and return-key operation in circuit/depth counts.

Correctness, confidentiality, constant-time behavior, and performance are independent obligations. Preserve valid symmetric/trusted and public research modes with their own statements. The existing current NINE65 refresh status must be reconciled before changing any historical path; this research packet neither enables a legacy path nor removes a working mode.

## Dynamic range and sequence closure

For add/multiply/scale chains, propagate a public interval or another valid domain certificate from operation bounds, without exposing/storing the exact hidden magnitude. Before a finite representation aliases, extend it from authentic source information. Prove:

    valid(state, domain) and enabled(op,state)
    implies valid(step(op,state), next_domain)
    and decode(step(op,state)) = semantic_op(decode(state)).

An induction then gives correctness of finite compositions. Division and comparison need their established guards; malformed provenance and exhausted domains need explicit refusal. Such a theorem establishes a declared programming model, not unrestricted infinite precision at fixed storage.

## Claim-level comparison for the contribution statement

State the claimed contribution before selecting comparators: an identity, an algorithm/state model, a generalization, a constructive cross-domain bridge, or an encrypted realization. A match at one level must not be promoted to an equivalence at the others. In particular, one Garner-like algebraic step is insufficient to identify the complete K-Elimination mechanism with Garner. Preserve attribution of the proposed framework to Anthony Diaz.

For each overlapping operation, compare relevant portions of Hitz–Kaltofen, Shenoy–Kumaresan, Bajard–Didier–Kornerup, Bajard–Imbert, Hollmann and the tropical/BBS literature. Gilbert's RNS-Q/RNS-QD and Rao–Trehan's magnitude index remain abstract-only leads until their actual mechanisms are read. Record exact input observables, outputs, domain, preprocessing, arithmetic width, work, depth, source bindings and state stored. Cite an antecedent as background when it supplies only an ingredient. To assert an earlier equivalent, identify the actual matching construction and its hypotheses. To assert a new theorem or bridge, articulate the added domain, conclusion or constructive content. Generalization can be a mathematical contribution even when its special cases and proof tools are established.

## Research questions that remain open

* The user's tropical source is now identified and reviewed. Which precise evolution operator and source map connect the conservative continuum flux to the intended BBS dynamics and FHE correction? The present source proves a given-transition embedding and separate theta/phase identities.
* How should the proven comparison/divmod/GCD closure and the existing bounded rank divider be refined into the intended general residue-native API? Feasibility without full scalar reconstruction now has constructive witnesses; current inspected GCD helpers still use scalar values. Competitive cost and encrypted admission need their own measurements/proofs.
* Can a higher-rank sheet observer be implemented efficiently with authentic encrypted coordinates, with all chart boundary cases covered?
* What operator-schema metadata can be transported reversibly without expanding beyond the destination's capacity?
* Is there a resource advantage after charging for anchor production, synchronization, nonlinear comparison and range growth?

These are useful concrete research targets. An unrestricted “universally generalizable” assertion is too weakly specified to prove or refute beyond the explicit counterexamples to lossless inversion without sufficient observations.
