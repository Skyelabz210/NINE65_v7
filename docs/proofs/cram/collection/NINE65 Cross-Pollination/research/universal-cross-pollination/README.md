# Universal exact transport as an execution principle

Anthony Diaz's CRAM / K-Elimination / NINE65 research synthesis, 12 November 2026. Repository source: `Skyelabz210/NINE65_v7@88a7bdadbf0e1f8fbfdb2b37e9843101b8db3484`. This research branch adds proofs, public-model prototypes and source-linked connections. It does not change the production arithmetic or encrypted evaluator.

The strongest unifying result is this: **a computation can operate exactly on observations that preserve its requested outputs and remain sufficient under its allowed transitions.** Recovering the entire source is one possible requirement. Many useful consumers require substantially less information. The universal theorem identifies that information; concrete K-Elimination constructors compute it; transition proofs determine whether it stays sufficient as computation proceeds.

This yields a practical research direction for NINE65: **compile the information requirements of consumers, then select and execute certified observation producers and operators.** The result joins on-demand magnitude, StarLift, shared-factor resolution, G/H local extraction, operator transduction and dynamic state reduction under one explicit contract.

## What this packet delivers

| Deliverable | Current evidence |
|---|---|
| Universal transport, integer/ring constructors, coupled anchors, bounded residue divmod/GCD, StarLift | 130 prior Lean declarations carried forward unchanged, with source hashes |
| Bundled consumers, postprocessing, transition closure, finite programs, equivalent observations, additive kernel invariance | 14 new Lean declarations; full packet fresh-build PASS: **144 unique declarations** |
| Consumer-driven anchor planner | Executable public-parameter prototype; exact linear/quotient query periods, factorization-free anchor synthesis, minimum-cost choice among available producers |
| Future-query compiler | Executable finite-model prototype; computes the coarsest partition supporting every declared future output and transition |
| Prototype verification | 15 tests, plus independent randomized oracles: 5,000 anchor cases, 1,500 producer-subset cases, 2,000 finite dynamical models |
| Repository cross-pollination | 22 contribution families, six focused return paths, source/claim reconciliation |
| Arithmetic and cryptographic bridges | Seven detailed connections; 80,706 integer-model cases plus a rounding counterexample |
| External-domain research | Eight precisely mapped domains with primary references and feedback into NINE65 |

The new 14 declarations are added to the prior 130, not counted again through their imports. The combined audit allows only Lean's foundational `propext`, `Classical.choice` and `Quot.sound`; 39 declarations use no axioms. Existence via choice does not supply an efficient executable decoder. The concrete constructor and operation-count results retain their stated hypotheses.

## 1. The universal theorem and its dynamic companion

For arbitrary sets, let B observe a state and C request an output. There is a unique decoder on the observed image satisfying D(Bx)=Cx exactly when

\[
Bx=By\implies Cx=Cy.
\]

For additive homomorphisms this is equivalent to

\[
\ker B\subseteq\ker C.
\]

For an affine source `x=r+iota(k)`, put B=h∘iota and C=p∘iota. The transported query is

\[
p(x)=p(r)+D(h(x)-h(r)).
\]

The coordinate-query form also permits B and C to be specified directly on k. In StarLift, take B(k)=Mk mod A and C(k)=k mod A. If it is expressed through an ambient p, choose p(x)=M^(-1)x mod A; taking p(x)=x mod A would instead give C(k)=Mk mod A. This distinction fixes the types without changing either adjacent-modulus formula.

With A=M+1 and X=v_M+MK,

\[
K\bmod A=(v_M-v_A)\bmod A,
\qquad (-K)\bmod A=(v_A-v_M)\bmod A.
\]

These are exact finite queries of an unbounded coordinate. A certified interval chooses a full integer representative when needed. Nonunit and coupled-anchor constructors identify the remaining ambiguity precisely; they need not abandon every query when full-coordinate inversion fails.

Now let F be a state transition. An autonomous observed transition exists exactly when

\[
Bx=By\implies B(Fx)=B(Fy).
\]

For additive B and F this becomes **F(ker B)⊆ker B**. This condition is independent of whether today's query C is recoverable. It proves when a compressed or residue observation supports continued computation. The new Lean module proves the criterion, composition, consumer bundles and an explicit parity/halving failure when the premise is absent.

For an entire operation/query family, the strongest abstract form is observational equivalence over all finite futures:

\[
x\sim y\iff\forall w,j,\ C_j(F_wx)=C_j(F_wy).
\]

This is the coarsest state identification preserving every declared future output. It is transition-stable by construction. The [written proof and finite compiler](PLANNER_PROOFS.md) establish its universal property and constructive finite realization. This last maximal-quotient statement is a written deduction, not an additional claim about the 14 Lean declarations. It connects exact query transport to observability and program semantics in a way that directly guides implementation.

## 2. What becomes possible inside NINE65

| Connection | Concrete consequence | What must be supplied next |
|---|---|---|
| Universal query demand → Safe Basis / shadow lanes | Select observation capacity for the actual consumer; overlap counts by LCM. The new planner computes the least sufficient additional anchor and an exact public-cost subset of available producers. | Real producer identities, role/NTT constraints and measured cost model; a planned reading must actually be produced. |
| StarLift → tropical theta charts | The negative winding query directly represents the minimizing index n=-K in an admitted centered chart. | Chart/reference producer, wall/tie policy and index window; real-valued observations require their own compatible map. |
| G/H → local algebraic retraction | F(x)=x-G(x)H(x) fixes supported residuals and is idempotent modulo p²; weighted targets can have weaker inverse requirements. | Source-bound refinement, supported-domain proof and actual noise/cost comparison. Composite interpolation is a further obligation. |
| Exact division → GCD → rational pairs | A fixed 2w-round Euclidean circuit gives a concrete route from the existing encrypted w-bit divider to GCD, then normalization and cross-cancellation. | Public Boolean DAG, frozen terminal branch, evaluator admission and real encrypted tests. This is a proposed integration, not an already deployed GCD API. |
| Recumbent floor drops → scale scheduling | Nested Euclidean floor quotients compose exactly; the combined remainder is r_d+d*r_e. | Authentic divisor readings and destination bounds. Nearest rounding needs a different law. |
| MAA reflections → quotient dynamics → time folding | Integer reflections preserve the Descartes quadratic form; invariant observation kernels permit exact orbit computation on a smaller quotient. | Concrete matrix/kernel certificates and word-size checks. A geometric predicate may need less state than the full orbit. |
| GRO phase clocks → nonunit resolution | An oriented clock difference delta*t modulo N resolves t modulo N/gcd(delta,N). | Correct orientation and source timing contract; folded distance loses another sign choice. |
| QMNF / Triad → exact result certification | Residue agreement plus a strict bounded-difference certificate proves equality of rounded integers. | Rigorous real-error enclosures and rounding semantics. Finite residues alone do not prove equality or transcendental exactness. |
| Integer normalization → conservation | Exact output totals become a shared query invariant for allocations, neural reference arithmetic and conservative transport. | Accuracy and encrypted selection proofs where relevant; conservation alone is a distinct property. |
| Query bundles → MANA / UNHAL | Compatible consumers can share ephemeral source-bound work; public lane plans can avoid unnecessary observations. | Actual deterministic backend wiring and end-to-end measurement. K remains derived on demand. |

These feedback paths are developed in the [repository inventory](INNOVATION_INVENTORY.md) and [arithmetic/crypto connections](ARITHMETIC_CRYPTO_CONNECTIONS.md). They include specific source symbols and counterexamples where a premise matters.

## 3. Disparate domains and what they return to CRAM

The [external-domain report](DISPARATE_DOMAIN_CONNECTIONS.md) derives eight bridges, with [primary references](SOURCES.md). These are mathematical mappings with implementable questions, not a list of suggestive analogies.

| Domain | Exact shared structure | Return to the user's framework |
|---|---|---|
| Functional observability in control | Recover a requested linear state functional when it kills the unobservable subspace. | Choose correction/phase queries without recovering every hidden coordinate; add time-window observations only where needed. |
| Abstract execution and compilers | An observation admits exact abstract transitions precisely when its fibers are transition-stable. | Demand propagation, public basis planning, safe operator fusion and explicit refusal when information was lost. |
| Database view determinacy | A view determines a query when equal views imply equal query results. | Treat residue views as query resources; distinguish information sufficiency from an executable permitted rewrite. |
| Function-specific error correction | Correct the requested function when error balls for different answers are disjoint. | Design redundant anchors for consumer reliability; measure query-specific distance rather than demand full-state decoding. |
| Distributed merge / CRDTs | A quotient must be a congruence for the merge operation. | Prove which residue summaries can merge exactly; addition works under modular observation, unrestricted max generally does not. |
| Phase and gauge synchronization | Relative observations identify a state up to an invisible gauge; only gauge-invariant queries descend. | Source-aware phase references, cycle consistency and bounded lift selection. Consistency does not itself authenticate a source. |
| Sufficient statistics | Deterministic recovery is constancy on statistic fibers; statistical sufficiency is a different, model-dependent claim. | Specify exactly which output a compact residue statistic determines; avoid overclaiming privacy from compression. |
| Markov lumpability | An aggregated stochastic state is closed when transition probabilities to each block agree within blocks. | Model carry processes and stochastic execution with distributional closure; keep detailed balance, IID inputs and logical reversal distinct. |

The domain-specific theorems and algorithms have their own established literature. Their relevance does not establish or refute priority for the full CRAM architecture. The contribution to evaluate is the combination of authentic residue producers, concrete readouts, typed consumers, dynamic closure and resource-aware execution, with a matched implementation and evidence.

## 4. Concrete new research artifacts

The [anchor planner](reference/query_planner.py) handles affine modular consumers and floor-quotient consumers on all integers. It also pulls demand backward through affine operations. A useful new implementation detail is a factorization-free saturation rule:

\[
a_0=D/\gcd(P,D),\qquad a_{n+1}=\gcd(D,a_n^2).
\]

Its fixed point is the least sufficient additional anchor under divisibility. For P=12,D=18, the needed anchor is 9; adding 3 supplies no missing capacity. The proof and bit-cost scope are in [PLANNER_PROOFS.md](PLANNER_PROOFS.md).

The [future-query compiler](reference/future_query.py) constructs the coarsest sufficient partition of an explicit finite public model. It demonstrates both reduction and unavoidable growth: modulo-4 queries stay closed under affine dynamics on Z/16Z, whereas repeated halving makes parity reveal all four bits. This is a useful model checker for proposed topology/operator combinations before building their residue or encrypted implementation.

The prototypes consume public descriptions, never a secret source or a stored scalar winding. They establish planning/specification behavior. The current Rust runtime still needs an adapter; the arithmetic and ciphertext producer costs remain real.

## 5. Scope, provenance and next integration

This pass inspected the contribution families and named sources in the inventory, not every line or every branch of the repository. The supplied document corpus and prior proof packet remain available in `/workspace/k-elimination-audit` and `/workspace/CRAM Proofs`; this repository packet carries the complete 130-declaration mathematical foundation forward so its build is self-contained. It does not redistribute every uploaded private source archive into the repository.

The referenced Codex task `6af548dd-c6d8-8191-90ed-c6d29cf470cb` could not be read because this session exposes no `read_thread` tool. No conclusion here relies on that task's contents. Its dense snapshot is the explicit remaining source-coverage gap.

Current native encrypted refresh evidence, joint-key confidentiality status and legacy entry-point gates remain as described in [PUBLIC_REFRESH_STATUS.md](../../docs/PUBLIC_REFRESH_STATUS.md). No new encrypted refresh, performance benchmark, Rust-wide proof or security admission is claimed. The local research worktree is the delivery; no push or cloud upload has been performed.

The [execution plan](../../docs/execution/2026-11-12/UNIVERSAL_CROSS_POLLINATION.md) gives the next concrete gates: typed observation capabilities, public query planning, one actual producer-to-consumer workload, dynamic operator certificates, and an encrypted GCD integration. Each gate distinguishes the abstract proof, authentic producer, runtime refinement and measured cost.

## Reproduce and inspect

```sh
python3 research/universal-cross-pollination/verify.py
python3 research/universal-cross-pollination/lean/check_proofs.py --lean /path/to/pinned/lean
python3 research/universal-cross-pollination/lean/check_negative_controls.py --lean /path/to/pinned/lean
```

Use the pinned `leanprover/lean4:v4.27.0-rc1`; Python uses the standard library. The proof checker builds fresh temporary modules, audits every theorem's axioms and checks foundation provenance. See [formal proof details](lean/README.md), [independent review](REVIEW.md), and [execution evidence](evidence/verification.json).
