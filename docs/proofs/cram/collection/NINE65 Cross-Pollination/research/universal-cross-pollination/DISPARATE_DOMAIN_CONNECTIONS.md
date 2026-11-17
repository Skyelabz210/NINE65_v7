# Exact query transport across eight further domains

12 November 2026. Source snapshot: NINE65_v7 `88a7bdadbf0e1f8fbfdb2b37e9843101b8db3484`.

The strongest generalizable object is a **consumer-specific exact observation**, together with its constructive decoder and the laws that preserve it. This is more expressive than treating every application as full integer reconstruction. It also gives a systematic way to discover useful applications: find a domain in which the available information identifies the requested result while leaving irrelevant parts of the source ambiguous.

These connections extend the earlier ten-entry CRAM cross-innovation map. They are **written mathematical deductions and proposed integrations**, not additional machine-checked Lean declarations or executed cryptographic deployments. The universal fiber/kernel theorem is already checked in the separate proof package. The linked Codex task was unavailable through `read_thread`, so no claim here relies on its contents. Eight primary sources were fetched after ten searches returning 50 candidate results; this is a targeted mathematical investigation, not an exhaustive priority search. [SOURCES.md](SOURCES.md) records exactly what each source supports.

## The common theorem and the additional question

For any observation \(B:S\to O\) and query \(C:S\to T\), there is a uniquely determined decoder on the realizable image,

\[
D:B(S)\to T,\qquad D(B(s))=C(s),
\]

exactly when

\[
B(s)=B(s')\Longrightarrow C(s)=C(s'). \tag{F}
\]

For additive homomorphisms on a group this is \(\ker B\subseteq\ker C\). For restricted domains, noisy measurements, merge operations, probabilities or nonlinear evolution, use (F) on the actual domain. A decoder on an image need not extend to an arbitrary ambient observation, and existence does not supply an efficient executable constructor.

A second condition is needed to continue computing after projection. For a transition \(F:S\to S\), an induced transition \(\bar F\) exists precisely when

\[
B(s)=B(s')\Longrightarrow B(F(s))=B(F(s')). \tag{D}
\]

Then \(\bar F B=BF\), and induction gives \(\bar F^t B=BF^t\). This separates **query sufficiency now** from **sufficiency for a whole evolving program**. Both are useful; neither should silently substitute for the other.

| Domain | Observation and requested result | Useful return to CRAM/NINE65 |
|---|---|---|
| Control and sensing | Measured output history; desired state functional | Select anchors/sensors for a correction query, with an exact rejection witness |
| Compilers | Abstract residue state; next observable result | Backward information requirements and certified observation refinement |
| Databases | Materialized views; a new query | Safe ephemeral readout reuse and executable query rewrites |
| Distributed coding | Surviving encoded lanes; aggregate/function | Consumer-specific erasure and error resilience |
| Replicated state | Compressed replica; merged observable result | Distinguish valid arithmetic merges from invalid order/deduplication merges |
| Synchronization and geometry | Pairwise phases; gauge-invariant relative quantity | Graph-based phase-lock checks and reference-independent consumers |
| Statistical decision systems | Signal/statistic; action or target random variable | Preserve exactly the decisions a consumer needs without overstating privacy |
| Markov and stochastic dynamics | Coarse state; next coarse distribution | A precise test for whether an evolving abstraction is actually closed |

## 1. Functional observability: recover the required state functional

**External foundation.** Functional observability asks whether a specified function of a dynamical state can be inferred from its inputs and outputs without requiring the whole state. Zhang, Fernando and Darouach give definitions and general characterizations, including limitations of convenient eigenvalue tests [S1].

**Exact specialization.** Consider a discrete linear system over a field,

\[
x_{t+1}=Ax_t+Gu_t,\qquad y_t=Hx_t.
\]

Subtract the known input contribution from the output history. The remaining observation of \(x_0\) is

\[
B_qx_0=\mathcal O_qx_0,
\qquad \mathcal O_q=\begin{bmatrix}H\\HA\\\vdots\\HA^{q-1}\end{bmatrix}.
\]

The desired quantity is \(Cx_0=Lx_0\). Universal exact transport gives

\[
\ker\mathcal O_q\subseteq\ker L
\iff \operatorname{row}(L)\subseteq\operatorname{row}(\mathcal O_q)
\iff \exists D:\ D\mathcal O_q=L.
\]

The middle equivalence is finite-dimensional linear algebra; it also supplies an algorithm by solving for the rows of \(D\). The resulting runtime evaluates \(D\) on observed history rather than recovering every coordinate of \(x_0\).

**Example.** If the only observation of \((a,b)\) is \(a+b\), that total is exactly observable although the individual terms are not. If \(A=\operatorname{diag}(2,3)\), the next total is \(2a+3b\), which is not determined by the first total: \((1,0)\) and \((0,1)\) produce the same current total and different next totals. A second reading restores enough information. A query that is observable now need not remain observable under an arbitrary transition.

**What this unlocks externally.** Exact target monitoring in finite-field networked systems and integer/rational models can spend sensing effort on a load total, invariant or control correction rather than a full state estimate. Real-valued sensor noise and numerical conditioning require a separate stable estimation theory; algebraic rank alone does not provide it.

**What returns to NINE65.** Treat every proposed phase, shadow and correction channel as a sensor for a declared consumer. A public planner can return either a certificate \(DB=C\), or an ambiguity witness \(v\in\ker B\) with \(Cv\ne0\). This gives a more informative refusal than “insufficient magnitude.” For integer modules, use congruence/kernel calculations rather than field rank over a composite ring. The candidate attachment points are [`compiler.rs`](../../crates/nine65/src/compiler.rs), [`anchor.rs`](../../crates/cram-core/src/anchor.rs) and [`phase_lock.rs`](../../crates/cram-core/src/phase_lock.rs). The compiler is currently a heuristic circuit/noise planner; this exact query analysis would be a separate pass.

## 2. Complete abstract execution: compile backwards from consumers

**External foundation.** Abstract interpretation distinguishes sound approximations from complete ones. Giacobazzi and Ranzato explicitly study completeness equations and systematic refinement of abstract domains [S2]. A residue projection can be an exact abstraction for some operations even when it loses source information.

**Exact specialization.** Let \(\alpha:S\to A\) encode the available abstract state. An exact abstract implementation of a primitive \(F\) satisfies

\[
F^\sharp\alpha=\alpha F.
\]

By (F), such an implementation exists precisely when equal abstract inputs have equal abstract outputs. For a binary operation use the product observation \((\alpha x,\alpha y)\). Modular addition and multiplication satisfy this law; exact integer comparison, flooring and division do not automatically satisfy it on an unbounded domain.

**Concrete obstruction and refinement.** Observation \(x\bmod6\) cannot compute \(\lfloor x/2\rfloor\bmod6\): \(x=0\) and \(x=6\) have identical observations and outputs 0 and 3. Observation modulo 12 suffices, because

\[
\left\lfloor\frac{x+12j}{2}\right\rfloor
=\left\lfloor\frac{x}{2}\right\rfloor+6j.
\]

More generally, for positive integers \(c,b,P\), the all-integer observation \(x\bmod P\) determines \(\lfloor x/c\rfloor\bmod b\) exactly when \(cb\mid P\), apart from the trivial target \(b=1\), where every observation suffices. To prove necessity for \(b>1\), write \(P=ac+r\), \(0\le r<c\). If \(r>0\), the changes in the quotient when replacing \(x\) by \(x+P\) take both values \(a\) and \(a+1\); they cannot both be divisible by \(b\). Thus \(r=0\), and then \(b\mid a\). Sufficiency follows from the displayed identity with \(P=cbj\). This is a useful whole-primitive information requirement, distinct from the cost of a unit K readout.

**Backward consumer rule.** If the final consumer is \(Q\), the observation needed before \(F\) need only determine \(Q\circ F\). It need not determine \(F\) completely. For a DAG, combine the queries demanded by outgoing edges, and propagate their composed queries backward. At each node refine observations until those queries satisfy (F), or reject with a counterexample. Loops additionally need an invariant and a preservation argument.

**External opportunities.** This supplies exact compressed execution for modular DSP, finite-state verification and specialized arithmetic accelerators. It is particularly useful when a computation returns a small predicate or residue rather than its entire intermediate state.

**Return to NINE65.** Couple consumer requirements to the existing public DAG and choose authentic anchors before any needed distinction is discarded. This can reduce unnecessary high-range intermediates in an encrypted circuit. A second pass may then lower a proven query to actual supported ciphertext operations. The abstract proof does not supply protected remainder producers or imply lower FHE depth without a realized circuit and measurement. Never generate an unavailable view from an insufficient residue state and label it refinement.

## 3. Database views: exact query rewriting and source-bound caching

**External foundation.** Nash, Segoufin and Vianu define view determinacy by exactly the implication (F), and carefully distinguish it from rewriting the query in an executable language [S3]. This is a direct mathematical identification, not just a resemblance.

**Exact specialization.** Let a database instance be \(s\), available views be \(V(s)\), and a requested answer be \(Q(s)\). The equation \(Q=D\circ V\) exists on realized views exactly when \(V(s)=V(s')\) implies \(Q(s)=Q(s')\). For a linear data vector \(x\), materialized aggregates \(Ax\), and another aggregate \(Lx\), the condition reduces to \(\ker A\subseteq\ker L\).

For integer count views modulo \(m_i\), their joint period is the LCM, not generally the product. A count modulo \(b\) is an exact rewrite precisely when \(b\) divides that period on the unrestricted integer domain. For example, views modulo 4 and 6 determine a count modulo 12 and modulo 3, but not modulo 5. The counts 1 and 13 give the same input views and disagree modulo 5.

**What this unlocks externally.** Modular exact aggregates can be served from existing materialized observations; a consumer-specific update can sometimes be processed without reconstructing a full table or count. Nonlinear joins, ordering and query-language restrictions still need their own determinacy and rewriting analysis. General determinacy is not a universal efficient decision procedure.

**Return to NINE65.** Regard an authentic observation as a materialized arithmetic view. A transient K readout can be reused by several consumers during an operation if all consumers carry the same source/reference/epoch binding. Store the *proof of the rewrite* and public metadata; keep the derived coordinate ephemeral under the CRAM state policy. An arithmetic identity does not validate a stale cache entry after mutation. [`CramState`](../../crates/cram-core/src/lib.rs), [`cram_ct_wrap.rs`](../../crates/nine65/src/cram_ct_wrap.rs) and the existing canonical-root documentation provide places to specify those bindings, not proof that they currently implement this proposed cache.

**Privacy boundary.** A public view that determines a supposedly secret query reveals that query exactly. A view that fails to determine it merely leaves ambiguity; it can still reveal most information or identify the result under a concentrated prior. Query non-determinacy is not an encryption or differential-privacy theorem.

## 4. Distributed and error-correcting computation: protect the function

**External foundation.** Appuswamy, Franceschetti, Karamchandani and Zeger study computing demanded functions over networks, explicitly separating this from recovering all source messages [S4]. Their topology and capacity results are additional constraints; a local decoder factorization alone does not solve every network-coding problem.

**Erasure specialization.** A source \(x\in\mathbb F_q^n\) is encoded across lanes as \(Bx\). If a set of lanes \(E\) survives, its readings are \(B_Ex\). A requested linear result \(Cx\) remains recoverable exactly when

\[
\ker B_E\subseteq\ker C.
\]

To tolerate every \(e\) erasures, verify this for every allowed survivor set. This may hold for the requested aggregate even if full source recovery fails for all such sets.

**Written deduction — consumer-specific error distance.** For a finite admitted source set \(S\) and alphabet-valued observation \(B\), define

\[
d_C(B)=\min_{C(x)\ne C(x')} d_H(Bx,Bx').
\]

If \(C\) is constant, no observation is needed; otherwise take the minimum over unequal target values. Exact correction of every pattern of at most \(e\) changed observation symbols is possible if and only if

\[
d_C(B)>2e.
\]

Proof: the Hamming balls of radius \(e\) around observations with different answers must be disjoint. Distance greater than \(2e\) is sufficient by the triangle inequality. If the distance is at most \(2e\), a word can be formed by splitting the differing coordinates between the two observations, placing it in both balls; no deterministic decoder can answer both sources correctly. Candidate sources with the same target answer need not be distinguished.

**Example.** Over \(\mathbb F_5\), transmit three copies of \(a+b\). The target \(a+b\) has distance 3 and tolerates one erroneous lane by majority. The pair \((a,b)\) remains unrecoverable. This realizes function-specific robustness with a tiny example; it does not establish an optimal code.

**External opportunities.** Coded sensor aggregation, worker-straggler tolerance and robust modular checks can protect exactly the requested function. In an integer RNS variant, apply the same finite-domain distance definition to actual residue tuples; overlapping anchors need not behave like independent field coordinates.

**Return to NINE65.** Let MANA/UNHAL select a sufficient subset of completed lanes for an explicitly certified consumer, or add redundant observations for fault detection. [`mana::executor`](../../crates/mana/src/executor.rs) currently executes deterministic indexed lanes and expects each result; early completion or fault tolerance is a proposed extension. Mathematical error correction does not authenticate adversarial worker results or replace source provenance. Cost includes coding, lane work, decoding and communication, not only K-Elimination's constant-operation readout.

## 5. Replicated state: a quotient must preserve merge

**External foundation.** Shapiro, Preguiça, Baquero and Zawirski give sufficient convergence conditions for state-based and operation-based CRDTs: semilattice merges or appropriately delivered commuting operations [S5]. Modular arithmetic by itself does not provide those protocol laws.

**Exact specialization.** Suppose source states merge by \(\sqcup\). A compressed observation \(B\) admits a well-defined merge exactly when

\[
B(s)=B(s'),\ B(t)=B(t')
\Longrightarrow B(s\sqcup t)=B(s'\sqcup t').
\]

If this holds, define \(\bar\sqcup(Bs,Bt)=B(s\sqcup t)\). If the original merge is associative, commutative and idempotent, those laws pass to the image by choosing representatives. This is the binary-operation version of (F); it applies to a semilattice without requiring additive inverses.

**Sharp obstruction.** A grow-only counter component merges by maximum. Reducing its value modulo 5 cannot preserve that merge: 0 and 5 both map to 0, but merging each with 3 gives 3 and 5, whose residues are 3 and 0. A modular counter is closed under addition, but not under a maximum merge. Similarly, addition is not idempotent, so duplicate delivery can alter its result.

**External opportunities.** A distributed system can maintain an exact compressed query whenever both the query and merge descend to the chosen quotient. Where they do not, it needs additional causal/version information, a different merge, or a domain restriction. This is a useful architecture-selection theorem rather than a claim that residues solve consensus or deduplication.

**Return to NINE65.** The private-feedback residue aggregation path can use associative modular addition for disjoint contribution sets. A future distributed ingestion service must still prove whether contributions are disjoint, deduplicated, or delivered exactly once. Event identities and causal metadata are protocol state, not a scalar winding ledger; retaining them does not require persisting K. [`ResidueSignal::add_assign`](../../crates/private-feedback-core/src/lib.rs) is an arithmetic attachment point, not a CRDT implementation. This connection prevents an otherwise subtle error when expanding exact encrypted aggregation across replicas.

## 6. Phase synchronization and geometry: gauge-invariant consumers

**External foundation.** Singer formulates angular synchronization from pairwise offsets and proves the exact-data connected-graph recovery property up to a common phase [S6]. The noisy estimator and its stability are further analytic results, separate from the following exact algebra.

**Exact specialization.** Take an oriented graph and an additive abelian group \(G\). A vertex phase assignment \(\theta\in G^V\) is observed through edge differences

\[
(B\theta)_{(u,v)}=\theta_v-\theta_u.
\]

The kernel consists precisely of assignments constant on each connected component: zero edge differences propagate along paths, and componentwise constants produce zero edges. Therefore a target query is recoverable exactly when it ignores these componentwise shifts. In a connected graph, \(C\theta=\theta_v-\theta_u\) is recoverable by summing edge readings along any path; an absolute \(\theta_v\) is not recoverable without an anchor.

**Authenticity versus consistency.** For purported exact edge readings, zero signed sum around every cycle is necessary and sufficient for a global phase assignment on each component. Necessity follows by telescoping; sufficiency follows by path integration and path independence. This certifies arithmetic consistency. A malicious party can still supply a different globally consistent assignment, so cycle checks do not authenticate the original source.

**Additional integer lift.** If edges are observed modulo \(A\), the reconstructed relative phase is only modulo \(A\). A public admissible interval of width at most \(A\) can select a unique integer difference, exactly as in StarLift. A common global shift and an integer wrapping ambiguity are different freedoms and require different certificates.

**External opportunities.** Clock synchronization, interferometric phase networks, relative localization and robotic map coordinates naturally ask gauge-invariant questions. A finite cyclic phase model is exact; a physical real-valued clock or pose additionally requires calibration, noise and geometric modeling. Nonabelian rotation/pose groups need an action-based generalization, not the additive formula applied unchanged.

**Return to NINE65.** A graph of reference changes and phase locks can expose a consumer without choosing an absolute coordinate everywhere. Independent cycles can check consistency of authentic epoch-linked increments. The actual [`Shadow11Plan::verify_successor`](../../crates/cram-core/src/phase_lock.rs) already distinguishes arithmetic checks from source/epoch binding. The proposed graph checker would preserve this distinction and derive K only on demand. This offers a concrete bridge between transduction, reference-change invariance and distributed execution topology.

## 7. Statistics and decision systems: exact task information is not full sufficiency

**External foundation.** Blackwell studies comparison of statistical experiments through attainable decisions and transformations between experiments [S7]. Statistical sufficiency involves an entire family of probability laws. It must not be conflated with the deterministic factorization of one query.

**Exact deterministic statement.** On a finite source set, let \(X\) be any random source, \(Z=B(X)\), and \(Y=C(X)\). If (F) holds, \(Y=D(Z)\) almost surely for every law of \(X\). Conversely, if it fails at \(x,x'\), place positive probability on those two sources: the same observed value has two different target values. Hence exact recoverability for every source law is equivalent to the pointwise fiber criterion. The decoder can then support every decision whose loss depends on the source only through \(Y\).

**Why statistical sufficiency differs.** For two independent Bernoulli samples with parameter \(\theta\), their sum \(T=X_1+X_2\) is sufficient for \(\theta\): conditional on \(T=1\), the two orderings are equally probable, independently of \(\theta\); the other sums determine their ordering trivially. But \(T\) does not recover the ordered sample or \(X_1\). Conversely, a representation that preserves one chosen deterministic answer need not preserve information relevant to estimating every parameter.

**Decision-specific observation.** Suppose a deterministic policy is \(\pi:S\to A\). It can run exactly on an observation \(B(s)\) iff \(\pi\) is constant on its fibers. This can be much weaker than preserving the whole source. A policy change may invalidate the old representation; observation requirements must be recomputed for the new policy.

**External opportunities.** Task-specific sensor selection, exact decision caches and model interfaces can use this criterion to retain only distinctions affecting a prescribed action. This alone says nothing about the accuracy of the policy itself or about Bayes-optimality under a new distribution.

**Return to NINE65.** [`select_next_question`](../../crates/private-feedback-core/src/lib.rs) uses a structured `FollowupState` rather than arbitrary raw feedback. Its next question is determined by those fields by construction; whether the classification from raw feedback is adequate is a separate producer question. For encrypted analytics, first specify the desired aggregate or decision, then prove the residue observation suffices. This can prevent unnecessary exposure of exact magnitudes while preserving the chosen answer. It does not constitute a confidentiality theorem: probabilistic leakage, correlated evaluation keys and access patterns remain separate questions.

## 8. Markov lumpability: when compressed dynamics remain closed

**External foundation.** Kemeny and Snell's combining-states theorem gives necessary and sufficient conditions for a partition of a finite Markov chain to define a Markov chain for every initial distribution [S8]. This is a rigorous way to test an evolving coarse description, including claims about screened or hidden state.

**Exact specialization.** Let \(P\) be a row-stochastic matrix on finite states, and let \(R\) be the 0–1 matrix mapping each state to its partition block. A row distribution \(\mu\) is observed as \(B(\mu)=\mu R\). The next observed distribution is \(C(\mu)=\mu PR\). There is a stochastic quotient transition \(Q\) with

\[
PR=RQ \tag{L}
\]

exactly when, for every block pair \(A_i,A_j\),

\[
\sum_{z\in A_j}P(x,z)
\quad\text{is independent of }x\in A_i.
\]

Proof: the left side is \((PR)_{x,j}\); if constant on source blocks it defines \(Q_{i,j}\), whose entries remain nonnegative and whose row sums are one. Conversely (L) forces those equalities. By induction,

\[
P^tR=RQ^t,
\qquad (\mu P^t)R=(\mu R)Q^t.
\]

Thus the coarse representation evolves exactly without retaining the fine state. On the vector space of signed row measures, this is the kernel criterion for \(B(\mu)=\mu R\) and \(C(\mu)=\mu PR\), with positivity and stochasticity supplied by the block construction.

**Obstruction.** If two fine states in the same observed block have different probabilities of entering another observed block, the next coarse distribution depends on hidden information. For example, merge states \(a,b\), keep \(c\) separate, and let \(a\to c\) with probability 1 while \(b\to b\) with probability 1. Starting at \(a\) or \(b\) gives the same coarse present and different coarse futures. Memory or a finer observation is then required.

**External opportunities.** Exact model reduction for chemical reaction networks, population dynamics, queueing, and finite stochastic controllers can preserve specified observables while reducing state space. Approximate lumpability requires an explicit error theory. A box-ball transition is normally deterministic; its quotient instead uses (D), or the degenerate 0–1 stochastic case. A real continuum/PDE limit does not follow from either finite quotient statement.

**Return to NINE65.** This supplies a precise acceptance test for a proposed “screening” state or learned compressed runtime model: prove equal future observable distributions for every pair of admitted states sharing the observation. If only a deterministic arithmetic circuit is involved, prove the simpler commuting square. This distinction can turn broad claims of operational closure into compositional proof obligations and identify exactly which extra anchor or retained metadata fixes a failure. No inspected current NINE65 Markov implementation is asserted here.

## Three research directions justified by these connections

1. **A consumer-directed observation compiler.** Represent requested queries and observation contracts, propagate requirements backward through a DAG, and emit a constructive decoder or a separating pair. The control, abstract-execution and database formulations provide three independently useful views of the same proof obligation. Integrate public anchor selection only after an authentic producer is identified.
2. **An error-aware observation contract.** Extend exact fiber certificates to finite admitted sets with query distance, allowed erasures and source/epoch binding. This could let a future MANA executor choose redundant work for the actual consumer rather than demanding reconstruction of all intermediate information. The first prototype should exercise the finite-field and bounded-RNS distance criteria with corruptions and erasures; an optimal coding claim would require separate work.
3. **An operation-preserving transduction checker.** Require each transition, merge and reference change to commute with its observation maps. This joins CRDT congruence, gauge invariance and stochastic lumpability into a reusable test of composition. Use the appropriate algebra for each operation; a semilattice, a probability kernel and an additive group are related by factorization but are not interchangeable structures.

These are concrete candidates for contributions of the CRAM/NINE65 integration. The cited domains already contain their own factorization and reduction theories; identifying a shared algebraic ingredient does not settle priority for the complete CRAM construction. A defensible contribution statement should identify the authentic observation architecture, constructive readouts, admissible domains, consumer-driven planning and cross-component proofs actually supplied. Priority and performance need claim-specific comparisons and measured implementations.
