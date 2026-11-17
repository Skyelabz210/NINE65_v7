# CRAM K-Elimination, Lifts, and Exact Reconstruction
## A Comprehensive Technical Compendium for Fixed-Frame, Zero-Float, Elimination-First Arithmetic

**Prepared for:** Anthony Diaz (Acid)  
**Scope:** CRAM threaded consolidation, StarLift, K-Elimination formal sources, CRAM corpus, NINE65_v7, Dual Codex, Shadow Disambiguation, and the supplied RTL artifact.  
**Document status:** **Normative synthesis with a source-status ledger.** The threaded zero-float documents govern all conflicts. Historical mechanisms and external application claims are retained, but they are not silently promoted to core guarantees.  
**Date:** 13 August 2026

---

## Abstract

This compendium consolidates every documented **lift**, every material **use of K-Elimination**, and every identifiable **reconstruction or materialization pathway** in the supplied CRAM/QMNF corpus. The governing result is elementary but architecturally consequential: for a fixed modulus $M$, every integer has a unique residue–lift decomposition

\[
X=r_M(X)+M K_M(X),\qquad 0\le r_M(X)<M.
\]

A residue gives the coordinate in a finite fundamental domain, while $K_M$ identifies the selected sheet of the integer-line cover. K-Elimination observes that lift through a coprime anchor. With authentic residues modulo $M$ and $A$, it computes $K_M(X)\bmod A$ exactly. The 36/37 StarLift is the adjacent-modulus specialization in which the inverse multiplication collapses to a single modular subtraction. It provides **constant fixed-width latency** and complete reconstruction **only** inside its certified capacity window $0\le X<36\cdot37=1332$. Outside that window, the same arithmetic returns a quotient residue, not an unbounded quotient. [1] [2] [4] [5]

The resulting architecture is therefore not “one subtraction reconstructs every integer.” It is a rigorously bounded hierarchy:

\[
\boxed{
\text{authentic phase residue}
+\text{anchor-observed lift residue}
+\text{capacity certificate or epoch}
=\text{exact reconstructible integer state}.
}
\]

This document distinguishes what is **CORE-PROVEN**, what is **CORE-CONDITIONAL**, what is a **boundary or architectural method**, and what remains **OPEN**. It also corrects several recurrent category errors: a local K-Elimination coordinate is not a Garner digit; a fixed anchor ladder cannot encode an unbounded quotient without an epoch; a shadow prime is not automatically an independent CRT coordinate; and a hardware resolver without a capacity certificate outputs $K\bmod A$, not necessarily $K$. [1] [2] [3]

---

## 1. Authority, notation, and conformance discipline

### 1.1 Source hierarchy

The current threaded consolidation is the controlling authority. It explicitly retires runtime Garner/mixed-radix reconstruction, requires a fixed authentic frame, prohibits synthetic residue emissions and runtime DynCRT lane creation, and separates deterministic arithmetic from external probability models. Earlier CRAM documents remain valuable as historical, architectural, test, and application sources, but must be reclassified when they conflict with those rules. [1] [3]

| Authority tier | Sources | How this compendium uses them |
|---|---|---|
| **Normative core** | Threaded Master Index; Threads 1–6; Reconciled Normative Kernel | Defines what the trusted core may claim and execute. |
| **Exact mathematical and executable sources** | `starlift.py`; covering-coordinate paper; Lean/Coq source artifacts; validation results | Supplies identities, finite test oracles, and formal-source statements. |
| **CRAM architecture and applications** | CRAM chapters 06–09, 14–16, A-07 | Identifies K-Elimination uses, companion methods, and hypothesis boundaries. |
| **NINE65 implementation/benchmark record** | NINE65_v7 architecture, audit, and baseline benchmarks | Maps the mechanism to current code paths and measured software implementations. |
| **Historical/reference methods** | Classical direct CRT, Garner/MRC, older Dual Codex alternatives | Included for comparison, proof or test oracles, and migration context; not runtime-core mechanisms. |

> **Core rule.** Every trusted arithmetic lane must be either a direct exact residue of the represented value or an explicitly invertible transform with a stated relation to that value. A synthetic, inferred, randomized, approximate, or lossy lane is not a trusted arithmetic lane. [1]

### 1.2 Exact domains

The trusted domains are integers $\mathbb Z$, residue rings $\mathbb Z/m\mathbb Z$, and—when division cannot be represented as an integer—normalized rational pairs $(a,b)$ with $b>0$ and $\gcd(a,b)=1$. No trusted transition may depend on IEEE-754 values, tolerance tests, approximate phases, similarity scores, phasors, or numerical convergence. [1] [3]

| Conformance predicate | Required interpretation |
|---|---|
| $\mathsf{Exact}$ | Every arithmetic step is an exact integer, modular, or normalized-rational operation. |
| $\mathsf{Authentic}$ | Every resulting lane is a direct reduction of the represented value, or a proved reversible coordinate of it. |
| $\mathsf{Reversible}$ | A core transition is bijective on a stated valid domain and provides an inverse witness. |
| $\mathsf{CapacitySafe}$ | Each quotient is either range-bounded, ladder-resolved, or epoch-tracked. |
| $\mathsf{DiagnosticSeparate}$ | A read-only diagnostic cannot alter the arithmetic value. |
| $\mathsf{IIDScoped}$ | Any IID statement names its external ensemble and its exact recurrence. |

---

## 2. The foundational residue–lift representation

### 2.1 Single-modulus arithmetic lift

Fix an integer modulus $M\ge2$ and use the least-nonnegative section

\[
r_M(X)\in\{0,1,\ldots,M-1\},\qquad r_M(X)\equiv X\pmod M.
\]

Define

\[
K_M(X)=\frac{X-r_M(X)}{M}\in\mathbb Z.
\]

Then the division algorithm gives the exact identity

\[
\boxed{X=r_M(X)+M K_M(X).}\tag{2.1}
\]

For nonnegative $X$, $K_M(X)=\lfloor X/M\rfloor$. Equation (2.1) is not merely a reconstruction formula: it separates the finite phase coordinate from the discrete lift sheet. The residue projection forgets the sheet; $K_M$ restores it. [1] [4]

| Object | Mathematical role | What it does **not** claim |
|---|---|---|
| $r_M(X)$ | Exact coordinate in the finite cycle $\mathbb Z/M\mathbb Z$ | It does not identify the unbounded integer without a lift. |
| $K_M(X)$ | Arithmetic lift/sheet coordinate | It is not, by itself, a topological winding number. |
| $(r_M,K_M)$ | Exact integer coordinate system | It does not imply a unique extended provenance/diagnostic state. |
| $X\mapsto r_M(X)$ | Projection to the finite cycle | It is necessarily many-to-one on $\mathbb Z$. |

### 2.2 Fixed-frame CRT residue–lift state

Let $B=(m_1,\ldots,m_k)$ be pairwise coprime, let $M_B=\prod_i m_i$, let $R_B=\prod_i\mathbb Z/m_i\mathbb Z$, and let $\gamma_B:R_B\to[0,M_B)$ be the unique CRT representative. The canonical core state is

\[
V_B=(r,K)\in R_B\times\mathbb Z,
\qquad
\nu_B(r,K)=\gamma_B(r)+M_BK.
\tag{2.2}
\]

For a **fixed** frame, $\nu_B$ is a bijection from $R_B\times\mathbb Z$ to $\mathbb Z$. Thus a full unbounded integer is exactly represented when both the residue tuple and the lift coordinate are retained. The direct CRT representative $\gamma_B(r)$ may be evaluated in a proof or at a boundary, but it need not be a hot-path operation. [1] [3]

> **The capacity point.** A residue tray alone identifies one representative modulo $M_B$, not one point on the unbounded integer line. The integer ambiguity is precisely $X, X+M_B, X+2M_B,\ldots$.

### 2.3 Trajectory lift and genuine winding

For a time-indexed trajectory $X_0,\ldots,X_T$, interpolate the lift $X_t/M$ linearly and then reduce modulo one to obtain the canonical circle path. If $r_M(X_T)=r_M(X_0)$, the projected path closes and

\[
\operatorname{wind}=K_M(X_T)-K_M(X_0)
=\frac{X_T-X_0}{M}.
\tag{2.3}
\]

This is the exact point at which “winding” has its usual topological meaning. A static quotient coordinate is an arithmetic lift; only the endpoint change of an explicitly specified lifted closed trajectory is a path winding. [4]

For a scalar trajectory projected through a CRT frame, a closed tuple has $X_T-X_0=\ell M_B$, and the lane-winding vector is constrained to

\[
\mathbf W=\ell\left(\frac{M_B}{m_1},\ldots,\frac{M_B}{m_k}\right).
\tag{2.4}
\]

Hence scalar trajectories realize a rank-one sublattice of the full torus winding group. The lane winding coordinates are not independently free variables. [4]

---

## 3. Complete lift taxonomy

The following table enumerates every material lift or lift-adjacent coordinate identified in the supplied sources. “Core status” records the result **after** applying the threaded normative kernel.

| ID | Lift or coordinate | Exact definition | Primary function | Capacity / precondition | Core status |
|---|---|---|---|---|---|
| L1 | **Fixed-frame canonical lift** | $X=\gamma_B(r)+M_BK$ | Exact unbounded integer state | Fixed pairwise-coprime frame; retained $K$ | CORE-PROVEN |
| L2 | **Single-modulus lift** | $X=r_M+MK_M$ | Residue plus sheet coordinate | Chosen residue section | CORE-PROVEN |
| L3 | **Covering-path lift** | $\widetilde\theta(t)=X_t/M$ | Makes trajectory winding well-defined | Explicit time path and interpolation | CORE-CONDITIONAL |
| L4 | **CRT torus lift** | $(X_t/m_1,\ldots,X_t/m_k)$ | Shows rank-one scalar winding structure | Pairwise coprime frame, scalar trajectory | CORE-PROVEN |
| L5 | **Generic anchor lift observation** | $\kappa_A=K_M\bmod A$ | Observes base lift through a coprime anchor | Authentic $r_M,r_A$ and $\gcd(M,A)=1$ | CORE-PROVEN |
| L6 | **Consecutive-pair adjacency lift** | $K\bmod(M+1)=(r_M-r_{M+1})\bmod(M+1)$ | Eliminates inverse multiplication | Consecutive authentic moduli | CORE-PROVEN |
| L7 | **36/37 StarLift** | Shell $36$, anchor $37$, $\kappa=(r_{36}-r_{37})\bmod37$ | Fast bounded magnitude recovery | Full $K$ only if $K<37$ | Congruence CORE-PROVEN; full reconstruction CORE-CONDITIONAL |
| L8 | **Star-number geometric lift** | $S_n=6n(n-1)+1=\operatorname{ring}(n)+1$ | Identifies the selected shell/anchor geometry | Arithmetic identity; not a universal RNS reconstruction theorem | CORE-PROVEN identity |
| L9 | **Anchor-ladder lift** | $\widehat K=K\bmod C$, $C=\prod_jA_j$ | Multiplicatively extends certified lift range | Static pairwise-coprime authentic anchors | CORE-CONDITIONAL |
| L10 | **Overflow epoch lift** | $K=QC+\widehat K$ | Preserves unbounded lift history | Exact capacity carries and retained epoch $Q$ | CORE-PROVEN |
| L11 | **Recombinant CRT winding** | Tuple/lane winding accompanies a residue tuple | Stores overflow history through operations | Exact counter update contract | CORE-CONDITIONAL |
| L12 | **Phase-lock coordinate** | $D_a=r_a-r_A-A\kappa_a\equiv0\pmod a$ | Tests common lifted interpretation across lanes | Fixed authenticated base/anchor update equations | CORE-CONDITIONAL diagnostic |
| L13 | **Input-retaining reversible embedding** | E.g. $(x,y,z)\mapsto(x,y,z+x+y)$ | Lifts a non-bijective value operation into reversible state space | Inputs or an inverse witness retained | CORE-PROVEN pattern |
| L14 | **Dual Codex magnitude coordinate $\beta$** | $\alpha(X)=\rho_B(X)$, $\beta(X)=X$ | Maintains residue and explicit magnitude representations in parallel | Compatibility invariant $\alpha=\beta\bmod B$ | ARCHITECTURAL / boundary |
| L15 | **Shadow/check coordinate** | Fixed redundant residue or signature such as the 11-lane record | Disambiguation/integrity observation | Must be an authentic fixed check, not an inferred lane | CORE-CONDITIONAL diagnostic |
| L16 | **FPD auxiliary reference coordinate** | Auxiliary coprime-lane observation for shared-factor division | Supports a specialized quotient extraction route | Requires a static, authentic, frame-safe auxiliary protocol | BOUNDARY pending conformance proof |

The key separation is structural: L5–L10 carry **integer magnitude information**; L11 preserves overflow state; L12 and L15 are **integrity observations**; L13 is a reversible-state construction; and L14 is an explicitly maintained parallel magnitude representation. These must not be conflated. [1] [2] [3] [12]

---

## 4. Generic K-Elimination as modular lift observation

### 4.1 The theorem

Suppose $M$ and $A$ are coprime and

\[
X=r_M+MK,
\qquad
r_M=X\bmod M,
\qquad
r_A=X\bmod A.
\]

Reduction modulo $A$ gives

\[
r_A\equiv r_M+MK\pmod A.
\]

Since $M$ is a unit modulo $A$,

\[
\boxed{
\kappa_A(X)=
(r_A-r_M)M^{-1}\bmod A
=K\bmod A.
}
\tag{4.1}
\]

This is K-Elimination in its most rigorous and minimal form: **a coprime anchor observes the base lift coordinate modulo that anchor**. It is exact as a congruence. It does not use, require, or imply a mixed-radix cascade. [1] [2] [4] [6]

### 4.2 Capacity-alias theorem

One anchor cannot identify an unbounded lift. For every $X=r_M+MK$,

\[
X'=X+MA=r_M+M(K+A)
\]

has the same residues modulo both $M$ and $A$:

\[
X'\equiv X\pmod M,
\qquad
X'\equiv X\pmod A.
\]

Thus any method using only $(r_M,r_A)$ returns the same output for $K$ and $K+A$. It can determine at most $K\bmod A$. Complete recovery follows only after choosing the canonical representative via the range certificate

\[
0\le K<A.
\tag{4.2}
\]

This is an information boundary, not an implementation weakness. It is the direct reason that a runtime status must distinguish `EXACT`, `RESIDUE_ONLY`, `OVERFLOW_EVENT`, and `AMBIGUOUS`. [2] [3]

### 4.3 Generic fixed-width cost

For fixed machine-width $M$ and $A$, equation (4.1) is constant-latency hardware architecture: a modular difference followed by multiplication by a precomputed inverse and reduction. The term “$O(1)$” is valid **only in the fixed-width architectural sense**. It is not a claim that arbitrary-precision reconstruction, unbounded anchor capacity, or unbounded epoch arithmetic has constant bit complexity. [2] [3]

| Claim | Correct formulation |
|---|---|
| “K-Elim is O(1)” | One fixed-width resolver has fixed latency for preprovisioned constants. |
| “An anchor ladder is O(1)” | A fixed number of parallel anchors can maintain one-result-per-cycle throughput; area grows with anchor count. |
| “Unbounded reconstruction is O(1)” | False. Capacity, epoch width, and/or number of anchors must grow with magnitude. |
| “K-Elim removes every multiplication” | False. Only adjacent moduli provide the subtraction collapse. |

---

## 5. The consecutive-modulus family and the 36/37 StarLift

### 5.1 Consecutive-pair identity

For $A=M+1$,

\[
M\equiv-1\pmod A,
\qquad M^{-1}\equiv-1\pmod A.
\]

Substituting into equation (4.1) yields

\[
\boxed{
K\bmod(M+1)=(r_M-r_{M+1})\bmod(M+1).
}
\tag{5.1}
\]

The inverse multiplication has collapsed to a sign reversal, represented by a subtraction. This holds for every consecutive pair $(M,M+1)$ with authentic residues. [2] [3]

### 5.2 The selected 36/37 fast path

The StarLift implementation selects

\[
M=36,
\qquad A=37,
\qquad 36\equiv-1\pmod{37}.
\]

The implementation’s centered-hexagram identity is

\[
S_n=6n(n-1)+1=\operatorname{ring}(n)+1,
\]

with the selected shell/anchor relation

\[
\operatorname{ring}(3)=36,
\qquad 36+1=37.
\]

Therefore

\[
\boxed{
\kappa_{37}(X)=(r_{36}-r_{37})\bmod37.
}
\tag{5.2}
\]

When $0\le K<37$, the residue class has one representative in the range and

\[
K=\kappa_{37}(X),
\qquad
\boxed{X=r_{36}+36\kappa_{37}(X).}
\tag{5.3}
\]

The exact window is

\[
0\le X<36\cdot37=1332.
\tag{5.4}
\]

The phrase “one modular subtraction reconstructs the number in $O(1)$” is therefore mathematically correct **only** when it includes the capacity certificate in equation (5.4). Without it, the same operation correctly reports only $K\bmod37$. [1] [2] [5]

### 5.3 Finite-set bijection and IID scope

On the product set $\mathbb Z/36\mathbb Z\times\mathbb Z/37\mathbb Z$, the map

\[
\phi(r,s)=(r,(r-s)\bmod37)
\]

is bijective, with inverse $\phi^{-1}(r,k)=(r,(r-k)\bmod37)$. Thus product-uniform $(r,s)$ maps to product-uniform $(r,k)$. This is an exact finite counting result. It does **not** state that a deterministic hardware trajectory produces IID data by itself; IID requires the separate external product-uniform input model defined in the threaded documentation. [2] [3]

### 5.4 Star-prime ladder: capacity, not universal adjacency

The executable StarLift source also constructs a coprime ladder from star primes and demonstrates that one anchor returns only the corresponding quotient residue. In its example, two anchors $37$ and $73$ have product $2701$ and can recover a quotient $K=975$ because $975<2701$. [5]

However, the subtraction-only property belongs to the adjacency pair $36/37$. A higher anchor such as $73$ is not adjacent to the base $36$ and generally requires the generic inverse multiplication in equation (4.1). The ladder extends range multiplicatively; it does not automatically preserve the one-subtraction microkernel at every rung. [2] [3]

---

## 6. Ladder capacity, Star-CRT merging, and overflow epochs

### 6.1 Fixed anchor ladder

Let $A_1,\ldots,A_s$ be pairwise coprime anchors, each coprime to the fixed base $M$. Per-anchor elimination computes

\[
\kappa_j=K\bmod A_j.
\]

The ladder capacity is

\[
C_s=\prod_{j=1}^{s}A_j,
\]

and an exact CRT merge produces

\[
\widehat K=K\bmod C_s.
\tag{6.1}
\]

The result is fully exact only if

\[
0\le K<C_s.
\tag{6.2}
\]

The ladder therefore changes the certificate threshold from $A$ to $C_s$; it does not turn finite residue data into an unbounded magnitude oracle. [2] [3]

### 6.2 Epoch protocol

For unbounded operation, retain an epoch $Q$:

\[
\boxed{K=QC_s+\widehat K,\qquad0\le\widehat K<C_s.}
\tag{6.3}
\]

If a quotient coordinate changes by $d_t$, update it by exact Euclidean division:

\[
\widehat K_t+d_t=c_tC_s+\widehat K_{t+1},
\qquad
Q_{t+1}=Q_t+c_t.
\tag{6.4}
\]

The signed carry $c_t$ is the exact capacity-crossing witness. It is not a synthetic signal; it is precisely the information absent from a finite residue-only observation. [2]

### 6.3 Merge topology and timing

The source corpus does not provide an audited post-place-and-route “Star-CRT” hardware implementation. The following are **architectural conclusions**, not measured FPGA results:

| Implementation shape | Merge depth for $s$ anchors | Throughput after pipelining | Correct statement |
|---|---:|---:|---|
| Serial/systolic merge | $O(s)$ stages | Can be one result/cycle after fill | Lower local routing complexity; larger latency. |
| Balanced reduction tree | $O(\log_2s)$ stages | Can be one result/cycle after fill | Preferred when the merge must appear in a latency-sensitive path. |
| Materialize only at boundary | No merge on hot path | N/A | Maintain individual anchor residues and merge only when a capacity certificate/export requires it. |

Each adjacent 36/37 resolver remains a fixed-width subtract-and-normalize unit. A general anchor merge includes fixed-constant modular arithmetic. Any statement of LUTs, FFs, DSPs, Fmax, or latency must be labeled an estimate until accompanied by reproducible synthesis reports, device/part number, clock constraint, and tool version. [2] [15]

---

## 7. Every reconstruction and materialization pathway

### 7.1 Normalized reconstruction table

| ID | Method | Formula / process | Exactness boundary | Runtime-core classification |
|---|---|---|---|---|
| R1 | **Canonical state materialization** | $X=\gamma_B(r)+M_BK$ | Exact if $K$ is retained | Fundamental representation theorem; $\gamma_B$ is a boundary/specification oracle. |
| R2 | **36/37 one-subtraction materialization** | $K=(r_{36}-r_{37})\bmod37$; $X=r_{36}+36K$ | Requires $0\le K<37$ | Normative fast path. |
| R3 | **General adjacent-pair materialization** | $K=(r_n-r_{n+1})\bmod(n+1)$; $X=r_n+nK$ | Requires $0\le K<n+1$ | Normative generalization. |
| R4 | **Generic single-anchor materialization** | $K=((r_A-r_M)M^{-1})\bmod A$; $X=r_M+MK$ | Requires $0\le K<A$ | Normative with static authentic anchor. |
| R5 | **Ladder materialization** | Merge $(\kappa_j)$ to $\widehat K$; $X=r_M+M\widehat K$ | Requires $0\le K<C_s$ | Normative conditional. |
| R6 | **Epoch-qualified ladder materialization** | $K=QC_s+\widehat K$; $X=r_M+M(QC_s+\widehat K)$ | Requires exact epoch state | Normative unbounded-history method. |
| R7 | **Recombinant CRT materialization** | CRT representative plus tracked tuple winding | Requires proved counter coherence | Architectural/conditional. |
| R8 | **Direct CRT sum** | $\gamma_B(r)=\sum_i r_iM_i(M_i^{-1}\bmod m_i)\bmod M_B$ | Returns representative in $[0,M_B)$ | Allowed only as proof, test oracle, or boundary materialization. |
| R9 | **Garner/MRC** | Sequential mixed-radix reconstruction | Returns representative in $[0,M_B)$ | Retired from runtime core; preserved for historical reference, testing, and boundaries only. |
| R10 | **Dual Codex $\beta$ export** | Read explicitly maintained magnitude $\beta=X$; check $\alpha=\rho_B(\beta)$ | Requires compatibility to be maintained continuously | Architectural boundary path. |
| R11 | **Fused Piggyback Division projection** | Auxiliary reference produces primary quotient tuple | Requires exact divisibility and static/authentic auxiliary design | Boundary pending conformance proof. |
| R12 | **Rational/rejection path** | Return normalized $(a,b)$ or rejection certificate | Used when $b\nmid a$ | Required exact alternative to false integer quotient claims. |

### 7.2 What is deliberately absent from the runtime core

Garner and direct CRT are valid mathematical reconstruction methods. Their retirement is an **architectural policy**, not a claim that they are mathematically invalid. They remain useful as independent test oracles, formal uniqueness arguments, and boundary export mechanisms. The runtime core’s commitment is narrower: it uses elimination-first bounded lift recovery and never disguises a sequential MRC cascade as a local K-Elimination coordinate. [1] [2] [3]

---

## 8. K-Elimination use inventory

### 8.1 Core arithmetic uses

| Use ID | Function | K-Elimination role | Preconditions | Output |
|---|---|---|---|---|
| U1 | **Magnitude observation** | Generic anchor lift observation | $\gcd(M,A)=1$; authentic base/anchor residues | $K\bmod A$ |
| U2 | **Bounded exact reconstruction** | 36/37 or general adjacency collapse | Certified lift range | Full $K$ and then $X$ |
| U3 | **Capacity extension** | One observation per static anchor | Pairwise-coprime ladder; capacity certificate | $K$ below $C_s$ |
| U4 | **Unbounded state preservation** | Ladder residue plus epoch update | Exact carry/borrow tracking | Full unbounded $K$ |
| U5 | **Phase-lock verification** | Tests $r_a-r_A-A\kappa_a\equiv0$ | Declared fixed update relation | Exact zero/nonzero defect |
| U6 | **Coprime RNS division** | Phase differential corrects quotient tuple | $\gcd(b,M)=1$, fixed basis, exact divisibility | Residue tuple for $a/b$ |

### 8.2 Application and implementation uses

| Use ID | Domain | Reported operational position | Rigorous interpretation |
|---|---|---|---|
| U7 | **NINE65 DualRNS rescale** | FHE multiplication pipeline: tensor product $\to$ RNS decomposition $\to$ K-Elimination rescale | The repository documents an active exact-division rescale path at fixed lane count. It does not by itself prove a general unlimited-depth FHE theorem. [13] [14] |
| U8 | **NINE65 coefficient resolver** | `KElimination::extract_k`, exact divider reconstruction, scale/round benchmarks | Benchmark values are implementation/parameter specific; the constant-time extractor benchmark includes a bit-serial modular multiply, so it is not equivalent to the 36/37 one-subtraction hardware fast path. [14] |
| U9 | **CRAM scientific division** | Chapter 06 cites known-factor quotient operations in scientific computation and a Navier–Stokes advection quotient | Exact discrete arithmetic may be valuable, but continuum regularity and physical conclusions remain separate open obligations. [8] [16] |
| U10 | **Recombinant CRT cross-check** | Extracted division winding can be compared with stored winding state | A sound integrity pattern only when both the tracked state and the extraction preconditions are specified exactly. [9] |
| U11 | **FPD reference-lane routine** | Specialized phase differential supports shared-factor divisors | Historic mechanism; static anchor/authenticity and mathematical proof obligations must be satisfied before core admission. [10] |
| U12 | **Shadow Disambiguator typing** | A K-Elim result participates in shadow-carrier typing rules | It is a verification/type layer rather than an independent magnitude reconstruction method. [11] |
| U13 | **Dual Codex synchronization** | K-Elim operates on $\alpha$ while $\beta$ is updated by exact division | The explicit $\beta$ magnitude is a second representation, not a value derived solely from a single anchor subtraction. [12] |

### 8.3 Coprime exact RNS division

The general CRAM K-Elimination chapter states a phase-differential algorithm for exact RNS division. Given an integer dividend $a$, divisor $b$, RNS product $M$, and exact divisibility $b\mid a$, it uses lane-local inverse products and a phase differential to correct the residue tuple of the quotient. Its stated core assumptions are $\gcd(b,M)=1$, a fixed basis, and a divisibility promise or certificate. [8]

The repository contains a Lean source file formalizing the basic residue–quotient identity, inverse existence, range bound, reconstruction identity, and a soundness theorem under $X<MA$. The source provides substantial formal evidence, but the current sandbox has no installed Lean/Lake toolchain; therefore this compendium records **formal source present, current sandbox compilation unavailable**, rather than asserting a new independent compilation result. [6] [7]

### 8.4 Shared-factor division and FPD correction

FPD is intended to handle the complementary case $\gcd(b,M)>1$. It uses an auxiliary modulus $p_{\mathrm{aux}}$ coprime to $bM$ and a specialized reference-lane procedure. [10]

A necessary correction is mathematical: if $\gcd(b,M)>1$, then adding an auxiliary modulus cannot make $b$ coprime to the complete product $M p_{\mathrm{aux}}$, because

\[
\gcd(b,Mp_{\mathrm{aux}})\ge\gcd(b,M)>1.
\]

Thus FPD cannot be described as ordinary K-Elimination on an “extended modulus where $b$ is coprime.” Its correctness, if used, must rest on its stated special case analysis and on information carried through the auxiliary reference, not on that invalid coprimality inference. Under the present fixed-frame/no-runtime-emission rules, FPD requires a **preprovisioned authentic auxiliary lane** or an explicitly reversible frame-change proof; otherwise it belongs outside the reversible core. [1] [2] [10]

---

## 9. Phase-lock transduction and exact diagnostics

For a base modulus $A$, coprime anchor $a$, base residue $r_A$, anchor residue $r_a$, and anchor coordinate $\kappa_a$, define

\[
\boxed{D_a=r_a-r_A-A\kappa_a\equiv0\pmod a.}\tag{9.1}
\]

For an additive translation by $\delta$, the source contract defines

\[
r_A'=r_A+\delta-Ac_A,
\qquad
c_A=\left\lfloor\frac{r_A+\delta}{A}\right\rfloor,
\]

\[
r_a'=r_a+\delta\pmod a,
\qquad
\kappa_a'=\kappa_a+c_A\pmod a.
\tag{9.2}
\]

Substitution verifies that $D_a'=0$ whenever $D_a=0$. This is a practical, exact, zero-float instrumentation primitive: a defect is an auditable congruence failure, not an inferred synchronization metric. [1] [3]

| Diagnostic result | Permitted action |
|---|---|
| $D_a=0$ | Continue; the stated phase relation is preserved. |
| $D_a\ne0$ | Emit a read-only defect or boundary certificate. |
| Range certificate absent | Report `RESIDUE_ONLY` or `AMBIGUOUS`; do not fabricate an integer lift. |
| Capacity carry nonzero | Update epoch exactly and emit an `OVERFLOW_EVENT` record. |
| Shadow signature mismatch | Report a check/type failure; do not mutate the arithmetic value. |

IID belongs to a different layer. The additive carry recurrence is IID only under its explicit external independent-uniform input ensemble. It cannot be inferred from deterministic control flow, used as a hardware side-channel theorem, or manufactured by adding synthetic residue emissions. [3]

---

## 10. Recombinant CRT and the relation between stored and observed winding

Recombinant CRT records lane or tuple windings through ordinary operations so that a value may be represented as a CRT fundamental-domain residue plus a retained overflow count. K-Elimination, by contrast, **observes/extracts** a quotient-related lift at a division boundary. They solve different state-management problems:

| Mechanism | Time of use | Information source | Main role |
|---|---|---|---|
| Recombinant CRT winding | During accumulation, addition, and multiplication | Explicit stored state/carry history | Preserve global identity through wrap events. |
| K-Elimination | At exact division or anchor observation | Differential relation between compatible authentic residues | Recover a quotient/lift residue and correct division. |
| Anchor ladder | At wider magnitude observation | Multiple K-Elimination observations | Extend range multiplicatively. |
| Epoch | At capacity crossings | Exact Euclidean carry/borrow | Preserve unbounded lift beyond all finite anchor capacities. |

When both a tracked winding and an independently extracted K-Elimination coordinate are available, equality is a valuable consistency check. But neither mechanism supersedes the capacity law: a residue-only observation is finite, and an unbounded exact value still requires retained unbounded state or a separate external bound. [2] [9]

---

## 11. Dual Codex and explicit magnitude paths

The Dual Codex architecture maintains an inner residue representation $\alpha(X)$ and an outer magnitude representation $\beta(X)$ simultaneously:

\[
\alpha(X)=\rho_B(X),
\qquad
\beta(X)=X,
\qquad
\alpha(X)=\rho_B(\beta(X)).
\tag{11.1}
\]

The reference form describes $\beta$ as a positional base-$M$ big-integer representation. It also records mixed-radix and Montgomery-scaled alternatives. Because $\beta$ is explicitly maintained, exporting it is not the same operation as K-Elimination from two residues. K-Elimination can synchronize a division in $\alpha$ with an exact division in $\beta$ under the appropriate conditions, but it does not eliminate the independent magnitude state. [12]

| Question | Elimination-first core answer | Dual Codex answer |
|---|---|---|
| Where is magnitude stored? | In lift $K$, capacity state, and/or epoch. | In explicitly maintained $\beta$. |
| How is magnitude recovered? | Anchor observation plus certificate, then base-plus-lift. | Read/export $\beta$, verifying compatibility when required. |
| Is Garner allowed in the hot path? | No. | Historical Dual Codex description may use it for $\alpha\to\beta$ transfer; this is a boundary/architectural tension. |
| Can the two forms coexist? | Yes, if their compatibility relation is explicitly maintained. | Yes, but this is a richer state design than pure elimination-first reconstruction. |

The compendium therefore classifies Dual Codex as an **explicit parallel magnitude architecture**. It is valuable for comparison and system design, but it must be documented separately from the bounded one-subtraction 36/37 resolver. [1] [12]

---

## 12. Shadow anchors and the open-shadow distinction

The Shadow Disambiguator assigns the 11-lane a context-specific check/type role and references the set $\{11^6,13,17,19\}$. It is described as a verification layer for vorticity signatures, chimera discrimination, and some cryptographic lane-mixing contexts. [11]

The threaded conformance register imposes an essential coprimality correction: if the base frame already contains modulus $11$, then $11^6$ cannot be an independent CRT modulus in that same frame because

\[
\gcd(11,11^6)=11\ne1.
\]

Therefore an “open shadow prime” or shadow anchor can be a fixed authentic redundant check or a bound-bearing auxiliary observation, but not an automatically independent CRT coordinate. It can supply **O(1) fixed-width magnitude recovery only when it is a coprime, authentic anchor whose capacity exceeds the relevant lift**, exactly as in the generic anchor theorem. [2] [3] [11]

This resolves the distinction between the two design ideas:

| Design | What it observes | When it reconstructs in fixed $O(1)$ hardware latency | What it cannot do alone |
|---|---|---|---|
| 36/37 adjacency resolver | $K\bmod37$ | When $0\le K<37$ | Recover an arbitrary unbounded $K$. |
| Open coprime shadow anchor $A$ | $K\bmod A$ | When a certificate gives $0\le K<A$ | Serve as an independent CRT coordinate if it shares a factor with the base. |
| Ladder of anchors | $K\bmod C$ | When $0\le K<C$ | Determine number of complete capacity epochs. |
| Ladder plus epoch | Full $K$ | Whenever epoch is stored exactly | Remain fixed-bit-width for unbounded values. |

---

## 13. Hardware and RTL integration contract

### 13.1 Current RTL artifact

The supplied `winding_resolver.sv` implements the adjacent-pair arithmetic candidate

\[
k_{\mathrm{out}}=(v_M-v_A)\bmod A
\]

using a registered subtractor, a comparator, and conditional normalization. This matches equation (5.1) when the wrapper guarantees $A=M+1$ and when $v_M,v_A$ are authentic residues of a common represented value. [15]

### 13.2 What the module proves operationally—and what it does not

| RTL property | Current status | Required wrapper condition |
|---|---|---|
| Implements a fixed-width subtract-and-normalize calculation | Present in source | Correct under modulo-$A$ arithmetic and input-width conventions. |
| Produces the adjacent K-Elimination coordinate | Conditional | Assert/enforce $A=M+1$, common-value authenticity, and input residue ranges. |
| Produces full $K$ | Not unconditional | Require a range certificate $0\le K<A$ or include epoch/capacity state. |
| Produces a full integer $X$ | Not implemented in the module | Add $X=v_M+M K$ only under the range/epoch contract. |
| Handles multi-anchor capacity | Not implemented in the module | Instantiate static anchor lanes and a separately verified merge/epoch controller. |
| Constant-time/side-channel security | Not established by RTL text | Require target-specific timing closure and a physical leakage evaluation. |

A production wrapper should carry `capacity_mode`, `range_valid`, or an explicit epoch protocol. It should never label `k` as `floor(X/M)` unconditionally; the mathematically correct raw output is $K\bmod A$. [2] [15]

### 13.3 Recommended certified interface

```systemverilog
// Semantic contract, not a claim that the present RTL has this interface.
typedef enum logic [1:0] {
  K_RESIDUE_ONLY,   // k = K mod A; no unique representative certified
  K_EXACT_BOUNDED,  // certificate proves 0 <= K < A
  K_EPOCH_QUALIFIED,// full K is interpreted with retained epoch state
  K_INVALID          // adjacency/authenticity/range precondition failed
} kelim_status_t;
```

The resolver datapath may remain a single subtract-normalize stage for 36/37. The **certificate path**, not the arithmetic expression, determines whether the output can be used for an exact integer reconstruction. This separation is the correct hardware translation of the capacity theorem. [2]

### 13.4 Resource and timing claims

No Xilinx UltraScale+ synthesis report, Vivado version, target part, placement, routing result, or timing constraint is present in the authoritative corpus examined here. Accordingly, the prior numerical values such as LUT, FF, DSP, and Fmax figures must be treated as **engineering estimates**, not measured synthesis results. This compendium does not restate them as facts.

A reproducible FPGA evidence package must include the exact RTL revision, parameter width, `A/M` relation, wrapper and certificate logic, target part, XDC clock, synthesis/place-and-route reports, power assumptions, and testbench/property suite. Only then can the system report actual resource utilization or a critical path. [15]

---

## 14. Formal evidence, test evidence, and unresolved proof obligations

### 14.1 Evidence matrix

| Artifact | What it establishes | Current qualification |
|---|---|---|
| Threaded normative kernel | Exact state model, capacity law, eliminaton-first policy, prohibition boundaries | Normative authority for this compendium. [1] |
| Covering-coordinate paper | Lift vs. winding distinction and rank-one CRT-torus winding theorem | Exact under stated path/closure convention. [4] |
| `starlift.py` | 36/37 collapse, star-number identities, single-anchor hygiene, finite ladder examples | Executable finite-range/reference evidence; code comments are not universal theorems. [5] |
| `KElimination.lean` | Division identity, inverse existence, range theorem, soundness proof source | Formal source present; not independently compiled in the present sandbox because no Lean toolchain is installed. [6] |
| `Adjacency.lean` | Adjacent-modulus subtraction-collapse proof source | Same local compilation limitation; theorem source correctly states the required range assumption. [7] |
| Exact validation file | Capacity aliasing, 36/37 bijection, counter examples, safe-prime and first-two-lane corrections | Finite exact validation summary. [17] |
| CRAM Chapter 06 | General RNS exact-division algorithm statement and measured test scope | Framework claim must be distinguished from independently checked formal theorem. [8] |
| NINE65 benchmarks | Software runtime records for current paths | Parameter/implementation specific; not hardware resource proof. [14] |
| RTL file | Candidate adjacent resolver arithmetic | Not a synthesis report and lacks capacity/epoch interface. [15] |

### 14.2 Priority proof backlog

| Priority | Obligation | Required artifact |
|---:|---|---|
| 1 | Lean/Coq proof of the fixed-frame residue–lift bijection | Definitions over an exact integer domain, machine-checked theorem, build record. |
| 2 | Parametric proof of generic anchor elimination and 36/37 bounded materialization | Explicit authentic-residue and capacity hypotheses. |
| 3 | Ladder capacity and epoch correctness proof | Pairwise-coprime anchor list, merge definition, signed carry/borrow semantics. |
| 4 | RTL equivalence proof | Prove the resolver output equals equation (5.1) and connect `valid` to input transaction semantics. |
| 5 | Static-anchor frame conformance proof | Show each stored anchor lane remains a direct residue throughout all admitted operations. |
| 6 | FPD proof repair | Replace the invalid extended-coprimality wording with a precise special-case theorem; formalize static auxiliary protocol. |
| 7 | NINE65 cryptographic correctness/noise proof | Complete parameter, security, bootstrapping/rescale, and noise-accounting proof—not merely arithmetic exactness. |
| 8 | FPGA synthesis report | Tool/device/constraint-specific LUT/FF/DSP/timing/power evidence and property tests. |

---

## 15. Application boundaries: FHE, scientific computing, and claims discipline

### 15.1 FHE integration

The NINE65 architecture describes a dual-RNS K-Elimination rescale in its homomorphic multiplication path and reports a full-polynomial software benchmark for `k_elim_rescale_dual`. It explicitly distinguishes this path from a retired shrinking-modulus ladder. [13] [14]

The exact arithmetic claim that follows is narrow but useful: if the coefficient representation, anchor state, divisibility, capacity, and correction formula satisfy their contracts, then the rescale/division does not inject a floating-point rounding approximation into that arithmetic step. This does **not** alone establish unlimited FHE depth, a secure bootstrap, a complete BFV/CKKS modulus-conversion proof, or a production security result. The NINE65 architecture itself labels deployment as pre-production and its security posture as provisional. [13]

### 15.2 Scientific computing and Navier–Stokes

CRAM chapters describe K-Elimination as supporting exact known-factor quotient operations in a discrete scientific solver. That is a discrete arithmetic statement. It can eliminate one class of representation drift, provided exact state contracts and divisor hypotheses are obeyed. A continuum Navier–Stokes regularity conclusion requires a separate scale family, embedding, consistency estimate, stability bound, and convergence theorem. The threaded source register correctly classifies a continuum-level result as open. [3] [8] [16]

### 15.3 Security and IID

The finite-set bijection associated with the 36/37 coordinate change and the additive IID theorem are exact mathematical results under their stated input distributions. They do not demonstrate electromagnetic/power leakage resistance, masking security, or random behavior of a deterministic machine. A security conclusion requires a leakage function, attacker model, measurement or proof method, and appropriate constant-time evidence. [3]

---

## 16. Prohibited, retired, and non-core mechanisms

| Mechanism or statement | Correct classification | Reason |
|---|---|---|
| IEEE floating point / approximate real arithmetic in the trusted core | **PROHIBITED** | Violates zero-float trusted-state definition. |
| Runtime Garner or mixed-radix cascade | **RETIRED** | Conflicts with elimination-first runtime architecture. |
| Calling $\kappa_A$ a Garner digit | **PROHIBITED terminology** | A two-modulus lift observation is not a mixed-radix digit. |
| “One anchor gives arbitrary full magnitude” | **REJECTED-AS-STATED** | Capacity alias theorem. |
| “A fixed ladder gives arbitrary full magnitude” | **REJECTED-AS-STATED** | Finite capacity aliases $K$ and $K+C$. |
| “All higher star anchors are subtraction-only” | **REVISED** | Only a consecutive base/anchor pair has $M^{-1}\equiv-1$. |
| Runtime DynCRT lane creation/reprojection | **PROHIBITED** | Breaks fixed-frame authentic-lane discipline absent a separately proved invertible frame change. |
| $11^6$ as independent CRT lane alongside 11 | **REJECTED-AS-STATED** | Not coprime to 11. |
| Non-bijective square/fold in reversible core | **PROHIBITED** | Lacks an inverse on general residue domains. |
| Synthetic residue emissions to induce IID | **PROHIBITED** | IID is analyzed from input ensembles; it is not manufactured. |
| Physical, cosmological, quantum, or continuum conclusions from residue identities alone | **OPEN / NON-NORMATIVE** | Requires separate model and proof bridge. |

---

## 17. Reference algorithms and certificates

### 17.1 36/37 bounded resolver

```text
function kelim_36_37(r36, r37, range_certificate):
    // Preconditions:
    //   r36 = X mod 36, 0 <= r36 < 36
    //   r37 = X mod 37, 0 <= r37 < 37
    //   both lanes are authentic for the same X
    k37 := (r36 - r37) mod 37

    if range_certificate proves 0 <= floor(X / 36) < 37:
        X_exact := r36 + 36 * k37
        return Exact(X_exact, k37)

    return ResidueOnly(k37)  // This is K mod 37, not necessarily K.
```

### 17.2 General fixed-anchor resolver

```text
function kelim_anchor(rM, rA, M, A, inverse_M_mod_A, certificate):
    require gcd(M, A) = 1
    require rM = X mod M and rA = X mod A in the fixed authentic frame

    kA := ((rA - rM) * inverse_M_mod_A) mod A

    if certificate proves 0 <= K < A:
        return Exact(rM + M * kA, kA)

    return ResidueOnly(kA)  // kA = K mod A
```

### 17.3 Ladder plus epoch

```text
function resolve_ladder(rM, kappas[1..s], anchors[1..s], epoch_Q):
    C := product(anchors)
    Khat := CRT_merge(kappas, anchors)   // K mod C, performed only under declared policy
    K := epoch_Q * C + Khat
    return Exact(rM + M * K, K)
```

The ladder merge must itself have a declared proof/implementation policy. In the normative architecture it may be a boundary materialization or a separate fixed tree; it must not be silently substituted with a runtime Garner cascade. [1] [2]

### 17.4 Exact division dispatcher

```text
function exact_divide(a_state, b):
    if b == 0:
        return Rejection(DivisionByZero)
    if not certificate_proves_divisibility(a_state, b):
        return ExactRationalOrRejection(a_state, b)
    if gcd(b, M) == 1:
        return CoprimeKElimination(a_state, b)
    else:
        return SharedFactorDivisionOnlyIfStaticAuxiliaryProtocolIsCertified(a_state, b)
```

The final branch is intentionally strict. The source corpus’s FPD idea is retained, but a dynamically injected auxiliary lane is incompatible with the present immutable-frame core. [1] [2] [10]

---

## 18. Final synthesis

The CRAM/QMNF reconstruction system is most rigorous when expressed as a hierarchy of exact finite observations and explicit lift state:

\[
\begin{aligned}
\text{residue tuple} &\Rightarrow \text{fundamental-domain coordinate},\\
\text{one coprime anchor} &\Rightarrow K\bmod A,\\
\text{adjacent 36/37 anchor} &\Rightarrow \text{one-subtraction }K\bmod37,\\
\text{capacity certificate} &\Rightarrow \text{unique bounded }K,\\
\text{coprime ladder} &\Rightarrow K\bmod C,\\
\text{epoch} &\Rightarrow \text{unbounded }K,\\
\text{base residue plus full lift} &\Rightarrow \text{exact integer reconstruction}.
\end{aligned}
\]

This ordering clarifies the role of every mechanism:

- **StarLift** is the selected 36/37 adjacency geometry and its single-subtraction resolver.
- **K-Elimination** is the general operation that observes a base lift modulo a coprime anchor and, in the coprime RNS-division formulation, corrects quotient residues by phase differential.
- **Anchor ladders** scale finite capacity but do not remove the finite-information boundary.
- **Epochs and explicitly stored magnitude codices** are the mechanisms that make unbounded identity possible.
- **Recombinant CRT** is a winding-preservation architecture; **phase lock** is an exact cross-lane invariant; **shadow anchors** are checks unless separately justified as coprime anchors.
- **Garner and direct CRT** remain valid mathematical reference constructions, but the current runtime core deliberately does not use them.

The central theorem for implementation is therefore not “all RNS reconstruction is a modular subtraction.” It is more exact:

> **Theorem (capacity-safe adjacency reconstruction).** In a fixed authentic 36/37 frame, the subtraction $(r_{36}-r_{37})\bmod37$ equals the base lift $K=\lfloor X/36\rfloor$ exactly when the accompanying certificate proves $0\le K<37$; otherwise it equals $K\bmod37$. With an explicit capacity/epoch state, this local constant-latency primitive composes into an exact, zero-float, unbounded integer representation.

That formulation preserves the genuine strength of the architecture—its exactness, its hardware simplicity for the adjacent kernel, and its explicit finite-capacity discipline—while keeping every claim aligned with its proof obligations. [1] [2] [3] [5]

---

## References

[1]: file:///home/ubuntu/cram_threaded_docs/RECONCILED_NORMATIVE_KERNEL.md "Reconciled Normative Kernel for the CRAM Consolidation"
[2]: file:///home/ubuntu/cram_threaded_docs/02_ELIMINATION_AND_CAPACITY_CONTRACT.md "Thread 2 — Elimination and Capacity Contract"
[3]: file:///home/ubuntu/cram_threaded_docs/06_CONFORMANCE_AND_UNRESOLVED_CLAIMS.md "Thread 6 — Conformance and Unresolved Claims Register"
[4]: file:///home/ubuntu/upload/Covering_Coordinates_and_Constrained_Torus_Winding..md "Covering Coordinates and Constrained Torus Winding in CRT Trajectories"
[5]: file:///home/ubuntu/upload/starlift.py "StarLift exact-integer reference implementation"
[6]: file:///home/ubuntu/k-elimination-lean4/KElimination.lean "Lean 4 K-Elimination formal source"
[7]: file:///home/ubuntu/k-elimination-lean4/KElimination/Adjacency.lean "Lean 4 Adjacency Collapse formal source"
[8]: file:///home/ubuntu/CRAMcorpus/06_k_elimination_theorem.md "CRAM Corpus Chapter 06 — The K-Elimination Theorem"
[9]: file:///home/ubuntu/CRAMcorpus/07_recombinant_crt_winding.md "CRAM Corpus Chapter 07 — Recombinant CRT Winding"
[10]: file:///home/ubuntu/CRAMcorpus/08_fused_piggyback_division.md "CRAM Corpus Chapter 08 — Fused Piggyback Division"
[11]: file:///home/ubuntu/CRAMcorpus/09_shadow_disambiguator.md "CRAM Corpus Chapter 09 — Shadow Disambiguator"
[12]: file:///home/ubuntu/CRAMcorpus/A-07_dual_codex_dcbigint.md "CRAM Corpus Addendum A-07 — Dual Codex and DCBigInt"
[13]: file:///home/ubuntu/NINE65_v7/docs/ARCHITECTURE.md "NINE65 Architecture"
[14]: file:///home/ubuntu/NINE65_v7/benchmarks/BASELINE.md "NINE65 Baseline Benchmark Audit"
[15]: file:///home/ubuntu/winding_resolver.sv "Winding Resolver SystemVerilog source"
[16]: file:///home/ubuntu/CRAMcorpus/14_major_theorems_register.md "CRAM Major Theorems Register"
[17]: file:///home/ubuntu/upload/EXACT_VALIDATION_RESULTS..txt "Exact Validation Results"
