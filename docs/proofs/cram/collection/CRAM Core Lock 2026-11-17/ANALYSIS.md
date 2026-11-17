# CRAM core lock: Torus-Fiber and certified-lift analysis

2026-11-17. This packet adds all ten new attachments to the CRAM evidence collection. It integrates their useful mechanisms and outstanding obligations into the standalone engine specification. NINE65 remains the intended consumer; its cryptographic correctness is outside this review.

**Result:** the composite-modulus experiments reproduce, and the prototype supplies concrete observation producers worth retaining. Two benchmark assumptions and two prototype invariants need repair before these artifacts can satisfy the locked CRAM contract. The maintained Lean package now checks 235 declarations, including twelve new source-binding results. This is mathematical coverage, not a claim that the uploaded Rust has been formally refined.

## 1. What was added and inspected

All original attachments are preserved under `inputs/`, with original paths, byte sizes and SHA-256 hashes in [INPUT_MANIFEST.json](INPUT_MANIFEST.json). No uploaded source was overwritten.

The three ZIPs are versions, not independent replications. ZIP9 (`...-3.zip`) is the richest version: its 38 checksum entries pass, and its report matches standalone upload1. ZIP10 matches standalone report3; ZIP4 contains an earlier report revision. Both older 27-entry checksum manifests also pass. These checks establish consistency with the supplied manifests, not authorship authentication.

The audit inspected the Markdown versions, Rust sources, relevant supplied scripts, every `certified_lift` source/test/example, and all six pages/twenty numbered results of `PROOFS.pdf`. The report PDF is preserved as a derivative artifact; its rendering was not separately audited page by page. Detailed scope and commands are in the [Torus review](evidence/torus-review/report.md) and [prototype/proof review](evidence/certified-lift-review/report.md).

## 2. The contribution to the mathematical core

### Composite carriers and dependent observations

The readouts work with pairwise-coprime composite carriers, including prime powers and even moduli, when the required inverses exist. Primality and squarefreeness are not prerequisites for these formulas. Anchor and checker moduli may share factors with each other while each remains coprime to the carrier product.

This supports CRAM's separation of **independent carriers**, **dependent views**, and **operator-specific domains**. It does not make a nonunit invertible or demonstrate that this particular CRT constructor accepts arbitrary overlapping carrier lanes. General shared-factor resolution retains its own kernel/LCM theorem and implementation obligations.

### CRT rank and source winding have an exact reference-change law

For pairwise-coprime moduli m_i > 1, define:

    M = product(m_i),  M_i = M/m_i
    xi_i = (x_i * inverse(M_i,m_i)) mod m_i
    S = sum(xi_i*M_i)
    x = S mod M
    S = x + alpha*M,  0 <= alpha < k.

For a lifted source X = x + K*M, and gcd(M,A)=1, an authentic anchor observation gives:

    c = (X mod A - S mod A)*inverse(M,A) mod A
      = (K-alpha) mod A.

Thus K = alpha+c modulo A. Replacing one coordinate by the other changes the result. With gcd(M,q)=1, the supplied rank formula

    alpha mod q = (S mod q - x mod q)*inverse(M,q) mod q

requires a reading of canonical x. Substituting a reading of X returns alpha-K unless the source-reference difference is explicitly corrected.

**Architectural consequence:** attach source-reference semantics to the readout. Distinguish modular rank, exact rank, winding residue and exact winding in APIs and proofs. Universal query transport tells us when a query is determined; the concrete producer must still supply its observations.

### A sharper rank bound

For a fixed carrier base:

    alpha_max = floor(sum_i (m_i-1)/m_i).

Every rank from zero through this maximum occurs: increase the independent coefficients one unit at a time, with each increase changing the normalized sum by less than one. CRT makes every coefficient tuple admissible. Consequently a single rank residue distinguishes all these ranks exactly iff q > alpha_max. Invertibility of M modulo q is an additional requirement of the readout formula. The familiar q >= k is sufficient but can be conservative.

For S6, {2,3,5,7,11,13}, the maximum is **4**, not 5. This is a useful admission and test-generation rule. It is derived here in ordinary mathematics and tested on finite cases; it has not yet been added as a Lean theorem.

## 3. Fresh verification and its limits

| Check | Fresh result |
|---|---|
| Latest Rust default composite corpus | PASS at 2, 4, 8, 16, 32, 64 and 128 lanes |
| Shared anchor/checker fixture | PASS |
| Supplied exhaustive composite probe | 1,801,800 canonical cases, 217,800 anchor pairs and 516 boundary vectors passed, plus high-word and ambiguity controls |
| Independent smaller-base probe | 57 bases; 10,687 states; 39,486 rank readouts; 118,458 shifted readouts passed |
| Corrected tropical minimization | 48,040 independent finite cases passed |
| Original certified_lift suite | 19 passed; none ignored |
| Additional prototype contract tests | Four tests exposed the recorded defects/limitations in both debug and release |
| Maintained Lean audit, before addition | 223 declarations, 58 axiom-free; PASS |
| Integrated Lean audit | **235 declarations, 67 axiom-free; PASS** |

Lean used 4.27.0-rc1 and mathlib revision `3bdc7047b97538f795b725dc0713c28c0f53ed10`. All transitive axioms stayed within `propext`, `Classical.choice`, and `Quot.sound`. Builds reused local compiled dependency artifacts. The [verification manifest](evidence/integrated-audit/verification.json) records source hashes and declarations.

The new PhaseBinding module proves that self-derived phase consistency can hold for mixed-origin readings, gives an explicit counterexample, and supplies conditional producer/transition composition and concrete paired-residue translation results. Generic premises are explicit: this does not prove every Rust producer correct.

Older partition, curvature, carry and 28,488,600-pair sweep results remain archived evidence; they were not all rerun. The supplied report's ARM timing medians are not fresh measurements here. Our single x86_64 benchmark run checks reproducibility, not a statistically controlled speedup claim.

## 4. Concrete issues to repair

### Benchmark admission and oracle

1. **The actual rank readout needs enough resolution.** The harness checks the secondary q2 range but not the mr used to reconstruct. With carriers [9,25,49,121], mr=2, q2=169, a valid input has rank 3. The first readout returns 1; the checker returns 3. Preflight stops before timing. Require mr > alpha_max (or conservative mr >= k) for exact-rank use.
2. **The maximal coefficient vector need not have rank k-1.** For carriers [2,3,5,7], the maximizing vector gives S=593, M=210, x=173, rank 2. The harness expects 3 and rejects a legitimate configuration. Use the proved base-dependent maximum.

These are reproduced preflight failures, not accepted wrong reconstructions or counterexamples to K-Elimination. The original fixtures and failure logs are preserved.

### Prototype invariants

1. **Frame binding fails through public APIs (CL-01).** Encoding 1000 under shell 36 and anchor 37 produces [28,1]. The shell-35 kernel accepts the foreign value and interprets those same readings as **1148**, while retaining the claimed bound 1000. A shorter foreign frame also panics. Private fields are insufficient without checked frame binding.
2. **The bound carries the source magnitude (CL-02).** Lift.bound starts at the exact input; unsigned addition/multiplication propagate it exactly. Multiplying 100 by 200 and adding 100 exposes 20000 and 20100 through .bound(). This violates the intended absence of an independent scalar magnitude track. Public workload envelopes with proved propagation remain permissible.
3. **Division is a specialized route (CL-03).** It requires unit divisors and historical constant-factor certificates. Directly loaded 140 divided by 7 is refused despite being exactly divisible. This prototype does not yet implement the engine's full divmod/GCD contract.
4. **Wide costs and refusal semantics remain explicit (CL-04/05).** Multi-anchor paths assemble temporary BigUint quotients. Growth and bound tightening can occur before a later operation refuses. These need their own cost and transaction contracts.

Useful mechanisms survive this review: concrete lane producers, signed comparison by common bias, observation growth before aliasing, specialized divisibility certificates, and bounded redundant-anchor readouts. They are candidates for refinement after the invariant repairs.

## 5. Further reusable results from the proof packet

**Division-free affine folding is a strong operator target.** For f(x)=ax+b, carry a temporary pair (p_n,s_n)=(a^n, sum_{j<n} a^j). Pair composition is

    (p,s) * (q,t) = (p*q, s+p*t),

with identity (1,0). Binary powering of (a,1) computes the pair in O(log(n+1)) modular operations, and f^n(x)=p_n*x+b*s_n. This works over every Z/mZ, including nonunits a-1, without division. It gives CRAM a precise repeated-operator optimization to formalize; it does not require importing a physical synchronization claim.

The tropical quadratic also has an exact boundary-sensitive form. For Q>0, integer K, z=g+QK and 0<=g<Q, minimizing Q*n^2+2*n*z over integer n gives -K below the half-boundary, -K-1 above it, and both at equality. The unqualified argmin=-K needs that correction. This supplies a future operator proof obligation; it is not yet a theorem reconstructing a continuum.

Other corrections matter to proof statements: Fermat-style inverse formulas can happen to work at composite Carmichael moduli, although primality-based justification is insufficient in general; noninjective maps can be homomorphisms; reversible lane packing is not information erasure; and cubing on F11* is a permutation but a square-root function only on quadratic residues. The detailed review identifies each affected result.

## 6. What is now locked, and what comes next

The [core specification](source/docs/cram/CORE_SPEC.md) now fixes authentic residue state, derived-on-demand K, parameterized Safe Basis roles, separate integer/rational/product semantics, explicit capacity changes and typed transduction. The [proof ledger](source/docs/cram/PROOF_OBLIGATIONS.md) records mathematical coverage separately from executable closure. [Source reconciliation](source/docs/cram/SOURCE_RECONCILIATION.md) preserves corrections without rewriting historical artifacts.

The next implementation order is:

1. **P4:** frame-bound values, canonical ingress and concrete sister-tray producer/transition invariants; reject foreign and stale frames without panics.
2. **P3/P8:** public bound policy, elimination of independently carried magnitude, and observation growth while old evidence still suffices.
3. **P3/P10:** corrected rank admission/oracles, explicit canonical-observation producers, checked word/limb refinement, and cost accounting for setup and readout construction.
4. **P5/P6/P9:** full division dispatch and progress, division-free affine powering, and state-preserving refusal at the public engine boundary.
5. **P10:** refine the actual Rust against the maintained mathematical contracts, then test the integrated engine path. NINE65 integration follows with separate application obligations.

The benchmark's final subtraction/multiplication is constant in operation count once inputs exist. Its lane accumulation is O(k), and the supplied canonical redundant readings are created using Garner during untimed setup. Full output uses wide S-alpha*M reconstruction. These are valid scoped experiments; neither is evidence that an arbitrary-width, arbitrary-lane engine operation costs O(1).

This packet is a local, uncommitted evidence delivery. Original uploads, audit logs, source snapshots and hashes are included. No remote publication or whole-engine certification is implied.
