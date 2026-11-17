# Arithmetic and cryptographic cross-pollination

Source snapshot: `Skyelabz210/NINE65_v7@88a7bdadbf0e1f8fbfdb2b37e9843101b8db3484`. Analysis date: 2026-11-12. This note develops new connections from the existing universal proof packet and concrete NINE65 implementations. It does not rely on the unavailable linked Codex task. The contribution being examined is Anthony Diaz's complete CRAM architecture: authentic observations, on-demand coordinate queries, operation semantics, bounds and composition, rather than an isolated modular identity.

**Status terms:** **implemented** means the cited executable source contains the construction; **existing Lean result** means the named theorem is already in the cited proof package; **written deduction** means an argument supplied below, not a new Lean declaration; **proposal** means a bridge whose implementation or refinement remains to be supplied. Mathematical generalization does not by itself decide historical priority.

## 1. What already connects, and what still needs a bridge

| Construction | Concrete source and scope | Consumer it can support |
|---|---|---|
| G/H digit producer | [`bounded_digit_circuit.rs`](../../crates/nine65/src/ops/bounded_digit_circuit.rs), lines 1–16, 80–140, and `SplitDigitEvaluator`; coherent encrypted views at plaintext moduli p² and p | The native source quotient modulo p, with an independently certified signed representative |
| Source and return authority | [`public_refresh_source.rs`](../../crates/nine65/src/ops/public_refresh_source.rs), `SourceCertificate`, `PreparedRefreshSource`, `accept_refresh`; [`public_refresh_return.rs`](../../crates/nine65/src/ops/public_refresh_return.rs) | Root-preserving return from the exact source history and key family |
| Provisioned coefficient division | [`arithmetic/recumbent.rs`](../../crates/nine65/src/arithmetic/recumbent.rs), `RecumbentBasis`, `RecumbentCoefficient::drop_main` | Floor, exact or nearest division by an already observed main modulus, across surviving lanes |
| General public-divisor projection | [`rank_residue_divider.rs`](../../crates/nine65/src/arithmetic/rank_residue_divider.rs), lines 1–28, `divide_floor` | Quotient residues for shared-factor divisors under an authentic signed interval; global full-width scratch, separate cost |
| Encrypted integer division | [`cram_main_division.rs`](../../crates/nine65/src/ops/cram_main_division.rs), `EncryptedUint`, `divide_integer`; [`integer_division_circuit.rs`](../../crates/nine65/src/ops/integer_division_circuit.rs), `Circuit::new` | Exact unsigned quotient, remainder and zero-divisor predicate on sealed encrypted words |
| Rational interfaces | [`rational_bridge.rs`](../../crates/nine65/src/arithmetic/rational_bridge.rs), `RationalBridge`; [`crt_rational.rs`](../../crates/exact_transcendentals/src/crt_rational.rs), `CRTRational` | Parameter rationals and integer-pair arithmetic; the present modular scalar projection still requires an invertible denominator |

These routes operate on different semantic sources. A coefficient, an encrypted integer word, a canonical plaintext coefficient, and the secret-dependent native phase are distinct. The shared theorem can organize their adapters while retaining those distinctions.

The other `Recumbent` in `exact_transcendentals/src/recumbent.rs` is a separate carrier: it has scalar parking and reconstruction in several methods. Its name does not make it the provisioned coefficient route analyzed here. Neither implementation is silently promoted to the user's intended fully on-demand K architecture.

## 2. G/H is also a finite-support retraction

**Existing Lean result.** [`PublicRefreshDigit.lean`](../../lean4/KElimination/KElimination/PublicRefreshDigit.lean) proves `taylor_remainder`, `certified_split_digit` and `residual_polynomial_correct`. For integer polynomials G,H, positive p, source x=ρ+pK and certificates

\[
G(\rho)=0\pmod {p^2},\qquad G'(\rho)H(\rho)=1\pmod p,
\]

the construction gives

\[
\left(\frac{G(x)\bmod p^2}{p}\right)H(x)=K\pmod p,
\qquad F(x):=x-G(x)H(x)=\rho\pmod {p^2}.
\]

The existing implementation constructs G from the public residual support S={−B,…,B}, verifies its roots modulo p², interpolates H over the prime field, and checks every derivative certificate. The condition 2B<p makes the residuals distinct modulo p and hence gives simple roots. The split evaluation pays for G at p² while evaluating H and the last product at p.

**Written deduction: retraction and idempotence.** Let U be the union of the classes ρ+pℤ inside ℤ/p²ℤ, for ρ∈S. Regard the chosen residual representatives as elements of ℤ/p²ℤ. Then F maps U into S, fixes S and satisfies

\[
F(F(x))=F(x)\quad\text{in }\mathbb Z/p^2\mathbb Z.
\]

Proof: the residual identity gives F(x)=ρ. Applied with K=0 it gives F(ρ)=ρ. Polynomial evaluation respects congruence, so the composition has the same value. Differentiating the defining polynomial at a supported residual also gives

\[
F'(\rho)=1-G'(\rho)H(\rho)-G(\rho)H'(\rho)=0\pmod p.
\]

Thus the map preserves the selected residual and removes its first-order p-direction. This is an exact algebraic retraction on a specified finite union of charts. It connects the native construction to local algebra, polynomial interpolation with derivative constraints, and Hensel-style corrections.

**What returns to NINE65.** The residual map and quotient map become two consumers of the same local chart. A compiler can ask whether the next operation needs K, ρ or a composed function of either, and select the cheaper certified circuit expression. Repeated residual normalization is semantically idempotent on this domain, giving an additional metamorphic test and a possible rewrite rule. The actual encrypted implementation still needs a cost/noise comparison: plaintext idempotence does not imply a second ciphertext evaluation is free or that it removes ciphertext noise.

**Proposal and falsification.** Add the retraction theorem and a refinement from the split producer to its residual consumer. Test supported negative residuals, endpoints and deliberately unsupported residuals. Reusing this map at p³ requires a new higher-order remainder argument; the p² certificate alone does not imply a stronger precision theorem. A residual chosen from two representatives congruent modulo p destroys the unique-chart premise.

## 3. Weighted G/H queries can need less than a derivative inverse

**Written deduction.** The Taylor identity is valid for a composite positive modulus m as well. For x=ρ+mK, a root certificate G(ρ)=0 mod m² gives

\[
\delta=\frac{G(x)\bmod m^2}{m}
       =aK\pmod m,\qquad a=G'(\rho)\bmod m.
\]

Suppose the consumer wants cK mod m. It suffices to supply h satisfying

\[
ah=c\pmod m;
\qquad h\delta=cK\pmod m.
\]

Such an h exists exactly when gcd(a,m) divides c. Equivalently the ambiguity of multiplication by a is invisible to multiplication by c. This is the universal kernel criterion with B(K)=aK and C(K)=cK. It is the same local observed-coordinate structure as the native G/H route, with the target included in the inverse certificate.

For example, m=12, a=8 and c=4 admit h=2. The observation 8K mod12 cannot identify K mod12, but twice that observation determines 4K mod12. More generally, K is known modulo R=m/gcd(a,m); a consumer cK mod b is determined for all integer K exactly when b divides cR. This follows by comparing K and K+R and then reducing cRj modulo b.

**Return to CRAM/NINE65.** A consumer-aware certificate format can express `derivative * decoder = target_weight`, avoiding an unnecessarily stronger request for the full digit when a correction consumes only a weighted projection. This is useful in composite-ring experiments, matrix-valued corrections and reduced target lanes. It gives an explicit target for the CLASS-R/generalized-anchor path.

**Limits and next proof.** The current native prime-field case has a nonzero target weight, so its derivative still must be a unit. No reduction in that implementation's work follows automatically. Moreover, pointwise scalar solutions h(ρ) over a composite modulus do not automatically interpolate to a single polynomial H: polynomial representability and coherent evaluation are additional obligations. A proposed composite circuit must produce and verify one H, satisfy the plaintext transform's invertibility conditions, and redo its error budget. The ring constructor supplies the arithmetic criterion, not these engineering premises.

## 4. Nested floor drops have an exact composition law

**Implemented primitive.** `RecumbentCoefficient::drop_main` reads r_d from a provisioned divisor lane d, selects the declared rounding representative, and updates every surviving main and anchor lane by (x_i−r_d)d⁻¹ mod m_i. Bounds and destination capacity are checked. The current basis is pairwise coprime, so d is a unit in every surviving lane.

**Written deduction: fuse the semantic quotient, retain the remainder.** For any signed integer X and positive d,e, write

\[
X=r_d+dq_d,\quad q_d=r_e+eq_{de},\quad
0\le r_d<d,\quad0\le r_e<e.
\]

Substitution gives

\[
X=(r_d+dr_e)+deq_{de},\qquad 0\le r_d+dr_e<de.
\]

Therefore

\[
\left\lfloor\frac{\lfloor X/d\rfloor}{e}\right\rfloor
=\left\lfloor\frac X{de}\right\rfloor,
\quad r_{de}=r_d+dr_e.
\]

Reversing d and e preserves the final floor quotient, though the local remainder sequence changes. This is a useful composition law for a scale scheduler and for reversible division histories. It derives from the exact decomposition and covers negative X under Euclidean floor semantics.

**Return to NINE65.** The planner can compare admissible sequential and fused quotient routes at the semantic level before costing their concrete lane operations. A consumer needing only the final quotient need not request the intermediate quotient as a scalar. A reversible operation must retain sufficient remainder information; residue representations of r_d+dr_e are enough when the declared recovery consumer does not require an integer remainder. A fused path still needs authentic observations and public inverses for its actual divisor and a valid destination interval. The semantic theorem does not synthesize a missing de lane.

Nearest rounding cannot be substituted into this rule unchanged. With ties toward positive infinity, X=2,d=3,e=2 gives round(round(2/3)/2)=1, whereas round(2/6)=0. A scheduler must either preserve the original order/rounding corrections or prove an additional condition. This counterexample directly protects rescale/transduction optimizations against an invalid commuting-square claim.

## 5. Existing encrypted division gives a concrete encrypted GCD route

**Implemented starting point.** `divide_integer` accepts sealed Boolean words, uses a public circuit schedule, and emits quotient, remainder and an encrypted zero predicate. Its zero-divisor convention is q=0,r=n,z=1. It is not division by modular inversion. The circuit builder uses a public small-word truth table or a restoring circuit, then removes dead gates; the evaluator checks the gate noise bounds before evaluation.

**Written deduction: a fixed 2w-round Euclidean schedule.** For nonnegative w-bit inputs (a,b), use at each public round the encrypted division outputs and a Boolean select implementing

\[
(a,b)\longmapsto
\begin{cases}
(b,a\bmod b),&b\ne0,\\
(a,0),&b=0.
\end{cases}
\]

Exactly 2w rounds suffice. To see this, let r=a mod b when b>0. If r=0, termination is immediate. If 0<r≤b/2, the following remainder is smaller than r and hence smaller than b/2. If r>b/2, b mod r=b−r<b/2. Thus the second component becomes less than half its prior positive value every two rounds. Since b<2^w, it is zero after 2w rounds. Euclid's identity preserves gcd at every live step, and the zero branch freezes the terminal value. The output is gcd(a,b), including gcd(0,0)=0.

**Return to NINE65.** This gives an explicit bridge from the existing encrypted word division implementation to GCD and then exact rational normalization. It avoids secret-dependent loop termination and does not require an encrypted comparison to discover when to stop: the existing zero predicate controls the freeze. The circuit state remains encrypted words; no persistent scalar winding is introduced.

**Proposal, cost and gates.** First implement the public DAG compiler and its clear Boolean oracle, then lift its gates through the existing evaluator with immutable key/noise histories. A schoolbook O(w²)-size divider repeated O(w) times yields O(w³) gate work before simplification; no constant-time arithmetic-cost claim is made. A fixed circuit schedule is also not a complete hardware side-channel proof. Admission may fail because of noise or width limits, in which case the API must refuse before evaluation. Sharing a denominator ciphertext and zero predicate does not authorize reuse across different source histories.

The existing universal package's bounded residue Euclid proof is a specification witness for the result. The new public 2w schedule and the actual encrypted DAG refinement remain separate formalization targets. No encrypted GCD execution is claimed here.

## 6. Cross-cancelled rational pairs connect GCD to capacity planning

**Written deduction.** Keep an exact rational as an integer numerator/positive-denominator pair, with each component carried by an admitted representation. For a/b and c/d, with b,d>0, let

\[
g_1=\gcd(|a|,d),\qquad g_2=\gcd(|c|,b).
\]

Then

\[
\frac ab\frac cd
=\frac{(a/g_1)(c/g_2)}{(b/g_2)(d/g_1)}.
\]

Every indicated division is exact. If the original fractions are reduced, the resulting numerator and denominator are coprime: any common prime would have to come from an original same-fraction common factor or one of the two cross factors already removed. Without that premise, a final GCD normalization is still required. Sign handling is separate from the nonnegative GCD kernel.

**Return to NINE65.** Cross-cancellation can lower numerator and denominator growth before multiplication, which can reduce the required public capacity, ciphertext word width or anchor demand. An optimizer must account for the cost of both GCDs and exact divisions; smaller intermediates do not automatically mean a faster encrypted circuit. A useful public decision rule compares a conservative uncancelled bound against available capacity, rather than branching on a secret GCD value outside the circuit.

This pair representation also avoids asking for 1/d in every lane. For instance 1/2 remains the pair (1,2) even in a frame containing a modulus-2 lane; it is not the nonexistent field-style inverse of 2 in that lane. The present `RationalBridge::to_residue` instead calls a modular inverse and panics when it does not exist. A pair transport must therefore be a distinct typed representation, with an explicit refusal or conversion certificate when a consumer requests a single modular scalar.

`CRTRational` already exposes numerator/denominator arithmetic and normalization, but that alone is not a proof that all its underlying integer operations implement the residue-native path. The integration target is a new adapter whose implementation refines the checked divmod/GCD specification, preserves denominator positivity, and proves intermediate capacities.

## 7. Exact-query transport and source authority compose together

The universal theorem assumes its readings come from the specified x and r. Merely supplying two integers that look like residues does not establish that relation. The repository already has an appropriate architectural pattern: private source constructors, immutable bounds, key-family identity, per-source lineage, and an issued canonical-root capability. `accept_refresh` checks family, exact source lineage and root identity before accepting the returned proof.

**Written deduction: source-indexed transport.** Define an observation contract for a semantic source identifier σ, public frame F and query C. A valid readout is a pair of observations with a derivation that they represent h(x_σ) and h(r_σ), plus the source decomposition. Composition is allowed when the output query and the next input refer to the same semantic source, or when an explicit transition certificate relates their sources. Kernel inclusion then proves the value part of each step; source indexing proves that the premises refer to the intended computation.

This distinction matters even for a shared plaintext. Two ciphertexts can encode the same plaintext while having different integer decryption phases and different K_native. The persistent plaintext-root authority is therefore not sufficient to mix one source's phase reading with another source's reference. Conversely a legitimate refresh intentionally changes ciphertext lineage while preserving plaintext-root authority. The type of the query must determine which equality is required.

**Return to CRAM.** A transient readout can feed several consumers safely when the cache key includes the source semantics, lineage/phase identity, frame and query contract. It need not retain K as persistent arithmetic state. Updating the source invalidates the transient value even if a high-level plaintext root remains the same. This connects query-directed computation to proof-carrying capabilities and common-subexpression elimination without creating a hidden magnitude ledger.

**Proposal and falsification.** Build a small sealed adapter shared by StarLift, coefficient-drop and local G/H consumers, with distinct semantic-source tags. Negative tests should exchange views between equal-plaintext/different-lineage ciphertexts, use the wrong frame, or replay a result after an update. The current local capability design is not a remote attestation protocol: a network proof or signature needs an explicit trust and serialization model.

## 8. Error invisibility is a target property, separate from full recovery

**Written deduction.** Suppose DB=C and a supplied defect is Bk+η. If η belongs to im B, additivity gives

\[
D(Bk+\eta)=Ck+D\eta.
\]

The target remains exact whenever Dη=0. Therefore the same kernel reasoning that permits query-specific ambiguity also characterizes observation perturbations invisible to that query. If η lies outside im B, D is not even specified there; an explicit extension or a validity/refusal check is needed. In particular an inverse readout for full coordinate recovery usually has no nonzero invisible perturbation.

**Return to NINE65 and external domains.** This separates three responsibilities: produce authentic observations, establish their perturbation domain, and prove the requested consumer ignores the allowed error. In sensor fusion or modular phase instrumentation, some physical errors can be ignored by a coarse target even when exact source recovery fails. In encrypted evaluation, the ciphertext error certificate has its own semantics and cannot simply be identified with η in a plaintext observation ring. A valid bridge must first prove how decryption error changes the actual observation. This is a precise route for importing robustness ideas into CRAM without conflating algebraic ambiguity with cryptographic noise.

## 9. Verification performed for these deductions

This pass inspected the named source paths and ran an independent Python integer model, not the Rust evaluator or a new encrypted refresh. All assertions passed:

| Check | Finite domain | Cases |
|---|---|---:|
| Nested floor quotient and remainder law | X=−200,…,200; d,e=2,…,13 | 57,744 |
| Fixed 2w-round masked Euclid | Every pair of w-bit unsigned inputs, w=1,…,7 | 21,844 |
| G/H digit identity, residual map and idempotence | p∈{5,7,11}, all 1≤B≤(p−1)/2, residuals −B,…,B and K=−p,…,p | 1,118 |
| Nearest-rounding negative control | X=2,d=3,e=2 | Sequential 1; fused 0 |

These counts describe finite model checks performed on 2026-11-12. They supplement the written arguments; they are not new Lean declarations, current-head Rust regression counts or encrypted performance measurements. The following compact witness reproduces the tests without external dependencies:

```python
from math import gcd, prod

for x in range(-200, 201):
    for d in range(2, 14):
        for e in range(2, 14):
            q, r = divmod(x, d)
            qq, rr = divmod(q, e)
            assert qq == x // (d*e) == (x // e) // d
            assert x % (d*e) == r + d*rr

nearest = lambda x, d: (x + d//2) // d
assert nearest(nearest(2, 3), 2) == 1
assert nearest(2, 6) == 0

for w in range(1, 8):
    for a in range(1 << w):
        for b in range(1 << w):
            x, y = a, b
            for _ in range(2*w):
                q, r = divmod(x, y) if y else (0, x)
                x, y = (y, r) if y else (x, 0)
            assert y == 0 and x == gcd(a, b)

for p in (5, 7, 11):
    for B in range(1, (p-1)//2 + 1):
        roots = list(range(-B, B+1))
        def G(x):
            return prod(x-r for r in roots)
        def H(x):
            total = 0
            for r in roots:
                derivative = prod(r-s for s in roots if s != r) % p
                numerator = prod(x-s for s in roots if s != r) % p
                total = (total + numerator*pow(derivative, -2, p)) % p
            return total
        def F(x):
            return (x-G(x)*H(x)) % (p*p)
        for r in roots:
            for k in range(-p, p+1):
                x = r+p*k
                assert ((G(x) % (p*p))//p * H(x)) % p == k % p
                assert F(x) == r % (p*p)
                assert F(F(x)) == F(x)
```

## 10. Integration order and acceptance targets

1. **Source-indexed query adapters.** Bind source semantics, public frame, authentic observations and exact consumer. Accept only after source-mixing negative tests and a refinement to the universal theorem.
2. **G/H retraction and weighted consumer lemmas.** Add the two written specializations to Lean; retain all root, derivative, coherence and supported-domain hypotheses. Verify candidate circuit cost against the current split evaluation before replacing it.
3. **Floor-drop composition.** Prove the exact signed quotient/remainder law and implement scheduler checks that reject the nearest-rounding counterexample. Measure actual lane work and preserve all claimed recovery data.
4. **Fixed-schedule encrypted GCD prototype.** Compile the 2w-round circuit, exhaust small clear domains, compare native arithmetic oracles, and pass every actual encrypted gate through noise admission. Then build rational pair normalization and cross-cancellation as separate clients.
5. **Robust query contracts.** Introduce perturbation assumptions only where an actual producer justifies them; prove target invariance or a typed refusal. Preserve the distinction between plaintext mathematics, encrypted correctness and complete key-setup confidentiality.

This sequence takes the universal theorem back into concrete NINE65 systems: the theorem determines what information a consumer actually needs; the existing producers, bounds and source authority determine whether that information is available; and implementation refinements connect the two.
