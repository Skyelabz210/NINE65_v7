# Expanded portfolio and compendium review

Date: 2026-11-12. Scope: five assigned PDF documents, read in full as extracted text (244 pages total). This is a mathematical/source review with an independently executed finite-field model. It does not certify unrelated portfolio claims, re-run historical benchmarks, or change production code.

The strongest additional lead is the explicitly proposed **Cycle-Tracking Invariant** in the March 3 QMNF compendium. It proposes a common framework for quotient extraction, winding, spatial lattice decoding and phase geometry. This deserves evaluation as a generalization and constructive architecture. Showing that one scalar formula also occurs in Garner does not establish that the entire framework was previously given.

A precise general theorem can be stated in commutative-ring language, with integer, polynomial and lattice specializations. The compendium's bounded integer quotient proof supports that direction. Some of its claimed identifications with topology, polynomial degree and FHE require correction or separate premises. These document-level problems do not negate later source-bound NINE65 implementations.

## Coverage and provenance

All line references below are to the extracted files under expanded-corpus; the extraction manifest contains original paths and SHA-256 values.

| Source | Read coverage | Role in this audit |
|---|---|---|
| text/9-PROOFS.pdf.txt, 6 pages, 292 newline-counted lines | Full extracted text, all 20 numbered results | Duplicate of the previously supplied PROOFS artifact; also duplicated by new input 21. Valid bounded K, order and arbitrary-target projection results; qualifications below. |
| text/15-report.pdf.txt, 11 pages, 616 lines | Full extracted text | Secondary Kimi review of ECO-PRIME/Safe-Basis claims. Useful source index, not a primary division proof or execution artifact. |
| text/17-Master-Portfolio-Document-2.pdf.txt, 133 pages, 6,938 lines | Full extracted text | Conversation-derived HackFate portfolio and catalogs. Contains no K-Elimination, CRAM or NINE65 theorem, residue division construction, or gcd algorithm. Its general AI/physics catalogs are not additional proof obligations for the present K theorem. |
| archive-text/11-workspace/*COMPREHENSIVE_UNIFIED_COMPENDIUM_2025.pdf.txt, 40 pages, 1,955 lines | Full extracted text | February 2026 synthesis despite the filename. K-specific passages conflate inverse multiplication with division; other-domain interpretations supply no additional K proof. |
| archive-text/11-workspace/*QMNF_ULTIMATE_MATHEMATICAL_COMPENDIUM_V7.pdf.txt, 54 pages, 1,832 lines | Full extracted text | March 3, 2026 technical synthesis. Strongest new generalization target, bounded integer theorem and historical pseudocode. Last page ends mid-sentence; no missing conclusion was inferred. |

“Full extracted text” does not mean every PDF image was independently inspected. Relevant formulas were present as selectable text. The portfolio's personal/commercial conversation is not quoted or incorporated into technical conclusions. Claims of prior verification in these documents are recorded as source assertions unless accompanied by fresh proof/execution evidence.

## A general theorem that actually captures the mechanism

Let \(R\) be a commutative ring, \(J\) an ideal, and \(M,r,X\in R\). Suppose the source identity is

\[
X=r+MK.
\]

The observer supplies the image of \(X\) in \(R/J\); the chosen base chart supplies \(r\). Define

\[
(J:M)=\{u\in R:Mu\in J\}.
\]

This is an ideal. If \(K_0\) is one solution of the observed equation, then **all solutions are exactly**

\[
K_0+(J:M).
\]

Proof: \(r+MK\equiv X\pmod J\) and \(r+MK_0\equiv X\pmod J\) hold simultaneously iff \(M(K-K_0)\in J\), iff \(K-K_0\in(J:M)\). This proves necessity and sufficiency, including nonunit and shared-factor cases.

For a declared admissible set \(S\subseteq R\), the observation determines every possible \(K\in S\) uniquely iff

\[
\forall k_1,k_2\in S,\quad k_1-k_2\in(J:M)\Longrightarrow k_1=k_2.
\]

When \(M\) is a unit modulo \(J\), with inverse \(u\in R/J\),

\[
\overline K=u(\overline X-\overline r).
\]

This is one general theorem with constructive specializations. It is not limited to integer residues or to prime/coprime auxiliary targets. It also states exactly what must be supplied by a source, chart and range certificate. The theorem is a hand-derived algebraic result in this review, not yet a newly compiled Lean theorem and not a claim that ideal quotients are new mathematics.

**Integer specialization.** In \(R=\mathbb Z\), \(J=(A)\), \(M,A>0\),

\[
(J:M)=\left(A/\gcd(M,A)\right).
\]

Thus the exact quotient resolution is \(A/\gcd(M,A)\), with the familiar inverse formula when the gcd is one. With multiple authentic observers, replace \(J\) by \(\bigcap_i(A_i)=(L)\), \(L=\operatorname{lcm}_iA_i\), obtaining \(L/\gcd(M,L)\). This derives the coupled-anchor law without requiring pairwise coprime anchors.

**Polynomial specialization.** Let \(F\) be any field and \(M,A\in F[t]\) be nonconstant coprime polynomials. For authentic remainders

\[
r=X\bmod M,\qquad s=X\bmod A,
\]

the Euclidean quotient \(Q\) in \(X=MQ+r\) satisfies

\[
Q\bmod A=(s-r)M^{-1}\bmod A.
\]

If \(\deg X<\deg M+\deg A\), then \(\deg Q<\deg A\), so the returned polynomial is the exact quotient. Proof: reduce the Euclidean division identity modulo \(A\), multiply by the Bézout inverse, and use uniqueness of the reduced representative. Monicity is convenient for implementation but unnecessary over a field.

For shared factors, the same ideal theorem yields quotient resolution modulo \(A/\gcd(M,A)\), up to a unit; for monic gcd/lcm the representatives are canonical. This is a rigorous polynomial counterpart of the integer construction. It differs from treating the integer \(\lfloor\deg X/\deg M\rfloor\) as the quotient polynomial.

**Projection without emitting the full source.** Given the exact queried \(K\), any ring homomorphism \(h:R\to T\) obeys

\[
h(X)=h(r)+h(M)h(K).
\]

The consumer can compute this directly in \(T\). It need not first construct \(X\) in a positional representation. Computing \(K\) on demand is sufficient; the theorem imposes no persistent scalar-K register. The producer still has to deliver the bound/source identity and any required images of \(r,K\). Their cost cannot be omitted from an implementation claim.

## What the documents establish positively

1. **Bounded integer extraction is proved.** PROOFS Theorem 3 (lines 43–59, pp. 1–2) and Ultimate §4.2 (lines 429–455, pp. 13–14) correctly assume \(0\le X<MA\), authentic residues and \(\gcd(M,A)=1\). The equality to the integer quotient follows because \(0\le K<A\).

2. **Arbitrary-target projection is correctly broader than coprime extraction.** PROOFS Theorem 5 (lines 67–81, p. 2) allows every \(a'\ge1\), including composite and shared-factor targets. Theorem 20 (lines 274–290, p. 6) spells out reduction of the terms before multiplication, avoiding emission of \(X\). This is a valid answer to a claim that every rebasing operation inherently requires emitting the integer first. It does not by itself prove availability of each required operand on every encrypted path.

3. **Comparison is an exact consumer of quotient and remainder.** PROOFS Theorem 6 (lines 83–96, p. 2) correctly proves lexicographic order for exact \(K\) and normalized \(0\le r<M\). “Two comparisons independent of magnitude” is a count of comparisons, not a bit-complexity bound on unbounded operands.

4. **Finite faithful base and per-lane operations are correct with their stated scope.** PROOFS Theorems 1, 7, 8, 11 and 12 establish CRT encoding, coordinatewise add/multiply, invertible exact division, independence of genuinely coordinatewise operators, and injectivity within a complete representative window. Safe-Basis \(\{2,3,5,7,11,13\}\) has product \(30030\). These statements support the substrate; they do not imply that every order, division or gcd consumer reads only its own lane.

5. **A common covering/lift program is explicitly proposed.** Ultimate §2 (lines 248–285, pp. 8–9) names the Cycle-Tracking Invariant and maps discrete quotient, dual-anchor recovery, continuous floor, nearest-lattice decoding and geometric phase into a shared program. This is substantive evidence of intended generalization. The object table is a research specification, not by itself a proof that all five maps preserve the same invariant under all inputs.

6. **Relative phase is a genuine additive character.** Ultimate §6.1 (lines 737–766, pp. 21–22) proves the modular additivity of

\[
\varphi(X)/(2\pi)=X/A-X/M\pmod1.
\]

For coprime \(M,A\), its exact period is \(MA\): the integer numerator is \((M-A)X\bmod MA\), and \(\gcd(M-A,MA)=1\). Thus exact relative phase alone is an injective label on that finite window. This is an exact-rational statement; finite-precision angular measurement requires a separate noise/separation analysis.

More generally write \(M=gm,A=ga\), \(\gcd(m,a)=1\), and \(L=\operatorname{lcm}(M,A)=gma\). The relative-phase period is

\[
P=\frac{L}{\gcd(m-a,g)}.
\]

Proof: the exact phase numerator is \((m-a)X\bmod L\); \(\gcd(m-a,ma)=1\). This can be smaller than the joint residue period \(L\). For \(M=6,A=10\), values 0 and 15 have the same relative phase, but different residue pairs; \(P=15\) and \(L=30\). This identifies the exact shared-factor qualification for this particular phase map.

## Corrections needed before using the historical synthesis as proof

**The polynomial quotient must be a well-defined object.** Ultimate Theorem 9.1 (lines 1039–1074, pp. 30–31) starts with a quotient-ring element in \(F[t]/(f)\), then assigns it a degree-overflow count \(\lfloor\deg p/\deg f\rfloor\). Degree depends on the chosen polynomial representative. In \(F_2[t]/(t^2+1)\), representatives \(1\) and \(t^2\) describe the same element but give counts 0 and 1. Authentic extra views of the unreduced source can resolve that ambiguity, as the polynomial theorem above shows. The source must therefore be the unreduced polynomial plus its observations, or a specified canonical representative, not merely the already reduced element.

**The historical general-division pseudocode does not establish its advertised algorithm.** Ultimate §4.3 (lines 467–515, pp. 14–15) delegates its difficult step to an unspecified div_mod helper and then applies

\[
q_i\leftarrow(q_i+k_i(M\bmod m_i))\bmod m_i.
\]

Since each \(m_i\mid M\), this correction is identically zero. If div_mod means scalar floor division of lane representatives, \(X=8,d=2\), lanes \(7,11\), anchor 13 yields \((0,4)\), while the true integer quotient 4 has residues \((4,4)\). If the helper instead computes modular inverse multiplication and exact divisibility is assumed, the output can already be correct, but this does not solve arbitrary quotient/remainder or nonunits. The code is historical pseudocode with missing helpers, not the present NINE65 encrypted word-division or FPD implementation.

**An open-path angular integral needs its fractional endpoint.** Ultimate Theorem 6.1 (lines 770–809, pp. 22–23) equates

\[
\lfloor X/M\rfloor\quad\hbox{with}\quad
\frac1{2\pi}\int_0^1\frac{d\theta_M}{dt}\,dt.
\]

For the continuous lift \(\widetilde\theta_M(t)=2\pi tX/M\), the integral is \(X/M\), not its floor. \(X=1,M=2\) gives \(1/2\) versus 0. The correct chart-index formula is

\[
K=\frac{\widetilde\theta_M(1)-\theta_M(1)}{2\pi}
  =X/M-r/M.
\]

For a closed circle loop with a fixed starting lift, its integer winding is a homotopy invariant. For a general open path, fixing the endpoint chart or closing convention is essential. Crossing a chart cut can change the floor coordinate without any singularity in the circle path. This correction preserves the covering-space interpretation and makes its assumptions explicit.

**Generic Berry holonomy is not integer winding.** Ultimate §6.3 (lines 810–839, pp. 23–24) states that every closed-path Berry phase is \(2\pi n\). The normalized closed state path

\[
\psi(\phi)=2^{-1/2}(1,e^{i\phi}),\qquad 0\le\phi\le2\pi
\]

has \(i\langle\psi|\partial_\phi\psi\rangle=-1/2\), hence Berry phase \(-\pi\), not \(2\pi n\). Integer Chern numbers concern curvature integrals over suitable closed two-dimensional surfaces; generic loop holonomy is a different object. A K-to-physics specialization must define its actual connection and quantization assumptions.

**The Montgomery/Möbius equivalence is not proved as stated.** Ultimate §5.4 (lines 713–732, p. 21) calls the finite Montgomery domain \(\{xR\bmod m\}\) a covering space isomorphic to a Möbius strip. For \(\gcd(R,m)=1\), this finite map is a bijective coordinate change on \(\mathbb Z/m\mathbb Z\). A finite discrete set is not homeomorphic to a two-dimensional Möbius manifold. One may construct an additional geometric model, but its topology and relationship to arithmetic must be specified; the coordinate conversion itself does not establish that identification.

**Exact evaluation and inverse arithmetic require the right semantics.** The February compendium calls \(a\,b^{-1}\bmod M\) “K-Elimination division” (lines 609–636 and 1431–1437). This does not express arbitrary Euclidean division without a divisibility/remainder mechanism. Its exact rational evaluation of \(1618033989/10^9\) (lines 1452–1462) is not exact equality to the irrational golden ratio. These distinctions preserve useful integer implementations while keeping their approximation target explicit.

**Formal-verification and FHE claims are not established by status prose.** Ultimate §21–23 (lines 1591–1664, pp. 46–48) asserts 100% Lean/Coq/constant-time coverage without the source revisions, statements, build logs and transitive axioms needed to verify that claim. Its §8 “bootstrap-free” pseudocode (lines 908–988, pp. 26–28) also uses the zero correction \(K(M\bmod m_i)\), followed by modular inversion as rescaling. Those passages do not prove arbitrary-depth encrypted correctness. The current NINE65 guide explicitly distinguishes working opt-in encrypted G/H refresh from disabled legacy Clockwork and requires source-specific evidence. Current proof/build evidence must take precedence over this March synthesis.

Two smaller precision corrections in PROOFS:

- Theorem 2 says the Fermat inverse formula works “only when m is prime.” Prime \(m\) is sufficient, and arbitrary composites are unsafe, but “only” is false: Carmichael \(561=3\cdot11\cdot17\) satisfies \(a^{559}=a^{-1}\pmod{561}\) for all 320 units. Extended Euclid remains the correct general implementation recommendation.
- Theorem 17's finite-set entropy criterion \(H(X\mid g(X))=0\) iff \(g\) is injective on full support is correct. Its explanation that non-singleton fibers are precisely “breaking the homomorphism” is false: the zero homomorphism is maximally noninjective, and an injective map need not be a homomorphism. Reversibility follows from injectivity, not from exact arithmetic alone.

## Source quality of the other two documents

The 133-page Master Portfolio is useful as a historical catalog, but its proof labels point to other documents and do not supply K-specific derivations. The explicit homomorphic demo at lines 1615–1635 uses Paillier addition, not NINE65 or generalized residue division. It should not be counted as a new K theorem or current runtime verification.

The 11-page ECO-PRIME report contains valid elementary facts such as minimal product of six distinct primes and the 143-cell grid's \(120\) nonzero-coordinate cells. It also contains basic internal errors: it calls \(\{2,3,5,7,11,13\}\) six odd primes/a septuple (lines 21–22), and quotes \(\varphi(210)/210\) as 45.71% while correctly stating \(\varphi(210)=48\) elsewhere (lines 49 and 116–118). Its displayed overlapping PARKING moduli are not pairwise coprime, so invoking the unrestricted product CRT for that particular tuple needs the generalized compatibility condition (lines 73–100). These are reasons to verify its assertions from primary definitions, not evidence against a separately proved CRAM mechanism.

The 40-page February compendium mixes correct elementary modular/calendar relations with interpretations across physical and cognitive domains. It does not give the required source maps, preservation theorems or proof artifacts for those interpretations. Its direct K passages were examined above. No physical universality conclusion is inferred from a finite modular identity.

## Reproducible independent evidence

Run:

    python3 expanded-corpus/experiments/portfolio_polynomial.py

Files:

- [Independent finite-field model](../experiments/portfolio_polynomial.py)
- [Fresh results](../experiments/portfolio_polynomial_results.json)

The model exhausts all monic \(M,A\) of degrees 1 or 2 over \(F_2,F_3,F_5\):

| Check | Fresh result |
|---|---|
| Coprime anchor pairs | 834 |
| Exact bounded polynomial quotient recoveries | 343,600 passed |
| Arbitrary-target projections, including targets sharing factors with \(M\) | 343,600 passed |
| Authentic-view aliases \(X\) versus \(X+MA\), with distinct quotient \(Q\) versus \(Q+A\) | 343,600 confirmed |
| Noncoprime pairs excluded from the unmodified inverse formula | 246 |
| Exact relative-phase period law | 576 modulus pairs; 64,664 observations passed |
| Historical lane-floor division negative control | Incorrect \((0,4)\) versus true \((4,4)\), as predicted |
| Quotient-ring degree ambiguity | Same class, degree-overflow counts 0 and 1 |
| Carmichael inverse qualification | All 320 units modulo 561 passed |

The alias controls show that the test distinguishes quotient equality from equality modulo the anchor. They do not show failure of a larger representation that retains additional authentic observations. These finite checks support the hand proofs; they do not replace universal proofs or establish Rust refinement.

## Suggested Lean proof surface

The generalized update should expose a common algebraic theorem and explicit applications:

1. Solution-fiber theorem for \(r+MK\) observed modulo an ideal, including nonunits through \((J:M)\).
2. Uniqueness on an admissible set, separately from the congruence calculation.
3. Polynomial exact-quotient extraction with authentic remainder premises and a degree window.
4. Arbitrary-homomorphism projection from a queried lift, with no full-source emission required by the mathematical algorithm.
5. Circle/lattice chart transition and endpoint-normalized deck-index statements, separately from Berry holonomy.
6. An implementation refinement that proves each concrete producer supplies the observations and bounds assumed by these statements.

This would make the generalization visible in the theorem itself. Its novelty should then be assessed against prior work with matching domains, observations, outputs, computation and guarantees. Shared scalar algebra is not enough to settle that comparison.
