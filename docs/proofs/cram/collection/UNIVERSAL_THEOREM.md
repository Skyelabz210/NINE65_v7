# The universal K-Elimination theorem

12 November 2026. This is the principal theorem candidate for Anthony Diaz's K-Elimination/CRAM proof update and subsequent NINE65 integration. Its constructive additive, ring and integer core is now machine checked. The [standalone Lean package](universal-theorem/README.md) contains 130 theorem declarations: the preceding 75-declaration core plus 55 closure and StarLift declarations. See [CLOSURE_PROOFS.md](CLOSURE_PROOFS.md) for the continuation. A fresh build from source passed, with no admitted proofs or custom axioms.

The generalization concerns **recovering and transporting the information needed by a computation from authentic observed differences**. An integer quotient is one instance. The theorem also describes exactly when a requested result can be obtained without identifying that quotient completely.

## 1. Main statement

Let K, G, H and T be additive commutative groups, with homomorphisms

\[
\iota:K\to G,\qquad h:G\to H,\qquad p:G\to T.
\]

Suppose a valid source has the presentation

\[
x=r+\iota(k).
\]

The implementation receives the source reading h(x), the reference reading h(r), and, for a target query, p(r). The potentially large x, r and k need not be runtime inputs or persistent registers. Define

\[
B=h\circ\iota,\qquad C=p\circ\iota.
\]

**Universal exact-transport theorem.** There is a unique additive map

\[
D:\operatorname{im} B\to T,\qquad D(Bk)=Ck,
\]

if and only if

\[
\boxed{\ker B\subseteq\ker C.}
\]

Whenever this holds,

\[
\boxed{p(x)=p(r)+D\bigl(h(x)-h(r)\bigr).}
\]

**Proof.** Additivity gives h(x)−h(r)=Bk. If Bk₁=Bk₂, then k₁−k₂ lies in ker B. Kernel inclusion gives Ck₁=Ck₂, so D(Bk)=Ck is well-defined. It is additive and unique on im B. Conversely, applying D to Bk=0 proves that ker B is contained in ker C. Finally p(x)=p(r)+Ck yields the displayed transport formula. ∎

The Lean statements are `phase_difference`, `target_factor_exists_iff`, `target_factor_unique`, `target_factor_additive`, and `direct_target_query` in [UniversalLift.lean](universal-theorem/UniversalLift.lean). The additivity statement is expressed on image representatives; no extension of D to every element of H is asserted.

This theorem supplies an exact criterion, not just a sufficient analogy. It permits a target query to ignore uncertainty that would prevent full recovery of k. Full coordinate recovery is the special query k↦k. On an admitted set S its exact criterion is

\[
\boxed{(S-S)\cap\ker B\subseteq\{0\}.}
\]

For an arbitrary query f on S, the criterion is Bk₁=Bk₂ ⇒ f(k₁)=f(k₂), for k₁,k₂∈S. These equivalences are also checked. A concrete constructor for D or for the admitted-domain decoder supplies the algorithm; an existence proof alone does not supply its cost.

## 2. The fast constructor is a proved instance

Let R and H be rings, possibly noncommutative, and let h preserve addition and multiplication. If

\[
X=r+MK,\qquad u\,h(M)=1,
\]

then

\[
\boxed{u\bigl(h(X)-h(r)\bigr)=h(K).}
\]

Indeed h(X)−h(r)=h(M)h(K), and left multiplication by u cancels h(M). For X=r+KM, the matching theorem uses a right inverse on the right. These are actual ring theorems; neither commutativity nor integer CRT reconstruction is used in their proofs.

The implemented readout is exactly

```text
defect := source_reading - reference_reading
coordinate_reading := inverse * defect
```

[RingReadout.lean](universal-theorem/RingReadout.lean) proves its result from the decomposition and inverse laws. [CostedReadout.lean](universal-theorem/CostedReadout.lean) defines an expression language, evaluates this program, and proves that it contains **one subtraction and one multiplication**. It also proves that this ring program instantiates the universal additive theorem; query correctness is not assumed to obtain query correctness.

Thus the O(1) statement has a precise meaning: a constant number of arithmetic operations in a supplied observation ring, with the two authentic readings and public inverse available. For a fixed-width modular lane these are two modular operations. Polynomial degree, matrix dimension, variable integer bit width, producing the observations, signed representative selection, and encrypted circuit realization have their own costs. The theorem identifies the reusable constant-operation kernel.

For integer adjacent anchors A=M+1, the inverse is −1 and the program reduces to

\[
K\bmod(M+1)=(\text{reference reading}-\text{source reading})\bmod(M+1).
\]

The subtraction-only expression and its operation count are checked too. Star anchors A=cM+1 have the proved public inverse −c.

## 3. Exact magnitude and arbitrary target moduli

Take X,r,M,K∈ℤ with X=r+MK, and an anchor A>0. Let

\[
t=r\bmod A,\qquad s=X\bmod A,\qquad uM\equiv1\pmod A.
\]

The computed query is

\[
q=((s-t)u)\bmod A=K\bmod A.
\]

If K is in [0,A), q is K itself. More generally, a public interval [ℓ,ℓ+A) gives the explicit selector

\[
K=\ell+((q-\ell)\bmod A).
\]

For the Euclidean reference r=X mod M, M>0, the source bound 0≤X<MA implies K=⌊X/M⌋∈[0,A). This is exact on-demand magnitude information. It does not require constructing X from the result.

For every target modulus b>0, once K is exact,

\[
X\bmod b=\bigl(t_b+m_b(K\bmod b)\bigr)\bmod b,
\quad t_b=r\bmod b,\quad m_b=M\bmod b.
\]

There is **no coprimality requirement on the target b**. The runtime projection consumes target-lane views and a transient coordinate; it does not assemble r+MK.

The stronger query theorem often avoids even exact K. If K is known modulo R, its unknown multiples of R change X by multiples of MR. Consequently, for fixed reference r and all integer coordinates,

\[
X\bmod b\text{ is determined by }K\bmod R
\quad\Longleftrightarrow\quad b\mid MR.
\]

The forward implication follows by comparing K=0 and K=R; the reverse follows by reducing MR modulo b. This is the integer form of ker B⊆ker C. The Lean package proves the concrete target program's sufficiency for the unit and reduced-nonunit queries. Its runtime arguments are t, s, t_b and m_b; large source and reference values occur only in the proof.

For example, M=6 and A=10 provide quotient resolution R=5. X=1 and X=31 have the same two source residues and different integer quotients. Their residues modulo 15 are nevertheless determined exactly, because 15 divides MR=30. Both yield 1. A target modulo 7 needs a distinguishing window or additional authentic information. This demonstrates query-specific transport directly.

## 4. Nonunits and combined observations

For a commutative ring, an observer ideal J, and X=r+MK, all compatible lifts form exactly

\[
\boxed{K_0+(J:M),\qquad (J:M)=\{v:Mv\in J\}.}
\]

The ring proof establishes this fiber and closure of the ambiguity set. In a noncommutative ring the corresponding set is a right ideal. A sided inverse removes the multiplier's ambiguity, leaving exactly the observer kernel. Invertibility is a sufficient fast constructor, not a necessary condition for recoverability: multiplication by 2 on ℤ is injective and has a decoder on 2ℤ, although 2 is not a unit in ℤ.

For positive integers, choose d=gcd(M,A), m=M/d and a=A/d. Authentic readings imply d|(s−t). With um≡1 mod a,

\[
\boxed{q=\left(\frac{s-t}{d}u\right)\bmod a=K\bmod a.}
\]

[IntegerSpecialization.lean](universal-theorem/IntegerSpecialization.lean) proves the actual formula, derives defect divisibility, and proves signed-window recovery and direct target transport. Its hypotheses provide d|M, d|A and the reduced inverse certificate; constructing d and that inverse is preprocessing. The nonunit formula includes exact division by d, so its operation count differs from the two-operation unit constructor.

For multiple anchors Aᵢ, let L=lcmᵢ Aᵢ. The combined coordinate resolution and source period are

\[
R=\frac{L}{\gcd(M,L)},\qquad MR=\operatorname{lcm}(M,A_1,\ldots,A_n).
\]

The proof is that a difference v is invisible exactly when every Aᵢ divides Mv, equivalently L|Mv, equivalently R|v. The combined-anchor specialization, minimal positive resolution, actual reading equivalence, and both directions of the target criterion are now checked in [CoupledAnchors.lean](universal-theorem/CoupledAnchors.lean).

## 5. What the universal theorem organizes

| Consequence | Mathematical construction | Current formal scope |
|---|---|---|
| Magnitude | Unit or reduced-anchor query plus an admitted integer window | Computed query, signed/unsigned windows and uniqueness checked |
| Arbitrary target modulus | Target reference plus transported correction | Concrete program checked, including targets sharing factors and transport without exact K |
| Non-coprime solving | Kernel/ideal-quotient fiber and reduced congruence | General fiber and certified integer reduction checked; automatic GCD/inverse generation remains separate |
| Polynomial division | Work in F[z]/(A); use the inverse of M and a degree window | Generic ring constructor checked; concrete polynomial/degree specialization has a written proof and prior finite experiments |
| Lattice and matrix queries | A linear factor D with DB=C; admitted-domain separation | Additive theorem checked; matrix/lattice algorithms and their cost are written specializations |
| Comparison, general divmod and GCD | Exact comparison/subtraction or stronger division primitives; Euclidean iteration | Complete bounded loops and all concrete paired-residue primitive laws are now Lean-checked; zero division is refused |
| Transduction and finite programs | Each primitive preserves encoding; compose its refinement | Abstract finite composition and valid-state round trips checked; concrete NINE65 refinements remain to add |
| Tropical and continuum applications | Recover specified chart/sheet information, then apply the domain's proved formula | Existing theta and conservative interpolation derivations; a general dynamics/analytic-limit theorem is separate |

Division and GCD belong under this framework. Given an exact residue-space divmod primitive, Euclid preserves gcd(a,b)=gcd(b,a mod b), and the positive second operand decreases until zero. This proves the algorithmic route without requiring scalar reconstruction or a persistent K register. The existing [residue-only model](expanded-corpus/experiments/compendium_residue_divmod_gcd.py) supplies a constructive witness; its earlier 37,701 GCD checks now have a corresponding complete Lean loop formalization and concrete primitive instance. The constant-operation K query is one primitive in such a computation, not a statement that Euclid takes one step.

For tropical applications, the subtraction occurs in the specified lifted group/ring or chart. A min-plus observation can discard information, so the exact-observation criterion states which query survives. The supplied theta-sheet formula and conservative continuum interpolation provide concrete instances in the [tropical addendum](TROPICAL_FHE_ADDENDUM.md). A group-action/stabilizer extension, covering-space qualifications, and detailed polynomial/lattice proofs appear in the [mathematical review](universal-theorem/MATHEMATICAL_REVIEW.md).

## 6. Verification and integration

The [verification manifest](universal-theorem/verification.json) records all 130 declarations, source hashes and transitive axioms. The [build log](universal-theorem/verification.log) comes from a new temporary build: no project `.olean` files were reused. The package uses the pinned Lean4.27.0-rc1 bundled standard library and has no Mathlib dependency. Thirty declarations are axiom-free; the remainder use only standard Lean `propext`, `Classical.choice`, or `Quot.sound`. The existence directions use classical choice, while the unit and integer query definitions are explicit executable formulas.

This is a candidate proof package, ready to review and integrate. The original public Lean and NINE65 checkouts have not been modified. Their pinned revisions and previous build/runtime evidence remain in the [research README](README.md). The next formal work is an implemented multi-anchor fusion decoder, polynomial/degree and lattice instances, and refinement of the actual NINE65 producers and consumers against this common contract. StarLift and the concrete bounded divmod/GCD programs are now checked in the continuation.

The contribution statement should center Anthony Diaz's full K-Elimination/CRAM construction: its supplied observations, on-demand queries, supported domains, state policy, and composition. A shared CRT/Garner algebraic ingredient does not establish that the entire construction was previously disclosed. The abstract kernel-factorization principle itself is standard algebra; this proof work establishes the precise general theorem and constructive instances to which a claim-level novelty comparison can be applied.
