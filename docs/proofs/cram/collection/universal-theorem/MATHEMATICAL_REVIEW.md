# Constructive universal K-Elimination: observed extensions and direct queries

Status: initial core mathematical review and theorem specification, 2026-11-12. **Continuation:** [CLOSURE_REVIEW.md](CLOSURE_REVIEW.md) reviews the subsequent 55 declarations; the current package totals 130. Combined-anchor GCD/LCM identification, target-divisibility necessity, reference-change invariance, concrete bounded divmod/GCD, and StarLift are now formally checked. The original review below records the preceding 75-declaration core. The core additive, ring, integer, and operation-count statements have passed a fresh Lean build: the initial build recorded 75 theorem declarations, including 9 reused observation theorems and 66 new declarations. This file supplies additional proofs on paper and reviews the checked layer. Section 11 identifies the checked subset and the distinction between theorems with a readout obligation and explicit programs that discharge it. The matrix, lattice, general group-action, polynomial-degree, and analytic applications below remain written mathematical applications rather than checked formal instances.

## 1. Main finding

A substantive universal theorem is available. Its common operation is **subtract an observed reference, resolve the resulting displacement, and transport only the requested information**. Full scalar reconstruction and persistent storage of the displacement are unnecessary.

The strongest useful formulation distinguishes three objects:

1. the space of possible displacements;
2. the portion of a displacement distinguished by the observations;
3. the portion needed by the requested operation.

For additive or module observations, their relationship has the exact algebraic criterion

\[
\boxed{\ker(\text{observed displacement})\subseteq
       \ker(\text{requested displacement}).}
\]

This criterion permits direct target queries even when full K recovery is impossible. The familiar unit-anchor subtraction and multiplication is an explicit, particularly cheap constructor for this theorem. Polynomial quotient recovery, matrix and lattice displacement recovery, non-coprime anchors, and relative lifts are other constructors with their own cost models.

There are two different universal claims here. The algebraic theorem classifies exactly which additive queries can be recovered from an observed extension. The constructive theorem additionally provides a specified algorithm for the resulting factor map. Kernel inclusion proves existence and uniqueness on the attainable observations; it does not, by itself, supply a uniformly cheap algorithm over every algebraic structure.

This is compatible with a meaningful generalization of K-Elimination beyond its original integer formula. Familiar arithmetic ingredients do not settle whether the full architecture, invariant, applications, or general theorem were previously presented. This mathematical review makes no unsupported historical priority determination.

## 2. Universal observed-extension theorem

Let \(K,V,H,T\) be abelian groups, written additively. Let

\[
\iota:K\to V,\qquad h:V\to H,\qquad p:V\to T
\]

be additive homomorphisms. A valid source state has an affine presentation

\[
x=r+\iota(k).
\]

Here \(r\) is a reference lift. It need not be the least nonnegative representative. The implementation need only obtain the required views of \(r\), not materialize a large scalar \(r\) or \(x\).

Define

\[
B=h\circ\iota:K\to H,\qquad C=p\circ\iota:K\to T.
\]

The authentic observed defect is

\[
\delta=h(x)-h(r)=B(k).
\]

### Theorem A: exact query resolution

The following statements are equivalent:

1. \(\ker B\subseteq\ker C\).
2. Whenever \(B(k_1)=B(k_2)\), one has \(C(k_1)=C(k_2)\).
3. There is a unique homomorphism
   \[
   D:\operatorname{im}B\to T
   \]
   such that \(D(B(k))=C(k)\) for every \(k\in K\).

Under these equivalent conditions,

\[
\boxed{p(x)=p(r)+D\bigl(h(x)-h(r)\bigr).}
\]

**Proof.** If \(B(k_1)=B(k_2)\), then \(k_1-k_2\in\ker B\). Kernel inclusion gives \(C(k_1-k_2)=0\), hence \(C(k_1)=C(k_2)\). Conversely, apply statement 2 to \(k\in\ker B\) and \(0\). Define \(D(B(k))=C(k)\); statement 2 makes this independent of the chosen preimage. Additivity and uniqueness follow immediately from additivity of \(B,C\) and the definition of the image. Finally, additivity of \(h,p\) gives \(\delta=B(k)\) and \(p(x)=p(r)+C(k)=p(r)+D(\delta)\). ∎

This proof works for modules over a ring, with linear maps throughout, and then \(D\) is linear on the image submodule. Commutativity of the coefficient ring is not needed for this module statement.

### What this theorem does and does not assume

- It does not assume that \(\iota\) is injective. Recovering a requested source property may not require identifying the coordinate \(k\).
- It does not assume that all observations are realizable. The domain of \(D\) is the image of \(B\).
- It does not assume a global inverse for the observer.
- It does require authentic observations of the same source and reference, using the same frame.
- It does require a means to evaluate \(D\). Concrete constructors appear below.

An important domain qualification: kernel inclusion need not produce a homomorphism on **all** of \(H\). For \(B:\mathbb Z\to\mathbb Z\), \(B(k)=2k\), and \(C(k)=k\), the unique factor is \(D:2\mathbb Z\to\mathbb Z\), \(D(2k)=k\). It cannot extend to an additive homomorphism \(\mathbb Z\to\mathbb Z\), since such an extension would require \(2D(1)=1\). A program can reject non-image inputs, or have correctness promised only for authentic inputs. A universal theorem must not silently strengthen image-level recovery to a total linear inverse.

### Theorem B: constructive interface

Suppose the frame supplies an explicit program \(\mathsf{transport}\) which, for authentic defects, satisfies the independently proved operator law

\[
\mathsf{transport}(B(k))=C(k).
\]

Then the following program computes \(p(x)\):

```text
delta := observed_x - observed_reference
answer := target_reference + transport(delta)
```

The proof is Theorem A's last identity. Its computational content comes from constructing `transport` from frame data—an inverse scalar, a matrix solve, or a certified quotient solver—and proving the operator law algebraically. Merely defining `transport` to mean “recover the correct answer” would be circular and would add no algorithm.

The instruction count is the cost of the two displayed group operations plus the cost of the supplied transport. K need never be stored persistently, and the program need never assemble \(x\).

### Exact displacement is a special case

For direct coordinate recovery, one asks for \(C(k)=k\). On the full coordinate group this is possible exactly when \(\ker B=\{0\}\). Finite residue observations cannot satisfy that condition for unbounded integer coordinates.

For a promised admissible set \(S\subseteq K\), the exact condition instead is

\[
(S-S)\cap\ker B\subseteq\{0\}.
\]

For a restricted query \(f:S\to U\), the necessary and sufficient condition is

\[
k_1,k_2\in S,\ B(k_1)=B(k_2)\Longrightarrow f(k_1)=f(k_2).
\]

The set-level version need not give a homomorphism, and it need not give an efficient inverse. Its constructive content must again come from the admissible-domain algorithm. This is where bounded integer windows, polynomial degree bounds, and lattice fundamental domains enter.

## 3. Explicit scalar constructors

### 3.1 Unit anchor: the exact two-operation kernel

Let \(R\) be a commutative ring and \(J\) an ideal. Suppose

\[
x=r+mk
\]

and the class \(\bar m\in R/J\) is a unit. Write \(s=\bar x\), \(t=\bar r\), and precompute \(u=\bar m^{-1}\). Then

\[
\boxed{\bar k=(s-t)u.}
\]

**Proof.** \(s-t=\bar m\bar k\); multiply by \(u\). ∎

There is a sided noncommutative ring version: for a multiplicative additive observation \(h\), a decomposition \(x=r+mk\), and a left inverse \(u h(m)=1\), the correct program is \(u(h(x)-h(r))=h(k)\). A decomposition \(x=r+km\) instead uses a right inverse on the right. Thus commutativity is not necessary for the concrete readout when multiplication order is specified.

The online kernel is exactly one subtraction and one multiplication in \(R/J\), with \(s,t,u\) available. It returns the coordinate class. An admissible-domain selector may upgrade that class to an exact coordinate. The selector's cost is a separate, explicit part of any such implementation.

For \(R=\mathbb Z\), \(J=A\mathbb Z\), and \(m=M\), this gives

\[
k\bmod A=((x\bmod A)-(r\bmod A))M^{-1}\bmod A.
\]

If \(k\in\{a,a+1,\ldots,a+A-1\}\), the unique integer coordinate is

\[
k=a+\bigl((\bar k-a)\bmod A\bigr).
\]

If \(0\le x<MA\) and \(r=x\bmod M\), then \(0\le k<A\), so the canonical modular output already is the exact quotient. The sufficient bound is a bound on \(k\), not a comparison such as \(A>M\).

The theorem applies to any reference \(r\equiv x\pmod M\). A signed window for \((x-r)/M\) may replace the canonical quotient window. This supports relative lifts without full reconstruction.

### 3.2 Nonunit anchor: exact ambiguity, not failure

Over a commutative ring, with no assumption that \(\bar m\) is invertible, the observed equation is

\[
mk\equiv x-r\pmod J.
\]

If \(k_0\) is one solution, **all** solutions are exactly

\[
k_0+(J:m),\qquad
(J:m)=\{v\in R:mv\in J\}.
\]

**Proof.** \(k\) and \(k_0\) give the same observation precisely when \(m(k-k_0)\in J\). ∎

Equivalently, on \(R/J\), the ambiguity is the annihilator of \(\bar m\). The unit case has zero annihilator in the quotient, so it recovers the full quotient-ring coordinate. A nonunit can nevertheless determine a particular target query whenever that target annihilates the remaining ambiguity.

A unit is sufficient for the two-operation constructor, not necessary for exact recovery. A nonunit can have zero annihilator: multiplication by \(2\) in \(\mathbb Z\) is injective and has an exact decoder on \(2\mathbb Z\), although \(2\) has no integer multiplicative inverse. This separates the information criterion from the particular cheap inverse-multiply implementation.

For positive integers \(M,A\), let \(d=\gcd(M,A)\). A congruence

\[
Mk\equiv\delta\pmod A
\]

has a solution exactly when \(d\mid\delta\). In that case define \(R=A/d\). For \(R>1\),

\[
k_0=\frac{\delta}{d}\left(\frac M d\right)^{-1}\bmod R,
\qquad
k\in k_0+R\mathbb Z.
\]

For \(R=1\), there is a single residue class carrying no coordinate discrimination. The formula is a reduced-modulus solve, with exact divisibility checked or certified. It removes a blanket coprimality requirement while stating exactly what resolution is available.

Multiple authentic anchor observations \(A_1,\ldots,A_t\) produce

\[
L=\operatorname{lcm}(A_1,\ldots,A_t),\qquad
R=\frac{L}{\gcd(M,L)}.
\]

The displacement ambiguity is \(R\mathbb Z\), and the source ambiguity is

\[
MR\mathbb Z=\operatorname{lcm}(M,A_1,\ldots,A_t)\mathbb Z.
\]

**Proof.** A coordinate difference \(v\) is invisible exactly when every \(A_i\mid Mv\), equivalently \(L\mid Mv\), equivalently \(R\mid v\). ∎

This law holds for coupled and non-coprime anchors. A product of anchors is justified only under the appropriate coprimality assumptions.

### 3.3 Arbitrary modulus queries directly

For a desired positive target modulus \(b\),

\[
\boxed{x\bmod b=(r\bmod b)+(M\bmod b)(k\bmod b)\pmod b.}
\]

No condition \(\gcd(M,b)=1\) is needed. An exact on-demand coordinate suffices, but may be more information than the query needs.

If observations determine \(k\) only modulo \(R\), the target query is nevertheless determined for every \(k\in\mathbb Z\) exactly when

\[
\boxed{b\mid MR.}
\]

**Proof.** Invisible coordinate changes are \(Rv\). Their target changes are \(MRv\bmod b\), all zero exactly when \(b\mid MR\). This is Theorem A's kernel inclusion. ∎

Under a valid bounded-window selector, exact \(k\) permits **any** target modulus \(b\). Outside such a window, observations at a fixed finite set of moduli cannot answer every possible modulus query. For example \(M=6,A=10\) cannot distinguish \(x=1\) and \(x=31\); their residues modulo \(7\) differ. This collision marks the exact hypothesis required, without saying that the valid-window algorithm needs reconstruction.

For general commutative-ring target \(R/I\), direct source reduction from the observed correction is possible on all coordinates exactly when

\[
(J:m)\subseteq(I:m).
\]

This ideal-quotient inclusion is the general annihilator criterion for arbitrary target quotient queries.

### 3.4 Division of polynomials

Let \(F\) be a field, \(M,A\in F[z]\) nonzero coprime polynomials, and

\[
X=MQ+r,\qquad \deg r<\deg M.
\]

From \(s=X\bmod A\),

\[
\boxed{Q\bmod A=(s-r)M^{-1}\bmod A.}
\]

If \(\deg Q<\deg A\), this determines the exact polynomial quotient. A sufficient source bound is \(\deg X<\deg M+\deg A\), with the zero polynomial handled separately. The proof is identical to the unit-anchor proof, with degree replacing an integer interval as the injective representative condition. Non-coprime polynomials have ambiguity modulo \(A/\gcd(M,A)\) after consistency reduction.

This is a real extension of the same constructor to a different Euclidean domain. Its two ring operations are polynomial operations; they are not a constant number of field operations as degrees increase.

## 4. Matrix and lattice constructors

For vector spaces over a field, let the observed displacement matrix be \(B\) and the target displacement matrix be \(C\). Then

\[
\ker B\subseteq\ker C
\quad\Longleftrightarrow\quad
\operatorname{rowspace}(C)\subseteq\operatorname{rowspace}(B).
\]

A matrix \(D\) satisfying \(DB=C\) can be computed by linear algebra and provisioned with the frame. Query recovery is then

\[
p(x)=p(r)+D\delta.
\]

If \(B\) has full column rank, choose a left inverse and recover the whole displacement. Otherwise a target can remain recoverable even though the displacement is not. Over a field, linear maps from an image subspace can be extended to the ambient observation space by extending a basis. This ambient extension is not automatic over general rings or integer modules.

For integer lattice observations, let

\[
B:\mathbb Z^d\to\mathbb Z^m/\Lambda,
\qquad B(k)=Ak\bmod\Lambda,
\]

where \(\Lambda\) is an explicitly given sublattice. The exact unresolved lattice is

\[
N=\{v\in\mathbb Z^d:Av\in\Lambda\}.
\]

An observation determines a coset \(k+N\). If \(\Lambda\) has basis matrix \(L\), an explicit integer solve of

\[
Ak-Lz=\delta
\]

using Smith or Hermite normal form supplies a particular solution and the homogeneous kernel. An admissible set \(S\) determines a unique displacement exactly when \((S-S)\cap N=\{0\}\). For full-rank \(N\), a fundamental representative set has \([\mathbb Z^d:N]\) elements. If the requested target is \(Ck\bmod\Gamma\), exact direct-query sufficiency is

\[
CN\subseteq\Gamma.
\]

Choosing a representative in an arbitrary promised region can be computationally hard; uniqueness alone is not an efficient selection algorithm. Coordinatewise intervals and prescribed normal-form representative domains give more concrete algorithms than an unrestricted region.

## 5. Noncommutative and action formulations

The observed-defect theorem extends beyond additive commutative arithmetic.

Let \(K,G,H,T\) be groups, with homomorphisms \(\iota:K\to G\), \(h:G\to H\), \(p:G\to T\), and a right-coordinate convention

\[
x=r\iota(k).
\]

Then

\[
\delta=h(r)^{-1}h(x)=(h\circ\iota)(k).
\]

Set \(B=h\circ\iota\), \(C=p\circ\iota\). Exactly as before,

\[
\ker B\subseteq\ker C
\]

is equivalent to a unique group homomorphism \(D:\operatorname{im}B\to T\) with \(DB=C\), and

\[
\boxed{p(x)=p(r)D\bigl(h(r)^{-1}h(x)\bigr).}
\]

**Proof.** Equal observations imply \(k_1^{-1}k_2\in\ker B\subseteq\ker C\), so \(C(k_1)=C(k_2)\). Define the image factor using this equality. The displayed transport identity follows from the homomorphism laws. ∎

For the convention \(x=\iota(k)r\), use \(\delta=h(x)h(r)^{-1}\) and reverse the placement of the transported correction. The order is essential. An integer commutative proof cannot silently justify both conventions in a noncommutative setting.

### General actions and stabilizers

Let \(K\) act on the right on a source set \(X\), observation set \(Y\), and target set \(Z\). Let \(o:X\to Y\) and \(q:X\to Z\) be equivariant. Fix a source reference \(r\). Define

\[
H_o=\operatorname{Stab}_K(o(r)),\qquad
H_q=\operatorname{Stab}_K(q(r)).
\]

There is a well-defined equivariant transport from the observation orbit \(o(r)K\) to the target orbit \(q(r)K\), sending \(o(r)k\) to \(q(r)k\), exactly when

\[
\boxed{H_o\subseteq H_q.}
\]

**Proof.** If an element fixes \(o(r)\), a well-defined transport must send its action to one fixing \(q(r)\), proving necessity. Conversely, if \(o(r)k_1=o(r)k_2\), then \(k_2k_1^{-1}\in H_o\subseteq H_q\). Therefore \(q(r)k_2=q(r)(k_2k_1^{-1})k_1=q(r)k_1\). ∎

For a free observer torsor, its displacement can be recovered uniquely from a pair of observations. If the observer action is not free, the unresolved information is a stabilizer coset rather than a unique group element. A constructive implementation still needs a specified displacement or orbit-solve algorithm. The group theorem is the special case where observer and target actions are induced by homomorphisms and the relevant stabilizers are their kernels.

This supplies a precise route to deck transformations and local sheets of covering spaces. A valid application must state the actual acting group, orbit, reference section, observer, and stabilizer. A general covering need not have a deck group acting transitively on each fiber. Global continuous sections and globally unique sheet coordinates are not automatic.

## 6. Composition, changing references, and transduction

### Changing the reference

If \(r'=r+\iota(a)\), the same source has coordinate \(k'=k-a\). Observed defects change by \(-B(a)\), and the transported target-reference changes by \(+C(a)\). Thus

\[
p(r')+D(B(k'))=p(r)+C(a)+C(k-a)=p(x).
\]

This is a reference-invariance law. It allows a convenient lift, including an unnormalized CRT lift, whenever the required observations of that lift and an admissible coordinate window are available.

### Extensions and arithmetic

An additive extension \(0\to K\xrightarrow\iota V\to Q\to0\) with a chosen set-theoretic section \(\sigma:Q\to V\) supplies references \(r=\sigma(q)\). The section need not be additive. When \(\iota\) is injective, the addition correction is the uniquely defined element \(c(q_1,q_2)\in K\) satisfying

\[
\iota(c(q_1,q_2))=
\sigma(q_1)+\sigma(q_2)-\sigma(q_1+q_2).
\]

Thus the coordinate of a sum is \(k_1+k_2+c(q_1,q_2)\). This is a semantic identity for the extension. It does not require a persistent scalar register holding that coordinate. An implementation may update the authentic observed views and recover only a requested correction later.

Multiplication is not an additive homomorphism in both inputs jointly, so Theorem A alone does not prove a multiplication algorithm. A ring/module implementation proves the appropriate operation refinement, including any cross terms, or keeps multiplicative observer channels updated and uses Theorem A on the resulting source state. The finite-program proof then composes those individual refinements.

### Transduction and round trips

Suppose two frames encode a common admissible semantic domain \(S\), and each frame can compute every target coordinate required by the other. Apply direct query transport to each destination observation, while proving the destination admissibility invariant. This constructs a base change without assembling a scalar source.

If both representations are faithful on \(S\), the forward and backward value transductions compose to identity. If they preserve only selected queries, their round trip preserves those queries; equality of every representation component needs an additional faithfulness or canonicality theorem.

This gives a groupoid of faithful representations of the same semantic domain when the transductions are actual mutually inverse encodings. It does not automatically transport arbitrary history, schema, topology, or policy metadata. Those fields need explicit maps and separate round-trip laws. Append-only history cannot be erased by a value inverse.

### Division and GCD

Magnitude comparison can use exact on-demand \((k,r)\) coordinates lexicographically, with \(0\le r<M\). It need not construct \(x=r+Mk\). Signed interpretation uses the chosen source interval and its actual midpoint; a bare comparison of \(k\) with \(A/2\) is not a universally valid sign theorem.

Integer division and GCD can then be built from certified residue-space operations, for example by a Euclidean sequence of exact `divmod` steps. Their correctness is a finite-composition consequence once each primitive and range invariant is proved. Their time is the cost of the selected division and Euclidean algorithms. The two-operation unit readout is a reusable primitive inside that computation, not a proof that general GCD is one subtraction and multiplication.

The important universal consequence is closure of the admitted semantic computation under proved primitives, with observations remaining authentic and sufficient at each stage. A fixed finite representation requires bounds; adaptive enlargement requires obtaining authentic additional observations before information is lost. Relabeling an already-collapsed state cannot restore a previously discarded distinction.

## 7. Tropical and continuum applications: exact scope

Tropical min/max addition is not cancellative, so the additive-group defect proof does not apply to the tropical semiring operation itself. It can apply to the **underlying translation or sheet action** that a tropical construction retains.

For the scalar tropical theta form recorded in the supplied analysis,

\[
T_Q(z)=\min_{n\in\mathbb Z}(Qn^2+2nz),\qquad Q>0,
\]

write \(z=g+QK\) with \(|g|<Q/2\). Substitute \(n=j-K\):

\[
Qn^2+2nz=Qj^2+2jg-QK^2-2Kg.
\]

For every nonzero integer \(j\),

\[
Qj^2+2jg\ge |j|(Q|j|-2|g|)>0.
\]

Thus the unique minimizer is \(n=-K\), and

\[
T_Q(z)=-QK^2-2Kg.
\]

This is a direct branch-selection consequence of an exact sheet coordinate. Boundary values \(|g|=Q/2\) require a tie convention. The quadratic target is not an additive homomorphism; it is evaluated after the sheet coordinate is obtained. The construction is not evidence that every tropicalized map has a unique inverse.

For a box-ball transition, an exact continuous interpolation of its discrete height and carrier data is a well-defined embedding when those data are specified. A theorem that interpolated dynamics converge to a continuum PDE, or that ultradiscretization can be inverted, requires additional hypotheses and proofs. In particular, a lossy tropicalization may forget coefficients or amplitudes unrelated to an integer sheet index. The relevant test is always whether the proposed retained observations distinguish the requested continuum object.

Consequently, the universal theorem can organize and prove a given sheet/branch lift. It should not contain “all continuum models” as an unconditional corollary.

## 8. Precise application table

| Application | Displacement and observation | Exact sufficiency / admissibility | Explicit constructor | What is proved; cost scope |
|---|---|---|---|---|
| Integer magnitude on demand | \(x=r+Mk\), \(B(k)=Mk\bmod A\) | Unit anchor plus an admitted K-window injective modulo A | \((s-r)M^{-1}\bmod A\), then window selection if needed | Exact K in the window; one modular subtraction and multiplication for the core readout |
| Non-coprime anchors | Same, several possibly overlapping moduli | Consistency and K-window injective modulo \(R=L/\gcd(M,L)\) | Reduced congruence solves and certified fusion | Exact ambiguity and sufficient range; fusion cost is additional |
| Arbitrary target modulus | Target correction \(Mk\bmod b\) | Exact K in a promised window, or globally \(b\mid MR\) | Target reduction of reference plus transported correction | No target coprimality requirement; no full scalar assembly |
| Polynomial quotient | \(X=r+MQ\), observation modulo polynomial A | \(\gcd(M,A)=1\), \(\deg Q<\deg A\) for exact Q | One quotient-ring subtraction and multiply | Exact polynomial quotient; ring-operation count does not erase degree cost |
| Field vectors | \(x=r+\iota(k)\), observed matrix B | \(\ker B\subseteq\ker C\); full K requires full column rank | Precompute D with \(DB=C\) | Direct target linear query; matrix-vector cost |
| Integer lattices | \(Ak\bmod\Lambda\) | Target kills \(N=\{v:Av\in\Lambda\}\); exact K needs an injective representative region | Smith/Hermite normal form and representative selection | Coset resolution and target queries; region selection may be expensive |
| Noncommutative groups | \(x=r\iota(k)\), defect \(h(r)^{-1}h(x)\) | \(\ker B\subseteq\ker C\) | Explicit image-factor algorithm, if supplied | Ordered group transport; not commutative subtraction |
| Covers / torsors | Sheet group action | Observer stabilizer contained in target stabilizer; reference chart specified | Displacement or orbit solve in that chart | Exact sheet-dependent query; no automatic global continuous section |
| Tropical theta branch | \(z=g+QK\) | Exact K and \(|g|<Q/2\) | K readout followed by proved quadratic expression | Unique branch and exact value in the chart; tie walls handled separately |
| Continuum interpolation | Given discrete height/carrier state and interpolation rule | Retained state determines requested interpolation | Specified interpolation map | Exact embedding of supplied data; PDE convergence is a separate theorem |
| Division and GCD | Valid states and exact `divmod` primitives | Every step preserves observations and range | Verified algorithm composed from primitives | Exact residue-space computation; algorithmic iteration cost remains |
| Frame transduction | Destination coordinates as source queries | Each destination query kills source ambiguity; valid destination frame | Apply transport to destination observations | Value transport; inverse requires faithfulness on a common domain |
| Metadata transduction | Explicit schema/history/policy state | Individual inverse/composition laws | Specified metadata maps | No inverse follows just from value preservation |

## 9. Cost theorem and input contract

The defensible strong claim is:

> For a fixed unit-anchor frame with authentic source/reference readings and a provisioned inverse, K-Elimination computes the coordinate class using exactly one modular subtraction and one modular multiplication. In an admissible canonical window that class is the exact coordinate. The coordinate can be consumed on demand without full scalar reconstruction or persistent scalar-K state.

This statement is precise and useful. Its input contract should be part of the theorem, not hidden in an implementation note:

1. The source reading and reference reading are authentic and refer to the same source/frame.
2. The inverse is valid for the current frame.
3. Any exact-coordinate conclusion includes the proved admissible window.
4. Any destination query includes its reference view or a specified way to obtain it.

If a source is provided only as many small residue lanes and the required reference view is not already resident, deriving that view is a separate algorithm. A relative CRT lift can obtain views by modular accumulation without assembling the large scalar, but its lane work is still counted. This does not invalidate the constant-operation kernel; it identifies the exact reusable boundary of that kernel.

For variable-width arithmetic, a modular multiplication has a bit cost. For homomorphic evaluation, a modular operation has an encrypted circuit cost and may require representation-specific comparison, reduction, or selection. Polynomial and matrix variants likewise have internal dimension costs. None of these changes the algebraic two-operation identity, and none should be silently declared zero by a universal theorem.

## 10. Recommended proof organization

The new layer should make the arithmetic constructors central, while keeping abstract existence and implementation cost distinct:

1. **Observed affine identity:** \(h(x)-h(r)=(h\circ\iota)(k)\).
2. **Constructive direct query transport:** from an explicit linear factor and its operator identity.
3. **Exact kernel criterion:** existence and uniqueness of the factor on the image.
4. **Restricted-domain injectivity:** exact coordinate recovery from an admitted window or degree bound.
5. **Unit constructor:** one subtraction and one multiplication, with inverse and authenticity inputs.
6. **Nonunit constructor:** ideal-quotient / annihilator ambiguity and consistency.
7. **Integer fusion and target queries:** \(R=L/\gcd(M,L)\), source period \(MR\), target criterion \(b\mid MR\).
8. **Reference invariance and transduction:** change-of-reference law and faithful round trips.
9. **Primitive and finite-program refinement:** each concrete operation preserves the contract.
10. **Domain-specific applications:** polynomial, lattice, tropical branch, continuum interpolation, and NINE65 circuits with their own explicit premises.

A formally checked set-level theorem alone cannot replace items 2 and 5–7: it establishes the shape of exact recovery, while those items exhibit what makes K-Elimination executable. Conversely, a checked integer inverse identity alone cannot establish all applications or their complexity.

The proposed universal statement therefore has a meaningful boundary: **observed extensions admit exact on-demand transport of precisely those queries that are invariant under the observation kernel; explicit inverse or solve operators make that transport constructive.** K-Elimination supplies the unit-anchor constructor and an architectural discipline for composing such transports without materializing the full scalar. Further generalized constructors can be added with separate correctness and cost theorems.

No new empirical tests were run for this review. The claims above have algebraic proofs; the nonextension and finite-observation examples are exact symbolic counterexamples. The fresh Lean build checks the core statements inventoried in Section 11. Earlier corpus experiments remain separate finite evidence for their recorded domains.

## 11. Review of the concurrent Lean implementation

Reviewed source: `UniversalLift.lean`, `RingReadout.lean`, `IntegerSpecialization.lean`, and `CostedReadout.lean` in this directory, together with their build/axiom logs and the initial verification manifest (preserved in the research history). The initial core package passed a fresh temporary build using pinned Lean 4.27.0-rc1 and bundled Std, without reusing project `.olean` files or depending on Mathlib. It contains 75 theorem declarations: 9 reused observation theorems and 66 new declarations. This review did not need to repeat that compilation.

The central `UniversalLift.phase_difference` proves the affine elimination identity from additive-map laws. `candidate_iff_kernel` identifies the entire compatible fiber. `separation_iff` states the exact admitted-domain injectivity condition. These are the correct foundations; none assumes an inverse exists in every domain.

`lift_query_exists_iff` is an exact necessary-and-sufficient existence statement for an arbitrary consumer on the admitted set. Its existential construction uses `Classical.choice` through the set-level theorem. It is explicitly documented as a mathematical existence result, not an effective decoder. This distinction is correct.

`target_factor_exists_iff` specializes the criterion to an additive consumer on the entire displacement group and proves precisely \(\ker B\subseteq\ker C\). `target_factor_unique` supplies uniqueness on the observed image. The existential result is typed as a function on the image; the checked `target_factor_additive` additionally proves

```text
answer(reading(linear, a + b))
  = answer(reading(linear, a)) + answer(reading(linear, b))
```

from the factor equation and `consumer.map_add`. These three results establish the unique additive factor on the image. They correctly make no claim that it extends additively to all observations.

`constructive_query_correct` and `direct_target_query` are valid refinement interfaces, but their `hread` argument is the algorithm-specific proof obligation. Taken alone, they do not exhibit an algorithm. This is not circular when the obligation is discharged independently, as it is in the concrete modules:

- `RingReadout.unit_readout` derives the runtime output from ring laws and an explicit sided inverse certificate. Its source and coordinate occur only in the specification; the runtime program accepts observations and a constant.
- `RingReadout.solution_fiber` and the closure lemmas support the annihilator/right-ideal ambiguity claim even in noncommutative rings, with the multiplication side correctly specified.
- `IntegerSpecialization.query_of_decomposition` proves the actual modular readout. The exact, signed-window, adjacent-anchor, and target-transport theorems strengthen its conclusion under explicit hypotheses.
- `IntegerSpecialization.query_chart_of_decomposition` and `chart_query_target_lane_transport` make the no-wide-reference interface concrete: runtime inputs may be only the required modular views.
- `IntegerSpecialization.nonunit_chart_query` proves an actual reduced-modulus program: remove a certified common factor \(d\) from the observed difference and multiply by a provisioned inverse modulo \(A/d\). The required exact divisibility follows from authenticity; correctness is not postulated. `nonunit_chart_query_signed_window` upgrades to exact K in a window. `nonunit_chart_target_lane_transport` transports directly to a target annihilating \(M(A/d)\), without exact K recovery. The nonunit program explicitly includes the exact division by \(d\); the unit program's two-operation count is not assigned to it.
- `CostedReadout.ring_is_universal_instance` explicitly discharges the generic `hread` obligation using the inverse certificate. This is the important bridge preventing the universal layer from being merely an assumed decoder contract.
- `CostedReadout.program_counts` counts one subtraction and one multiplication in an explicit expression syntax. The evaluator is related to both the ring and normalized modular programs. The adjacent expression has one subtraction and no multiplication.

The reviewed source therefore supports the constructive additive/ring/integer instances, the nonunit reduced solve, direct queries without full K, and the exact substrate-operation count for the unit constructor. Explicit gcd/LCM identification and multi-anchor minimal resolution, necessity of the arbitrary-target divisibility criterion, matrix/lattice algorithms, general group actions, polynomial degree specialization, and tropical/continuum applications in this review still require their own formal instances if they are to be included in the repository's machine-checked claims.

The initial core manifest reported only ordinary Lean logical foundations where needed (`propext`, `Quot.sound`, and `Classical.choice`), with 29 declarations depending on no axioms. In particular, the principal ring readout, affine identity, constructive refinement, direct-target query, image-factor additivity, and ring-instance bridge have no axiom dependencies. Some concrete integer proofs inherit ordinary logical axioms through library lemmas or tactics; their defined runtime arithmetic remains executable. This is a statement about the reviewed files and build, not a blanket certification of the production NINE65 implementation.
