# Ring-level observed-lift elimination

`RingReadout.lean` compiles with Lean `4.27.0-rc1` using `import Std`. It contains 16 proved theorems over Lean's bundled `Lean.Grind.Ring` hierarchy, with no Mathlib dependency, admitted proofs, or custom axioms. The ring assumptions are the standard bundled algebra laws; the observation assumptions are explicitly the additive and multiplicative homomorphism laws.

## Main theorem

Let `R` and `H` be rings, not necessarily commutative, and let `h : R → H` preserve addition and multiplication. If

\[
X=r+MK,\qquad u\,h(M)=1,
\]

then

\[
\boxed{u\bigl(h(X)-h(r)\bigr)=h(K).}
\]

The proof first establishes the phase defect `h(X) - h(r) = h(M) h(K)`, then associates the product and cancels with the supplied left inverse. Neither the theorem nor its proof uses commutativity, primality, finiteness, ordered integers, or an integer CRT reconstruction. A matching theorem for `X = r + K M` uses a right inverse on the right.

The observation need not be declared unital: its two displayed homomorphism laws suffice, and the inverse certificate is an equation in the target ring. The computational definition is exactly `inverse * (sourceReading - baseReading)`. The unknown lift `K` is a quantified variable in the correctness theorem; it is not a readout argument or stored register.

## Exact ambiguity and source uniqueness

Define

\[
N_{h,M}=\{\delta\in R:h(M\delta)=0\}.
\]

For any compatible lift `K₀`, the full compatible fiber is precisely

\[
\{K:h(r+MK)=h(r+MK_0)\}=K_0+N_{h,M}.
\]

The compiled statement uses `K - K₀ ∈ N` and proves both implications. The invisible changes contain zero, are closed under addition and negation, and are closed under right multiplication. Thus they form a right ideal in the noncommutative setting. If `R` is commutative, left multiplication closure also follows; this is the ideal quotient `(ker h : M)`.

For an arbitrary admitted set `D`, injectivity of `K ↦ h(r + M K)` on `D` is equivalent to

\[
a,b\in D,\quad a-b\in N_{h,M}\quad\Longrightarrow\quad a=b.
\]

This is proved as an equivalence, without assuming the desired output equality. When `u h(M)=1`, the additional theorem `unit_lift_null_iff` proves

\[
N_{h,M}=\ker h.
\]

Consequently, the multiplier's ambiguity disappears under the unit certificate; any ambiguity remaining in a full source lift is exactly the observer's ambiguity. In the integer residue instance `h(x)=x mod A`, the principal query gives `K mod A`; a certified interval or another separating decoder upgrades this to the particular integer `K`. The separate source-domain theorem is essential to state exactly what is recovered, and is compatible with on-demand magnitude recovery.

## Target projections

For any other homomorphic observation `g : R → T`, including a target where `g(M)` is not invertible,

\[
g(X)=g(r)+g(M)g(K).
\]

`target_projection` formalizes this equation. Its input includes `g(K)`: obtaining it from a different anchor observation `h(K)` requires the admitted-domain decoder or a valid factorization of `g` through `h`. This target theorem does not silently assume that different residue readings can be converted without sufficient information.

## Query cost and scope

The definition of `readout` contains one subtraction and one multiplication in `H`. For a fixed-width modular observation with a precomputed inverse, that is a constant number of modular arithmetic operations. This is a count of the readout expression; it is not a bit-complexity theorem, hardware latency benchmark, FHE circuit-cost theorem, or a claim that obtaining the observations and inverse is free. No binary reconstruction or persistent scalar winding register appears in the query.

This file proves the algebraic specialization of the universal observed-lift framework. It does not establish historical novelty, give a general tropical inverse, or certify an encrypted implementation. Rings may include matrices, polynomial rings, finite rings, and quotient rings when the stated observations and sided inverses exist. Max-plus and min-plus semirings do not themselves satisfy the subtraction assumptions of this specialization; a tropical instance needs an appropriate lifted ring/group model and a demonstrated observation map.

## Verification

Run from this directory:

```sh
ELAN_HOME=/workspace/k-elimination-audit/proof-check/elan \
  /workspace/k-elimination-audit/proof-check/elan/bin/lean \
  +leanprover/lean4:v4.27.0-rc1 -o RingReadout.olean RingReadout.lean
```

`ring-build.log` records the successful compiler run and every theorem's `#print axioms` output. The principal phase-defect, left/right readout, unit-kernel, and target-projection theorems depend on no Lean axioms. Auxiliary proofs use at most the standard Lean foundational axioms `propext` and `Quot.sound`. None uses `Classical.choice`, `sorryAx`, or a custom axiom. `ring-result.json` gives the source hash and per-theorem dependency list for the final compiled source.
