# StarLift as a universal coordinate query

The user's adjacent-anchor interpretation is correct with explicit source/coordinate types and subtraction orientation. [StarLift.lean](StarLift.lean) proves 13 declarations under the package's pinned Lean4.27.0-rc1 using the existing constructive integer module. [starlift-build.log](starlift-build.log) records compilation and each theorem's axiom dependencies. There are no admitted proofs or custom axioms.

## Exact formulas

Let M>0, A=M+1, X∈ℤ and

\[
v_M=X\bmod M,\qquad v_A=X\bmod A,\qquad K=X/M
\]

where division is Euclidean. The two oriented queries are

\[
\operatorname{Star}_+(v_M,v_A)=(v_M-v_A)\bmod A=K\bmod A,
\]

\[
\operatorname{Star}_-(v_M,v_A)=(v_A-v_M)\bmod A=(-K)\bmod A.
\]

Both formulas hold for arbitrary signed X, without a magnitude bound. The proofs in `positive_adjacent_congruence` and `negative_adjacent_congruence` use the actual two-reading functions. Neither X nor K is a runtime input. The identities also hold under Lean's totalized arithmetic conventions outside the usual positive-modulus interpretation; practical RNS uses positive M and A.

With the raw observed defect δ=v_A−v_M modulo A, the positive-coordinate decoder is D₊(δ)=−δ and the negative-coordinate decoder is D₋(δ)=δ. Reversing operands exchanges the two oriented queries. The expression D(q)=−q is correct when q already denotes the positive-coordinate result; it is not the negative-coordinate decoder on the original δ. `adjacent_orientations` and `negative_query_adjacent` make this distinction explicit.

For example, M=36, A=37 and X=36 give K=1, v_M=0 and v_A=36. The positive query returns 1; the negative query returns 36, the residue of −1 modulo 37. A bounded positive quotient conclusion belongs to Star₊, or to Star₋ after negation and representative selection.

## Universal theorem: the correctly typed instance

Take coordinate and source groups K=G=ℤ, observation group H=ℤ/Aℤ, and

\[
\iota(k)=Mk,\qquad h(x)=x\bmod A.
\]

Then the observed coordinate map is

\[
B(k)=h(\iota(k))=Mk\bmod A.
\]

The requested coordinate consumers are specified directly:

\[
C_+(k)=k\bmod A,\qquad C_-(k)=-k\bmod A.
\]

Because M≡−1 mod A,

\[
\ker B=\ker C_+=\ker C_-.
\]

The checked `unit_kernel_equal` proves the first equality under a general inverse certificate; `adjacent_kernel_equal` supplies the adjacent instance. Negation does not change a kernel. Thus both queries factor exactly through the observed defect, as required by the universal query theorem.

If one specifically wants a source target map p:G→T with C=p∘ι, use

\[
p_+(x)=ux\bmod A,\qquad p_-(x)=-ux\bmod A,
\quad uM\equiv1\pmod A.
\]

Then C₊(k)=k mod A and C₋(k)=−k mod A. In contrast, choosing p(x)=x mod A gives C(k)=Mk mod A. The distinction is between a map on the source x and the desired query on its coordinate k. The source transport formula is p(X)=p(r)+D(δ); the coordinate query is its correction term D(δ).

Using h=id on ℤ is a valid abstract setup, but supplies the full integer difference. The residue-valued h above models the intended observed-view runtime.

## General and nonunit anchors

For a general anchor and inverse certificate uM≡1 mod A, authentic chart/source readings t=r mod A and s=X mod A with X=r+MK give

\[
C_+(K)=u(s-t)\bmod A,\qquad C_-(K)=-u(s-t)\bmod A.
\]

`negativeQuery` computes the second expression using the negated public inverse; `negative_query_of_decomposition` proves its result. The inverse and readings are supplied inputs, with authenticity and correctness stated as proof hypotheses.

For nonunits, a nonzero common factor d with d|M and d|A, together with an inverse of M/d modulo a=A/d, gives

\[
q=\left(\frac{s-t}{d}u\right)\bmod a=K\bmod a,
\qquad (-q)\bmod a=(-K)\bmod a.
\]

`negative_nonunit_chart_query` proves both required defect divisibility and this negative-coordinate result by using the existing certified nonunit solve. For positive moduli and d=gcd(M,A), a is the available coordinate resolution. The nonunit computation explicitly includes exact common-factor removal; the unit constructor's two-operation count is not a cost statement for that extra work.

## Selecting an exact integer

For a public half-open window K∈[ℓ,ℓ+A), the positive class q determines

\[
K=\ell+((q-\ell)\bmod A).
\]

If the supplied result is the negative class n=(−K) mod A, first form q=(−n) mod A, then select the window. `decodeNegative`, `negative_decode_exact` and `negative_adjacent_exact_window` implement and prove exactly this procedure. The half-open boundary is material: its integer span is strictly less than A.

For 0≤X<M(M+1), Star₊ itself equals the integer quotient. This is proved in `positive_adjacent_exact_source_window`. Star₋ remains its additive inverse modulo A; it is not renamed the positive quotient.

## Meaning of the infinity terminology

An unbounded integer coordinate K can have a finite exactly recoverable query. Here that query is (−K) mod A. This gives a precise mathematical interpretation of the user's phrase “additive inverse of infinity”: negation applies to an integer coordinate whose possible magnitude is unbounded, and the observation returns its residue class. The construction neither introduces an infinity element into ℤ nor defines arithmetic negation of a literal infinite magnitude.

Direct target transport remains governed by the existing kernel criterion. Given a fixed reference and K known modulo R, X mod b is determined on all integer coordinates exactly when b|MR. Knowing the negative class has the same information as knowing the positive class because negation is an involution. Under an admitted exact-coordinate window, arbitrary positive target moduli are available through the already proved target projection.

## Verification scope

These proofs add the named StarLift orientations, their kernel certificate, signed reconstruction from the negative class, and the nonunit negative query. All transitive axiom dependencies are standard Lean `propext`, `Classical.choice`, or `Quot.sound`. Broad finite tests were not repeated because the formulas are proved for their quantified domains. No production NINE65 source was modified by this module.
