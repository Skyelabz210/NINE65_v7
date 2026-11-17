# From universal transport to StarLift, combined anchors, division and GCD

12 November 2026. This continuation adds **55 checked theorem declarations** to the preceding 75-declaration package, for **130 total**. Both a fresh isolated Lean build and the normal Lake build passed. All theorem dependencies were audited; no admitted proof or project axiom is present. The [manifest](universal-theorem/verification.json) records source hashes and exact dependencies.

## StarLift is now an explicit corollary

For M>0, A=M+1 and any signed integer X, set v_M=X mod M, v_A=X mod A and K=X/M using Euclidean division. The two computed readouts satisfy

\[
\boxed{(v_M-v_A)\bmod A=K\bmod A,\qquad
       (v_A-v_M)\bmod A=(-K)\bmod A.}
\]

These congruences require no magnitude bound. Exact integer K follows from an admitted half-open window; a negative winding residue is first negated modulo A and then decoded in that window. [StarLift.lean](universal-theorem/StarLift.lean) checks both orientations, the general inverse formula, unit-kernel equality and the reduced nonunit negative query.

The user's interpretation is captured by a direct lift consumer C(k)=k mod A or C₋(k)=−k mod A. In the source-map notation, p(z)=z mod A composes with iota(k)=Mk to give Mk mod A; choosing p(z)=uz mod A with uM=1 mod A gives the desired C. For the raw defect δ=v_A−v_M, the adjacent positive decoder is −δ and the negative decoder is δ. Operand reversal relates the two oriented outputs. These typing and sign conventions are made explicit in [STARLIFT.md](universal-theorem/STARLIFT.md).

“Additive inverse of infinity” can name the finite query of an unbounded integer coordinate in the author's terminology. The proved arithmetic is the exact residue (−K) mod A; mathematical infinity is not an operand in the implementation or theorem.

## Exact combined-anchor capacity

For an arbitrary finite list of positive anchors A_i, including repeated and overlapping moduli, define

\[
L=\operatorname{lcm}_i A_i,\qquad
R=\frac{L}{\gcd(M,L)}.
\]

[CoupledAnchors.lean](universal-theorem/CoupledAnchors.lean) now proves, using the actual standard-library GCD and LCM,

\[
\begin{aligned}
\forall i,\ A_i\mid M\Delta &\iff R\mid\Delta,\\
R&=\operatorname{lcm}_i\frac{A_i}{\gcd(M,A_i)},\\
MR&=\operatorname{lcm}(M,A_1,\ldots,A_n).
\end{aligned}
\]

The result covers signed coordinate differences, proves R is the least positive invisible coordinate shift, and proves uniqueness in any common half-open coordinate window of width R. It also identifies equality of the actual main/anchor source readings with divisibility of X−Y by MR. An additional anchor dividing the existing L adds no resolution.

The target criterion is checked in both directions: for fixed reference r and all compatible coordinates, X mod b is determined exactly when b divides MR. This supplies the formal necessity proof as well as sufficiency. These are exact capacity and information theorems. Computing a fused representative from an arbitrary set of supplied congruences is a separate decoder implementation.

## Concrete residue-space divmod and GCD

[ResidueAlgorithms.lean](universal-theorem/ResidueAlgorithms.lean) defines actual total, fuelled programs for repeated-subtraction divmod and Euclidean GCD. Runtime operations contain a public capacity, residue zero, increment, subtraction, comparison and zero detection. The semantic encoding function occurs only in a separate proof proposition.

[ResiduePrimitives.lean](universal-theorem/ResiduePrimitives.lean) supplies the concrete implementation. Its entire number state is

```text
State { main : Int, anchor : Int }
```

A frame supplies public positive M,A and the inverse certificate. For every n,d<MA, d>0, the checked result is

\[
\operatorname{divmod}(E(n),E(d))
 =\operatorname{some}\bigl(E(\lfloor n/d\rfloor),E(n\bmod d)\bigr),
\]

and for all a,b<MA,

\[
\operatorname{gcd}(E(a),E(b))
 =\operatorname{some}\bigl(E(\gcd(a,b))\bigr).
\]

Every generic primitive obligation is discharged from actual modular operations and the checked K query. Comparison is the lexicographic order of the transient quotient and main residue. Subtraction and increment update both lanes. No runtime call reconstructs X or retains scalar K. Divisors may share factors with either observer modulus, and division need not be exact. A represented zero divisor returns `none`; GCD handles zero inputs, including gcd(0,0)=0.

The division invariant q+r<MA keeps each increment and subtraction in range. Every nonterminal subtraction decreases r by at least one, so public capacity provides sufficient fuel. Euclid's second operand decreases to the remainder, preserving the frame bound and providing its own fuel proof. Exhausted fuel returns `none`, while the correctness theorem proves this exhaustion cannot occur on admitted inputs with the provisioned capacity. Encoding injectivity on that domain is also proved, so encoded-result equality is faithful.

This establishes a concrete bounded residue implementation, extending the earlier written invariant proof and Python witness. It uses data-dependent repeated subtraction; it is not a performance replacement for NINE65's existing division paths or an encrypted constant-time circuit. The two-operation K query remains a primitive, and the complete algorithms have iteration costs.

## Changing the affine reference

[ReferenceChange.lean](universal-theorem/ReferenceChange.lean) proves that r'=r+iota(a) changes k to k−a and the observed defect to Bk−Ba. The requested target remains identical when the old and new decoders satisfy their respective admitted-domain laws. The observer and target maps are fixed in this theorem; changing anchor maps or constructing new authentic readings requires an additional transduction contract.

## Verification and execution

| New module | Checked declarations |
|---|---:|
| ReferenceChange | 3 |
| CoupledAnchors | 19 |
| ResidueAlgorithms | 6 |
| ResiduePrimitives | 14 |
| StarLift | 13 |

Counts include supporting lemmas. [CLOSURE_REVIEW.md](universal-theorem/CLOSURE_REVIEW.md) records an independent review of assumptions, loop bounds, concrete primitive discharge and sign conventions.

The compiled Lean programs also passed [1,809 executable comparison/divmod/GCD pairs](universal-theorem/closure-smoke.log): exhaustive inputs for frames 2/3 and 6/7, plus nine boundary/shared-factor cases in 36/37. Four additional controls checked fuel exhaustion, out-of-window aliasing and reversed positive-winding orientation. [ClosureSmoke.lean](universal-theorem/ClosureSmoke.lean) keeps ordinary integer oracles at test ingress and verification only. These executions check wiring; the proofs cover every admitted pair for any positive unit-anchor frame.

Reproduce in `universal-theorem/` with the pinned Lean installed:

```sh
python3 check_proofs.py --lean lean
lake build
lake env lean ClosureSmoke.lean
```

The remaining integration work is concrete multi-anchor fusion, polynomial/degree and lattice instances, the specific geometric dynamics statements, and refinement of NINE65's actual producers and consumers. The standalone proof package and original repository root have separate build status. Neither original production checkout was changed by this continuation.
