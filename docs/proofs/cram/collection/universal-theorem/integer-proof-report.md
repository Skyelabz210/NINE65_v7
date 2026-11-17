# Integer specialization: verified paired-view readout

`IntegerSpecialization.lean` contains 28 theorem declarations, checked using
Lean `leanprover/lean4:v4.27.0-rc1` with `import Std` only. The exact build log is
`integer-build.log`; the parsed per-theorem axiom inventory is
`integer-axiom-audit.json`.

The implementation is

\[
\operatorname{query}(r,s,A,u)=(((s-r)\bmod A)u)\bmod A.
\]

Its inputs are the supplied paired readings and public constants. Neither the
source integer `X` nor its quotient `K` is a runtime input. Theorem hypotheses
establish authenticity of the readings; the query itself does not verify their
provenance. The stronger chart-reading theorem consumes only
`chart = r % A` and `s = X % A`: the potentially wide affine base point `r`
also becomes a ghost value, used only in the proof.

The core proof derives, rather than assumes,

\[
X=r+MK,\quad s=X\bmod A,\quad uM\equiv1\pmod A
\quad\Longrightarrow\quad
\operatorname{query}(r,s,A,u)=K\bmod A.
\]

Taking `r = X % M` proves this for the actual Euclidean quotient `X / M`, with
arbitrary signed `X`. Exact integer recovery follows either from
`0 ≤ X / M < A`, or from `M > 0` and `0 ≤ X < M*A`. An arbitrary public signed
window `[lo, lo+A)` is handled by the executable decoder

\[
\operatorname{windowDecode}(q,A,lo)=lo+((q-lo)\bmod A).
\]

The star-anchor certificate `A = c*M+1`, `u=-c` is proved algebraically. The
adjacent case `A=M+1` reduces the actual query to `(r-s) % (M+1)`, and its exact
quotient theorem includes the source-window assumption.

The target projection computes

\[
((r\bmod B)+(M\bmod B)(K\bmod B))\bmod B.
\]

It emits the correct residue for every integer target `B`, given exact readout
or signed-window decoding. There is also a stronger direct-transport result:
**if `B` divides `M*A`, no exact quotient lift or range assumption is needed**.
The output is insensitive to the unresolved multiples of `A` in the quotient.
The runtime expression never forms the scalar `r+M*K`; that expression is used
only in the correctness proof. In practical RNS interpretation the target
modulus is positive; the integer identity also covers Lean's totalized
modulo-zero convention.

The theorem `chart_query_target_lane_transport` makes the lane interface
explicit. Runtime inputs are `chart=r%A`, `s=X%A`, the target reading `t=r%B`,
and the public reduced multiplier `mB=M%B`. It proves

\[
\bigl(t+m_B(\operatorname{query}(\mathit{chart},s,A,u)\bmod B)\bigr)\bmod B
 = X\bmod B
\]

from `X=r+M*K`, the authentic-reading certificates, the inverse certificate,
and `B | M*A`. The wide `r`, `X`, and `K` are all ghost values. Thus this is a
concrete instance of transporting an observable without identifying the full
source or the full quotient.

## Certified nonunit reduction

The module also proves a generalized formula for a supplied common factor
`d ≠ 0` with `d | M` and `d | A`. Write `m=M/d`, `a=A/d`. If a precomputed
constant satisfies `u*m ≡ 1 (mod a)`, then

\[
q=\left(\frac{s-\mathit{chart}}d\,u\right)\bmod a=K\bmod a.
\]

The exact divisibility `d | (s-chart)` is **proved** from authentic observations
of `X=r+M*K`; it is not silently assumed or obtained by truncating a division.
An intermediate theorem derives exact defect reduction from
`defect=M*K+A*z`. The direct source and chart-reading theorems derive that
consistency equation from the source relation and residue identities.

The same signed-window decoder recovers `K` when it lies in a public interval
of width `a`. Without such a window, `nonunit_chart_target_lane_transport`
still emits `X%B` exactly whenever `B | M*(A/d)`. For positive `M,A` and
`d=gcd(M,A)`, this period is `lcm(M,A)`. The Lean theorem uses the explicit
divisibility/inverse certificates; this file does not separately prove a
GCD routine or generate the inverse.

Two final theorems state the precise identifiability boundary. A common valid
quotient window makes two authentic paired readings uniquely identify the
source. Without a window or further observations, the views repeat after
`M*A`; no function of a fixed pair of nonzero-modulus views can return every
unbounded integer quotient.

## Cost interpretation

For supplied readings and a precomputed inverse, the expression has one modular
subtraction and one modular multiplication. In the adjacent case it has one
modular subtraction. This is a constant arithmetic-gate count. The file does
not claim constant bit complexity, prove a machine timing bound, amortize
inverse computation, generate paired readings, or establish the cost of
reducing an arbitrarily wide reading into a lane. The chart interface removes
the need to supply that wide reading when its anchor-lane observation is
already available. Signed-window decoding and target projection have their
own explicit arithmetic operations. The generalized `nonunitQuery` explicitly
performs exact division of the defect by `d` before its modular multiplication;
the unit-case gate count must not be attributed to that extra operation.

## Scope of assurance

The source contains no admitted proofs or custom axioms. The printed transitive
dependencies are subsets of `propext`, `Classical.choice`, and `Quot.sound`;
these are standard Lean logical axioms. The theorem statements never take query
correctness as a premise. Affine decomposition is an authenticity condition;
the Euclidean-quotient theorem derives it from the supplied low reading.

This file proves the integer instance and certified common-factor reduction.
It does not prove a complete arbitrary-divisor integer-division engine, GCD or
inverse generation, tropical inversion, FHE security, or implementation-level
correspondence to an uninspected producer. Those remain separate obligations.

Reproduce from this directory:

```sh
ELAN_HOME=/workspace/k-elimination-audit/proof-check/elan \
  /workspace/k-elimination-audit/proof-check/elan/bin/lean \
  +leanprover/lean4:v4.27.0-rc1 \
  -o IntegerSpecialization.olean IntegerSpecialization.lean
```
