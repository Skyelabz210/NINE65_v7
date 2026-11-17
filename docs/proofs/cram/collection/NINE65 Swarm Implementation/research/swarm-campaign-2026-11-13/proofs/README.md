# Campaign formal results

The standard-library packet checks **180 unique declarations: 144 preserved
unchanged and 36 new**. It uses pinned Lean `v4.27.0-rc1`, rebuilds all project
imports in a fresh temporary directory, and audits each declaration's axioms.
There are no admitted proofs or custom project axioms. Fifteen new declarations
are axiom-free. Foundational `propext`, `Quot.sound` and `Classical.choice` are
reported individually in [verification.json](verification.json).

## New mathematical content

### Future-query quotient — 23 declarations

[FutureQuotient.lean](FutureQuotient.lean) defines equality of every requested
output after every finite operation word. It proves this is an equivalence
relation, is preserved by each declared operation, determines current outputs,
and is coarser than every other relation with those two properties. Actual
`Quotient` constructors implement the mathematical output and transition maps;
their defining equations and exact quotient-equality criterion are checked.

The module formalizes the refinement recurrence underlying the finite-model
compiler. Its n-th relation agrees exactly with observations along words of
length at most n. If a refinement round is a fixed point, it equals the full
future-query relation. This proves the semantic fixed-point criterion; it does
not by itself prove the Python implementation's class numbering, cardinality
termination bound, or code extraction.

For additive transitions and queries, the invisible set is the intersection of
the kernels of all future query composites. The module proves zero/addition/
subtraction closure, transition invariance, maximality among query-invisible
invariant sets, and equivalence between future equality and invisible
differences. The source may be an admitted subtype, but every declared
transition must be total on it. No finite-capacity claim follows merely from
the existence of this abstract quotient.

### Anchor exponent saturation — 11 declarations

[AnchorValuations.lean](AnchorValuations.lean) proves the exact prime-exponent
rule: a demand exponent d already covered by p requires zero extra exponent;
otherwise it requires the full d. This vector is feasible and least under
pointwise order. Starting from d-p and iterating `a -> min(d,2*a)` reaches the
required exponent with a conservative finite bound, and its only bounded fixed
points are zero and d.

The standard-library module deliberately states the exponent recurrence. The
Nat.gcd/Nat.lcm/prime-factorization bridge is maintained separately in the
original Lean repository's `KElimination/AnchorSaturation.lean`; its build and
axiom audit also passed. Its **13 additional new declarations** prove that the
actual integer recurrence `a₀ = D/gcd(P,D)`, `aₙ₊₁ = gcd(D,aₙ²)` yields the
divisibility-least anchor satisfying `D | lcm(P,a)` for positive P,D. Conservative
fuel D guarantees a fixed point; stopping at any earlier fixed point is also
correct. The algorithm uses division and gcd of public parameters; factorization
is proof machinery only. The checked source is mirrored in
[mathlib/AnchorSaturation.lean](mathlib/AnchorSaturation.lean), to be compiled in
the original Mathlib project. No proof here claims source-level refinement of
the Python implementation.

### Reflection identities — 2 declarations

[ReflectionInvariant.lean](ReflectionInvariant.lean) proves that replacing a
coordinate a by `2*(b+c+d)-a` is an involution and preserves the Descartes form
`2*(a²+b²+c²+d²)-(a+b+c+d)²`. These are polynomial identities over **every
commutative ring**, including characteristic two and composite residue rings.
No inverse, odd characteristic or prime modulus is required. This strengthens
the algebraic domain available to MAA/AHOP adapters; implementation word-size
bounds, source binding and particular geometric interpretations remain separate.

## Reproduce

```sh
ELAN_HOME=/path/to/elan python3 check_proofs.py --lean /path/to/lean
ELAN_HOME=/path/to/elan python3 check_negative_controls.py --lean /path/to/lean
```

`dependency-provenance.json` checks all 13 copied foundation modules against
the previous 144-declaration package. `verification.log` is the raw fresh-build
and axiom output. `negative-controls.json` records the checker refusing an
admission, a custom axiom, a false halving-closure claim and a missing audit
query. These are proof-checker tests, not encrypted execution or performance
evidence.

## Original repository integration

An isolated `campaign/universal-proof` worktree at
`/workspace/k-elimination-swarm-proof` preserves the original input revision
`0400092096962e3da45a8e5cbb82185a3c2c38fe`. It repairs the opening-comment parser
issue and the Basic div/mod proofs, narrows the aggregate tactic import, and
integrates the universal modules under `KElimination/UniversalResearch`.

The official Mathlib cache request was rejected by the configured proxy with
HTTP CONNECT 403. The pinned dependencies were instead built from source;
[cache-attempt.json](cache-attempt.json) records the observed failure and
[original-source-build.log](original-source-build.log) preserves the source
build. The final integrated build passed (1,185 jobs). The full project audit
passed **223 declarations**: 27 legacy root, three Basic, 144 preserved universal
foundation, 36 new standard-library and 13 new Nat theorems. That is **49 new
declarations in total**, not 223 new results. See
[original-repository/verification.json](original-repository/verification.json)
for every source hash and axiom dependency, and
[original-repo-verification.json](original-repo-verification.json) for revision,
patch and scope metadata. No project custom axiom or admission was used; 58 of
the 223 declarations are axiom-free. The initial integration attempt exposed an
unsolved draft induction step; the corrected final build and axiom audit pass.

No GitHub push, Coq revalidation, Rust implementation refinement, global
constant-cost claim or cryptographic admission is implied by these results.
