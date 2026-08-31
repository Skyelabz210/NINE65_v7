# CRAM Safe-Basis Repacking, Composite Adjacency, and Lift-Aware Transduction

Status: execution packet / acceptance gate
Date: 2026-08-31

## Purpose

This packet converts the 2026-08-31 CRAM architecture session into executable, exact-integer acceptance gates. It is intentionally narrower than the full CRAM research program: it formalizes the parts that can be tested immediately in `NINE65_v7` without changing FHE semantics or weakening any existing correctness gate.

The central architectural correction is:

> The Safe Basis is an instantiated factor-and-identity substrate. Its prime factors may be regrouped into pairwise-coprime composite carriers without losing product-space identity. Winding/lift is derived on demand from authentic phase-locked residues. Transduction across a source-product boundary must include the derived lift contribution; plain canonical-residue transduction cannot distinguish `X` from `X + M_A`.

All arithmetic in this packet is exact integer arithmetic. No floating point is permitted.

---

## A. Canonical constants

```text
S6 = {2,3,5,7,11,13}
M6 = 30030
S8 = {2,3,5,7,11,13,17,19}
M8 = 9699690

S6 composite repack = {6,35,143}
S8 composite repack = {6,35,143,323}

A6 = M6 + 1 = 30031 = 59 * 509
A8 = M8 + 1 = 9699691 = 347 * 27953
```

The adjacent anchors are deliberately recorded as composite. The adjacency identity depends on `A = M + 1`, not on primality.

---

## B. Theorem gates

### G1 — Safe-basis saturation

For every `x` in `[0,M6)`, the signature

```text
(x mod 2, x mod 3, x mod 5, x mod 7, x mod 11, x mod 13)
```

must be unique.

Acceptance:

```text
unique_signatures == 30030
collisions == 0
```

### G2 — Composite repack isomorphism

Partition S6 and S8 into disjoint prime-factor groups:

```text
S6 -> {2*3, 5*7, 11*13} = {6,35,143}
S8 -> {2*3, 5*7, 11*13, 17*19} = {6,35,143,323}
```

The composite carriers must be pairwise coprime and their product must equal the original Safe-Basis product.

For every `x` in the full S6 product space, the prime signature and composite signature must identify the same state.

This gate establishes the exact distinction:

- disjoint factor grouping -> independent composite basis;
- overlapping grouping -> exact views only, with independent capacity governed by the LCM rather than the raw product.

### G3 — Composite adjacency lift

For every `M >= 2`, set `A=M+1`. Then

```text
M == -1 (mod A)
M^-1 == -1 (mod A)
```

and for every `X` in `[0,M*A)`:

```text
rM = X mod M
rA = X mod A
K  = (rM - rA) mod A
K == floor(X/M)
```

The test suite should include composite `M`, composite `A`, and the canonical values `M=36`, `M=30030`, and `M=9699690` where feasible without exhaustive iteration of the huge product windows.

### G4 — Universal projection from a resolved lift

For exact identity

```text
X = g + K*M
```

and any target modulus `b > 0`, including composite/shared-factor moduli:

```text
X mod b == (g mod b + (K mod b)*(M mod b)) mod b
```

No inverse of `M mod b` is required at the projection stage.

### G5 — Lift-aware transduction regression

Plain source residues cannot distinguish:

```text
X0 = 0
X1 = M6 = 30030
```

because their S6 trays are identical.

However:

```text
30030 mod 17 = 8
30030 mod 19 = 10
```

Therefore a transduction API that accepts only the canonical S6 residue tray must remain explicitly bounded to `[0,M6)`. A lift-aware API must accept enough phase-lock evidence to derive `K mod b_j` and produce:

```text
S6 + derived lift -> S8 extension lanes = (...,8,10)
```

for `X=30030`.

This is the primary regression that prevents accidental range truncation.

### G6 — Heterogeneous product-space reversibility

For pairwise-coprime composite lanes `{6,35,143,323}`, assign an independently invertible affine map to every lane:

```text
f_i(x) = a_i*x + b_i (mod m_i), gcd(a_i,m_i)=1
```

The product map must round-trip every state tested.

This gate distinguishes:

- ordinary integer-line semantics, which may be undefined after heterogeneous operators;
- product/topology-state reversibility, which remains exact when each lane operator is bijective.

### G7 — Uniformity/IID scope

Do not assert blanket IID preservation for basis expansion.

A bijection onto the full target product preserves the uniform distribution. An embedding into a larger target product generally does not.

Regression witness:

```text
X uniform over [0,30030)
target pair = (X mod 17, X mod 19)
```

The 323 target cells do not have identical counts because `323` does not divide `30030`.

Tests must use exact integer counts/cross-products only.

---

## C. Required implementation changes

### C1 — Preserve current `TransductionMap` bounded contract

Do not silently broaden `TransductionMap::apply` beyond its documented `[0,M_A)` domain. Its current canonical-source behavior is useful and should remain explicit.

### C2 — Add a separate lift-aware projection primitive

Add a small exact primitive with semantics equivalent to:

```rust
project_with_lift(g_mod_b, k_mod_b, m_mod_b, b)
    = (g_mod_b + k_mod_b*m_mod_b) mod b
```

The API must not require a stored scalar `K`. It should consume `K mod b` derived from the phase-lock/anchor machinery.

### C3 — Add a lift-aware transduction entry point

The entry point should accept:

- source canonical residue state;
- source product `M_A`;
- target moduli;
- a callback/provider/typed witness capable of supplying `K mod b_j` for each target lane.

It must not materialize the full integer and must not introduce a Garner/mixed-radix cascade into the hot path.

### C4 — Separate state semantics

Add an explicit type-level distinction between:

```text
IntegerNamedState
TopologyProductState
```

or an equivalent enum/certificate.

A heterogeneous schema must not be called arithmetically irreversible merely because no single ordinary integer function names the output. It may still be exactly reversible as a product/topology state.

### C5 — Do not overload Shadow-11 as the full-product lift anchor

When S6/S8 already contains 11, `M^-1 mod 11` does not exist. Shadow-11 remains a disambiguation/integrity lane; the lift anchor must be an independent adjacent/phase-locked coordinate.

---

## D. Required tests

Create exact tests covering:

1. S6 saturation, exhaustive 30,030 states.
2. S6 composite repack `{6,35,143}`, exhaustive 30,030 states.
3. S8 composite repack algebraic invariants and a deterministic large sample.
4. Adjacency theorem exhaustive for `2 <= M <= 100` and all `0 <= X < M(M+1)`.
5. Canonical 36/37 boundary vectors.
6. Canonical 30030/30031 vectors around `M-1`, `M`, `M+1`, several higher sheets, and the alias boundary `M*A`.
7. Universal projection to prime, composite, and shared-factor target moduli.
8. Lift-aware S6->S8 regression for `X=30030`, requiring extension residues `(8,10)`.
9. Heterogeneous affine round-trip over composite carriers.
10. Exact count witness showing S6->(17,19) is not product-uniform.

No random-only acceptance gate is sufficient where the finite state space is small enough to exhaust.

---

## E. FHE / issue #95 interaction

This PR must not claim that these gates alone solve public BFV bootstrap issue #95.

What they establish is the exact state machinery needed to avoid destroying residual/lift information before a secret-dependent public refresh transition is evaluated. Public bootstrap must still correctly evaluate the encrypted secret-dependent relation or migrate to the documented exact low-bits/BGV path.

The useful integration rule is:

> preserve/derive the complete exact phase state first; only then perform the encoding transition. Never replace a reversible decomposition with independently rounded component projections.

---

## F. Completion gate

This work is complete when:

```text
cargo test -p exact_transcendentals
```

passes with the new theorem regressions, no floating-point production path is introduced, no new Garner/mixed-radix call appears in the transduction hot path, and the `X=30030` lift-aware extension test emits `(mod17,mod19)=(8,10)`.

If production integration is not completed in the first implementation pass, the theorem harness must still land and the unimplemented production entry point must fail closed rather than silently reduce to the source corridor.
