# Track 1: Derived-Transient Exact mod-Q Multiply

**Assigned agent:** Claude Code  
**Branch:** `claude/track-1-derived-transient-exact-mul`  
**Base:** `main@3f8ac37ff655ca735b26fc31b6030e3320ddeab6`  
**Companion plan:** PR #102, `docs/CRAM_APPLICABILITY_MAP_2026-09-01.md` and
`docs/CRAM_RLWE_COEXISTENCE_PLAN_2026-09-01.md`

## Objective

Replace the multi-prime-inexact multiplication/rescale route with an exact
derived-transient evaluator kernel. The kernel consumes and emits only the
published mod-Q representation. Auxiliary residues are computed during one
operation, never serialized, and discarded before return.

This PR begins as a draft implementation. It becomes mergeable only after all
completion gates below pass on every supported profile selected for the route.

## Non-negotiable arithmetic and security contract

1. Use exact integer and residue arithmetic on every load-bearing path.
2. Introduce no `f32` or `f64` value, estimate, threshold, or oracle.
3. Introduce no Garner or mixed-radix cascade.
4. Do not materialize the canonical coefficient `X` in the production kernel.
   Big integers and canonical reconstruction belong only in tests and reference
   oracles.
5. Do not add an anchor, shadow, redundant, or auxiliary lane to any serialized
   key, ciphertext, relinearization key, Galois key, or bootstrap key.
6. Every auxiliary value must be a deterministic function of the incoming
   mod-Q ciphertext and public parameters.
7. Return a typed error when a proof obligation, range certificate, or
   manufactured-chain identity is absent. Never continue with a best-effort
   quotient.
8. Preserve exact output equivalence with the mathematical BFV rounding rule.
   Do not replace the specified rounding rule with truncation.

## Architectural correction required before wiring `base_ext`

The current `BaseExt::project` requires an external redundant residue
`r_red = X mod m_r`. A mod-Q ciphertext does not carry that residue. Do not
thread it through key generation, encryption, ciphertext state, or
serialization.

Implement a main-base-only canonical-rank primitive. For pairwise-coprime main
moduli `m_i`, product `M`, canonical residues `x_i`, and `M_i = M/m_i`,
define

```text
c_i = x_i * (M_i^-1 mod m_i) mod m_i
rho = floor(sum_i c_i / m_i)
```

Then for every transient auxiliary modulus `a_j`, compute

```text
X mod a_j =
    (sum_i c_i * (M_i mod a_j) - rho * (M mod a_j)) mod a_j.
```

`rho` is the only cross-lane correction required. Compute it directly from the
exact rational sum, without constructing `X`.

### Required implementation shape

- Add a clearly named primitive such as `CanonicalRank` or
  `MainOnlyBaseExt` under `crates/nine65/src/arithmetic/`.
- Precompute all basis-only constants once.
- Require canonical input residues and validate that contract at external
  boundaries.
- Use a certified integer fixed-point interval for the common path.
- When the interval meets an integer boundary, use a fixed-work exact fallback
  that resolves `rho` without reconstructing `X`.
- Expose path observability under tests so both the common and exact-fallback
  paths must execute in the test suite.
- Keep the existing redundant-residue `BaseExt` as a reference/cross-check
  until the new primitive passes every differential gate.

## Implementation stages

### T1.1: Lock the current failure and target semantics

Add regression tests proving all of the following:

- current limb-local `exact_rescale` disagrees with the bigint BFV oracle on a
  multi-prime case where `Delta^2 > Q`;
- the production route cannot call the existing `BaseExt::project` without
  supplying information absent from the mod-Q object;
- the target result is the exact rounded BFV result, reduced back into mod-Q
  lanes;
- no auxiliary lane survives serialization.

The first test documents the current blocker. Do not weaken or delete it after
the new route is introduced; change it to assert that the replacement route
matches the oracle.

### T1.2: Main-only canonical rank and base extension

Implement and test `rho` extraction, then use it to project into one or more
transient auxiliary moduli. Required tests:

- exhaustive enumeration for several small coprime bases;
- every canonical value at zero, one, `M/2` neighbors, `M-2`, and `M-1`;
- rank values from zero through `lane_count - 1`;
- cases that force the certified fallback;
- every named production main-prime prefix;
- exact agreement with an independent Python integer oracle;
- permutation invariance under every tested main-lane ordering;
- typed rejection of non-coprime bases, non-canonical residues, insufficient
  accumulator capacity, and an empty auxiliary base.

### T1.3: Exact rescale contract

The in-tree `UnifiedRescale` requires a manufactured chain `Q = t * D`. Select
one explicit route and encode that choice in types and tests:

1. add an experimental manufactured profile satisfying `Q = t * D`, then rerun
   exact security screening for that exact tuple, or
2. implement a separate exact rounded rescale whose proof applies to the
   existing named chains.

Do not silently apply `UnifiedRescale` to a chain that does not satisfy its
constructor identities.

Before each rescale, prove or check the capacity certificate

```text
X + floor(Delta / 2) < Q * A.
```

Return a typed capacity error when the inequality is not certified.

### T1.4: Evaluator integration

Integrate behind an explicit experimental route first. The operation must:

1. tensor the two mod-Q ciphertexts;
2. derive transient auxiliary residues from the main residues;
3. compute the exact rounded rescale quotient;
4. relinearize using public mod-Q evaluation-key material;
5. emit a normal mod-Q ciphertext;
6. zeroize or drop transient storage before return.

No public API may accept or return the auxiliary base.

### T1.5: Differential and wire gates

For every selected configuration, cover:

- `mul_no_relin` tensor coefficients;
- `mul` including relinearization;
- zero, one, negative-centered, maximum-lane, and rounding-tie neighborhoods;
- seeded random ciphertext pairs;
- repeated multiplication until the documented noise limit;
- bit-identical mod-Q residues against the bigint oracle;
- decrypt equality against the tracked plaintext oracle;
- serialized keys and ciphertexts containing only divisors of Q;
- a call-graph/source gate rejecting Garner, mixed-radix, canonical
  reconstruction, and the old redundant-lane input from the production route.

## Security prerequisites carried into this track

Before this route can support a security claim:

- replace the single-track public/evaluation-key sampler that draws one `u64`
  and reduces it into every Q lane with exact full-width uniform sampling over
  `[0,Q)`;
- apply WIRE-Q inspection to every published key and ciphertext component;
- compare the lattice estimator result with the exact named target; a 240-bit
  binding estimate does not satisfy a 256-bit target;
- rerun the estimator for any manufactured chain introduced by T1.3.

These prerequisites may be delivered as prerequisite commits or a linked PR,
but the exact multiply route cannot be marked complete without them.

## Completion gates

- [ ] No floating-point type or operation enters the arithmetic or crypto call
      graph.
- [ ] No Garner/MRC call and no canonical `X` reconstruction enters the
      production multiply call graph.
- [ ] Main-only rank/base extension agrees with the independent integer oracle
      on every vector.
- [ ] Both certified-common and exact-fallback rank paths execute in tests.
- [ ] Every rescale has a proved manufactured-chain identity and capacity
      certificate.
- [ ] Complete multiply and relinearization are bit-identical to the bigint
      oracle.
- [ ] WIRE-Q serialization tests pass for all public artifacts.
- [ ] Exact full-width public/evaluation-key sampling is active.
- [ ] Named security targets pass the selected binding estimator, or the
      profile name/claim is corrected before use.
- [ ] Benchmarks report exact integer counts and durations only after every
      correctness gate is green.

## Boundary with issue #95

This track computes an evaluator-side quotient determined by public ciphertext
data. Issue #95 additionally requires the secret-dependent correction term to
be represented and evaluated under encryption, or an encoding migration that
removes that requirement. Keep public bootstrap fail-closed until that separate
integration is complete and proven.
