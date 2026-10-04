# Issue #86: [P1] Harden validated deserialization: reject trailing bytes and context-invalid DualRNS state

- state: open
- labels: (none)
- created: 2026-08-31T07:10:03Z  updated: 2026-09-04T09:58:12Z
- url: https://github.com/Skyelabz210/NINE65_v7/issues/86

---

## Finding

The `from_*_validated` APIs in `ops/rns_fhe.rs` currently provide mainly structural validation:

- `bincode::decode_from_slice` returns `(value, consumed)` but the consumed byte count is ignored, so trailing bytes are accepted;
- `DualRNSCiphertext::validate()` checks shapes and broad level bounds but does not establish that every residue is canonical for the actual main/anchor moduli;
- a separate `validate_residues(main_primes, anchor_primes)` exists but is not part of the validated decode path;
- keyset validation checks shape consistency but not all semantic invariants needed by secret-key consumers;
- bootstrap secret lifting currently maps a non-ternary secret coefficient to zero rather than rejecting malformed key material.

A method named `validated` should either validate the complete context-dependent invariant or make its narrower contract explicit.

## Required work

1. Reject bincode input unless `consumed == bytes.len()`.
2. Introduce context-bound decode/validation entry points that know the expected `FHEConfig`/`DualRNSContext`.
3. Require exact main-limb count for the ciphertext level and the expected anchor basis.
4. Validate every residue is `<` its corresponding modulus before arithmetic use.
5. Validate `level` semantics exactly rather than only `level <= main.len()` where the representation requires equality.
6. Validate secret keys are ternary under every represented lane before bootstrap/key-switch use; malformed coefficients return a typed error instead of silently becoming zero.
7. Apply allocation/size limits before expensive parsing or nested allocations.
8. Keep serialization compatibility changes versioned and explicit.

## Adversarial tests

Add malformed corpora for:
- valid object + trailing bytes,
- over-modulus residues,
- mismatched main/anchor lane counts,
- inconsistent `level`,
- wrong polynomial lengths,
- non-ternary secret coefficients,
- payloads at and just above allocation limits,
- valid payloads for the wrong config.

All invalid cases must fail with typed errors and no panic. Valid roundtrips must remain byte-for-byte deterministic where the format contract requires it.

## Mandatory before/after performance evidence

Benchmark JSON/bincode encode + validated decode for representative ciphertexts/keysets at all named config sizes. Record integer byte counts and nanosecond/microsecond medians before/after. Also benchmark first arithmetic use after decode to ensure validation does not alter representation or hot-path speed.

## Completion condition

`validated` decode means the returned object is safe to consume under the supplied context, with no trailing payload, noncanonical residue, level ambiguity, or silently normalized malformed secret material.