# CRAM universal proof package

Standalone Lean package imported from the maintained K-Elimination proof workspace on 2026-11-17. Its audited Lean sources are identical to the integrated 235-declaration snapshot. This package is independent of the adjacent `lean4/KElimination` library; run commands from this directory.

## Reproduce

Install the version in `lean-toolchain` using elan. Keep `lake-manifest.json`, which pins mathlib and its dependencies; do not run `lake update` as part of reproducing this snapshot. Fetch the pinned dependencies and their optional compiled cache, then run:

```sh
lake build
python3 scripts/audit_proofs.py --lake "$(command -v lake)" --output /tmp/cram-proof-audit
```

The audit builds the maintained library, inventories every theorem/lemma, rejects admitted or custom assumed declarations, and checks transitive foundational axioms. Recorded result: **235 declarations, 67 axiom-free**; allowed axioms are `propext`, `Classical.choice` and `Quot.sound`. Toolchain: Lean 4.27.0-rc1; mathlib `3bdc7047b97538f795b725dc0713c28c0f53ed10`.

The original audit reused locally compiled dependency artifacts. The publication verifies byte identity of all 21 audited source files and the dependency manifest; it does not claim an additional clean dependency rebuild.

## Contracts and evidence

- [CRAM core specification](docs/cram/CORE_SPEC.md)
- [Proof obligations](docs/cram/PROOF_OBLIGATIONS.md)
- [Source reconciliation](docs/cram/SOURCE_RECONCILIATION.md)
- [Full proof collection](../../docs/proofs/cram/README.md)
- [Integrated audit and source hashes](<../../docs/proofs/cram/collection/CRAM Core Lock 2026-11-17/evidence/integrated-audit/verification.json>)
- [PhaseBinding source](KElimination/UniversalResearch/PhaseBinding.lean)

The mathematical results do not by themselves verify the corresponding Rust implementation, the authenticity of an assumed observation producer, performance on arbitrary inputs, or a cryptographic consumer. Those obligations remain explicit in the ledger.
