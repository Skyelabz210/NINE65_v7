# CRAM proofs and evidence

Published collection prepared 2026-11-17. This directory brings the complete local CRAM proof collection into NINE65_v7, alongside a standalone maintained Lean package. It preserves the distinction between CRAM's arithmetic engine contracts and NINE65's additional implementation and cryptographic obligations.

## Start here

- [Owner clarification: fixed primary and arbitrary-modulus dependent sisters](FIXED_PRIMARY_SISTER_TRAYS_2026-11-17.md)
- [Full Prime Family read: role transport, dependent composites and corrections](PRIME_FAMILY_RECONCILIATION_2026-11-17.md)
- [Current engine specification](../../../lean4/CRAMUniversal/docs/cram/CORE_SPEC.md)
- [Proof obligations and remaining implementation work](../../../lean4/CRAMUniversal/docs/cram/PROOF_OBLIGATIONS.md)
- [Source reconciliation](../../../lean4/CRAMUniversal/docs/cram/SOURCE_RECONCILIATION.md)
- [Torus-Fiber and certified-lift analysis](<collection/CRAM Core Lock 2026-11-17/ANALYSIS.md>)
- [Latest dated evidence packet](<collection/CRAM Core Lock 2026-11-17/README.md>)
- [Full collection index](collection/CRAM_PROOFS_INDEX.md)
- [Publication inventory and exclusions](PUBLICATION_MANIFEST.json)

## Checked mathematical package

The standalone package is [lean4/CRAMUniversal](../../../lean4/CRAMUniversal/README.md). Its 21 audited source files and Lake dependency manifest match the successful 2026-11-17 integrated audit byte-for-byte: **235 declarations, 67 axiom-free**, with remaining dependencies confined to `propext`, `Classical.choice` and `Quot.sound`.

The package includes universal query transport, integer/ring instances, StarLift, coupled-anchor resolution, residue arithmetic and bounded division/GCD, reference changes, future-query quotients, anchor saturation and source-binding results. Theorems retain their stated hypotheses. This does not establish whole-program Rust refinement, universal O(1) execution or NINE65 confidentiality.

The existing `lean4/KElimination` package remains separate. Its library definitions and build configuration are not replaced by this import. Use each package's documented build and audit commands.

## Historical evidence and publication scope

The collection contains **786 preserved files**: proof sources, papers, original uploads, analyses, reference programs, patches, manifests and execution records. Seven generated legacy Coq/cache/binary artifacts were omitted and are individually listed with their original hashes in the publication manifest. Original uploaded archives remain unchanged.

Frozen manifests, measured results and historical status statements are preserved. Older files that report 130 or 223 declarations, uncommitted snapshots, or no GitHub upload describe their original dates; this publication wrapper records the later import. Paths into `/workspace` and `/tmp` in raw logs identify the original execution environment. New navigation links above work within this repository.

`PUBLICATION_MANIFEST.json` records the initial import at `137d970`; its maintained-document hashes describe that snapshot. The subsequent fixed-primary clarification amends the live specification and ledger without changing the archived collection or any audited Lean source. Its document hashes are recorded in `ARCHITECTURE_CLARIFICATION_MANIFEST_2026-11-17.json`.

Historical patches and prototype sources under `collection/` are evidence, not applied changes to the NINE65 runtime. In particular, the certified-lift frame-binding and scalar-bound findings remain open. The current proof ledger gives the next engine implementation obligations.
