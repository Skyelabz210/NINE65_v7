# CRAM Proofs — start here

This collection brings together the proof sources, theorem statements, independent reviews, build evidence, research reports and executable reference models produced in this collaboration. The archive preserves the directory layout so the relative links work after extraction.

## Read in this order

0. [CRAM core lock and Torus-Fiber intake — 2026-11-17](<CRAM Core Lock 2026-11-17/README.md>): current standalone engine specification, proof obligations, ten new attachments, reproduced composite checks, implementation findings and the 235-declaration integrated Lean audit. Older bundles below retain their dated evidence and counts.
1. [Universal theorem](UNIVERSAL_THEOREM.md): exact query transport, constructive readout, magnitude and target projection.
2. [StarLift](universal-theorem/STARLIFT.md): positive and negative winding queries, their types and orientations.
3. [Closure proofs](CLOSURE_PROOFS.md): combined-anchor resolution and concrete residue-space division/GCD.
4. [Cross-innovation map](CROSS_INNOVATION_MAP.md): applications, derived connections and proposed integrations across the CRAM/NINE65 system.
5. [Proof package](universal-theorem/README.md): source modules and reproduction commands.
6. [Integration specification](PROOF_UPDATE_SPEC.md): the next implementation and formalization obligations.

## Verification record

The earlier standalone distribution preserved here has **130 checked theorem declarations** under Lean4.27.0-rc1, with no admitted proof or custom project axiom. Counts include supporting lemmas. The [verification manifest](universal-theorem/verification.json) records every source hash and transitive foundational dependency. The [compiler log](universal-theorem/verification.log) records a clean rebuild of all project imports; [Lake output](universal-theorem/lake-build.log) records the normal package build. The newer maintained-source audit is in the dated core-lock packet linked above.

The concrete Lean reference algorithms passed [1,809 executable cases and four controls](universal-theorem/closure-smoke.log). [Independent review](universal-theorem/CLOSURE_REVIEW.md) checks assumptions, loop bounds, concrete primitive discharge and StarLift signs. Production Rust/FHE refinements have the separate status recorded in the reports.

The older native-refresh arithmetic slice and current-source runtime evidence retain their own source revisions and scope. They are not folded into the standalone theorem count.

## Research and evidence

- [Expanded analysis](EXPANDED_ANALYSIS.md) and [coverage inventory](expanded-corpus/COVERAGE.md).
- [Original literature and implementation analysis](ANALYSIS.md).
- [Tropical and continuum constructions](TROPICAL_FHE_ADDENDUM.md).
- [General mathematical review](universal-theorem/MATHEMATICAL_REVIEW.md).
- [Cross-innovation review](cross-innovation-review.md).
- [Full file/hash inventory](bundle-manifest.json).

The collection includes supporting Lean, Python and Rust source, selected source extracts, patches, JSON manifests and execution logs. Original repository checkouts, toolchain binaries, compiled build trees and unrelated private material are outside this distribution. Historical statements are retained as evidence with their stated scope, not promoted into present verification.

## Using the folder

The folder is a distribution copy of the maintained research workspace. Keep the manifests and raw logs with their corresponding source. Rebuild the proof package before changing a checked claim. The cross-innovation map labels written deductions and implementation proposals separately from the existing Lean theorems.

Cloud-upload completion, account and file IDs are recorded only after successful upload and readback. Creating this local collection does not by itself mean it has been uploaded to Google Drive.
