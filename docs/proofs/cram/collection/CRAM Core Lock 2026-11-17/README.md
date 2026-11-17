# CRAM core lock — 2026-11-17

Start with [ANALYSIS.md](ANALYSIS.md): findings, executed checks, corrections and the next proof obligations for the standalone CRAM engine.

- [Core specification](source/docs/cram/CORE_SPEC.md)
- [Proof obligations and current coverage](source/docs/cram/PROOF_OBLIGATIONS.md)
- [Source reconciliation](source/docs/cram/SOURCE_RECONCILIATION.md)
- [Torus-Fiber audit](evidence/torus-review/report.md)
- [certified_lift and PROOFS.pdf audit](evidence/certified-lift-review/report.md)
- [235-declaration Lean audit](evidence/integrated-audit/verification.json)
- [New source-binding module](source/KElimination/UniversalResearch/PhaseBinding.lean)
- [Original input manifest](INPUT_MANIFEST.json)
- [Packet provenance and hashes](PACKET_MANIFEST.json)

`inputs/` preserves all ten attachments. `evidence/` separates fresh audit output from the archived supplied results. `source/` is a snapshot of the maintained proof package and lock documents, including the uncommitted additions; it excludes compiled dependencies. The live maintained documents are in `/workspace/k-elimination-swarm-proof/docs/cram/`.

Proof baseline: `dd9c6cfb341ad3747f148c336a015e2b80664e87`. NINE65 reference, read only: `88a7bdadbf0e1f8fbfdb2b37e9843101b8db3484`. See TRACKED_CHANGES.patch and the packet manifest for the source snapshot. The older CRAM Proofs bundles retain their own dated counts and frozen manifests.

To reproduce the Lean audit from a suitable Lean installation and downloaded pinned dependencies, run `python3 scripts/audit_proofs.py --lake /path/to/lake --output /path/to/audit-output` from source/. The input scripts and reviewed Rust crate, their lockfiles, added regression tests, commands and logs are under the corresponding evidence directories. The four added Rust contract tests pass by demonstrating existing defects; those defects have not been repaired in the supplied prototype.

No Git commit, remote push or Drive upload was performed for this packet. Source review and finite tests are distinct from the compiled Lean statements and from outstanding Rust refinement.
