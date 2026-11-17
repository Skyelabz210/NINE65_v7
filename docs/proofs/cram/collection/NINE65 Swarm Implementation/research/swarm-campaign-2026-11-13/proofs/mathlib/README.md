# Mathlib bridge mirror

These files mirror the maintained original Lean repository at local commit
`dd9c6cfb341ad3747f148c336a015e2b80664e87`.

`AnchorSaturation.lean` belongs at `KElimination/AnchorSaturation.lean`.
`audit_original_repository.py` belongs at `scripts/audit_proofs.py`; run it
there, with the repository's pinned `lean-toolchain` and `lake-manifest.json`.
It is not a standalone script for this mirror directory.

Apply [the complete patch](../original-repository.patch) to original revision
`0400092096962e3da45a8e5cbb82185a3c2c38fe` to reproduce the integrated project.
The standalone 180-declaration checker intentionally excludes this Mathlib
bridge; its 13 theorems are included in the separate 223-declaration audit.
