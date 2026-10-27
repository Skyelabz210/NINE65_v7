# Checked signed CRT substrate

This package imports the user-supplied `ns_v5/qmnf_crtbigint` substrate and
repairs signed integer arithmetic, full-width magnitude reconstruction, and
capacity admission. The source archive remains unchanged outside the repository.

Original `src/lib.rs` SHA-256:
`59d0eca292afeb6ec09cc34cb4c10cbc739c57e1a21045c88a0b074e41f12cb0`.

The fixed basis has eight pairwise-coprime moduli and a 504-bit product `M`.
An integer stores a private sign and magnitude residues, with `|x| < M`.
Checked addition, subtraction and multiplication return `CrtError` if the exact
result exceeds that capacity. The operator traits fail explicitly on the same
condition. They never silently reduce integer results modulo `M`.

`mod_pow` and `mod_inverse` are explicitly modular operations, as their names
indicate. They retain signed-magnitude convention; `signed_residue(lane)` is the
Euclidean residue of the represented signed integer. `residue(lane)` and
`residues()` expose the magnitude representation for compatibility.

`magnitude_limbs()` reconstructs the full magnitude into eight little-endian
`u64` limbs. `try_garner_reconstruct()` refuses a magnitude wider than `u128`.
The legacy `garner_reconstruct()` now panics on that narrowing error rather
than returning wrapped bits. `to_i64()` includes the asymmetric `i64::MIN`
boundary and refuses values outside the signed range.

This is a reference and boundary arithmetic package. Signed comparisons and
capacity checks reconstruct full magnitudes. This implementation must not be
described as the reconstruction-free production BFV divider or wired into that
hot path under that claim. Importing raw residues selects their canonical
magnitude; it does not authenticate the history or range of an external value.

Public `CRTBigInt.residues` and `.sign` fields become read-only accessors. Code
that constructed raw struct literals must use checked constructors. This is an
intentional API change to preserve canonical sign/zero and residue invariants.

The supplied auxiliary research types and their 23 tests are retained. Their
broader scaffold, entropy, stability, and security claims are not certified by
the signed-arithmetic repair. They are not connected to NINE65 production FHE.

Validation adds exhaustive small signed arithmetic, 10,000 deterministic
full-range signed `i64` input pairs checked against independent `i128`
arithmetic, 24 signed 245-bit operand pairs checked against Python arbitrary
integers, signed lane conversion, modular units, canonical zero, exact
multi-limb powers/carry/borrow, and rejection at the full CRT product boundary.

The original 23 tests passed while four new regression tests failed before the
fix. The repaired package passes all 23 original tests and 12 added regression
tests in debug and optimized profiles. Reproduce with:

```sh
cargo test -p qmnf_crtbigint
cargo test -p qmnf_crtbigint --release
cargo clippy -p qmnf_crtbigint --all-targets -- -D warnings
```
