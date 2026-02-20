# P1 Result - Formalization Reference Integration

Changes applied:
- Added docs/FORMALIZATION_INDEX.md as proof-to-code mapping.
- Updated README.md to reference the formalization index.
- Added theorem reference blocks to modules aligned with formal proofs:
  - crates/nine65/src/entropy/crt_shadow.rs
  - crates/nine65/src/arithmetic/cyclotomic_phase.rs
  - crates/nine65/src/arithmetic/pade_engine.rs
  - crates/nine65/src/arithmetic/integer_softmax.rs
  - crates/nine65/src/arithmetic/mobius_int.rs
  - crates/nine65/src/arithmetic/persistent_montgomery.rs
  - crates/nine65/src/arithmetic/order_finding.rs
  - crates/nine65/src/arithmetic/exact_coeff.rs
  - crates/nine65/src/arithmetic/exact_divider.rs
  - crates/nine65/src/ops/gso_fhe.rs
  - crates/nine65/src/ops/neural.rs
  - crates/nine65/src/security/secret_data.rs
- Added proof-aligned integration tests in crates/nine65/tests/formalization_invariants.rs.

Quantum-only proofs (EncryptedQuantum.v, StateCompression.v) are excluded in
docs/FORMALIZATION_INDEX.md.
