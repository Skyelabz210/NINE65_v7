# Proof-to-Code Mapping (L1)

Dependencies: A1, A2

## Coq proofs -> Rust modules

| Proof file | Primary Rust module(s) | Notes |
| --- | --- | --- |
| CRTShadowEntropy.v | crates/nine65/src/entropy/crt_shadow.rs | Shadow entropy + quotient signature invariants.
| CyclotomicPhase.v | crates/nine65/src/arithmetic/cyclotomic_phase.rs | Cyclotomic ring phase operations.
| EncryptedQuantum.v | [EXCLUDED] | Quantum scope out of this build.
| ExactCoefficient.v | crates/nine65/src/arithmetic/exact_coeff.rs; crates/nine65/src/arithmetic/exact_divider.rs | Dual-track exact coefficient arithmetic.
| GSOFHE.v | crates/nine65/src/ops/gso_fhe.rs; crates/nine65/src/compiler.rs | Noise bounding and depth claims.
| IntegerSoftmax.v | crates/nine65/src/arithmetic/integer_softmax.rs; crates/nine65/src/ops/neural.rs | Exact-sum softmax.
| KElimination.v | crates/nine65/src/arithmetic/k_elimination.rs; crates/nine65/src/ops/rns_fhe.rs | Exact division and rescaling.
| MQReLU.v | crates/nine65/src/arithmetic/mq_relu.rs | O(1) sign detection.
| MobiusInt.v | crates/nine65/src/arithmetic/mobius_int.rs; crates/nine65/src/ops/neural.rs | Signed integer transforms.
| MontgomeryPersistent.v | crates/nine65/src/arithmetic/persistent_montgomery.rs; crates/nine65/src/arithmetic/ntt_fft.rs | Persistent Montgomery arithmetic.
| OrderFinding.v | crates/nine65/src/arithmetic/order_finding.rs | Non-circular order finding.
| PadeEngine.v | crates/nine65/src/arithmetic/pade_engine.rs; crates/nine65/src/ops/neural.rs | Pade rational approximations.
| SideChannelResistance.v | crates/nine65/src/security/secret_data.rs; crates/nine65/src/arithmetic/k_elimination.rs | Constant-time markers and ct-safe primitives.
| StateCompression.v | [EXCLUDED] | Quantum state compression; out of scope for this build.

## Lean proofs -> Rust modules

| Lean file | Primary Rust module(s) | Notes |
| --- | --- | --- |
| KElimination.lean | crates/nine65/src/arithmetic/k_elimination.rs | Main K-Elimination formalization.
| ShadowEntropy.lean | crates/nine65/src/entropy/crt_shadow.rs | Shadow/quotient reconstruction.
| ZMod.lean | crates/nine65/src/arithmetic/k_elimination.rs | Modular arithmetic lemmas.
| Basic.lean | crates/nine65/src/arithmetic/k_elimination.rs | Core definitions.

## Gaps
- None (quantum-only proofs excluded from this build scope).
