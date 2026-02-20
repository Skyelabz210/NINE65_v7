# Theorem Stack (O1)

Verified integrations:
- KElimination.v -> arithmetic/k_elimination.rs (doc-linked)
- GSOFHE.v -> ops/gso_fhe.rs + compiler tests
- CRTShadowEntropy.v -> entropy/crt_shadow.rs
- CyclotomicPhase.v -> arithmetic/cyclotomic_phase.rs
- PadeEngine.v -> arithmetic/pade_engine.rs
- IntegerSoftmax.v -> arithmetic/integer_softmax.rs
- MobiusInt.v -> arithmetic/mobius_int.rs
- MontgomeryPersistent.v -> arithmetic/persistent_montgomery.rs
- OrderFinding.v -> arithmetic/order_finding.rs
- ExactCoefficient.v -> arithmetic/exact_coeff.rs + exact_divider.rs
- MQReLU.v -> arithmetic/mq_relu.rs
- SideChannelResistance.v -> security/secret_data.rs

Lean artifacts:
- KElimination.lean builds successfully with warnings-as-error and no deferred proofs.

Excluded by scope:
- EncryptedQuantum.v (quantum aspects not included in this build)
- StateCompression.v (quantum state compression not included)
