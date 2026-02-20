# Formalization Index (NINE65 v6 "a Clockwork Prime")

This index maps formal proofs (Coq/Lean) to the Rust implementation. It is the
canonical proof-to-code reference for the v6 codebase.

## Coq Proof Mapping

| Proof file | Rust module(s) | Integration status |
| --- | --- | --- |
| CRTShadowEntropy.v | `crates/nine65/src/entropy/crt_shadow.rs` | Integrated (module docs + unit tests) |
| CyclotomicPhase.v | `crates/nine65/src/arithmetic/cyclotomic_phase.rs` | Integrated (module docs) |
| EncryptedQuantum.v | [EXCLUDED] | Quantum scope out of this build |
| ExactCoefficient.v | `crates/nine65/src/arithmetic/exact_coeff.rs`; `crates/nine65/src/arithmetic/exact_divider.rs` | Integrated (module docs) |
| GSOFHE.v | `crates/nine65/src/ops/gso_fhe.rs`; `crates/nine65/src/compiler.rs` | Integrated (module docs + compiler tests) |
| IntegerSoftmax.v | `crates/nine65/src/arithmetic/integer_softmax.rs`; `crates/nine65/src/ops/neural.rs` | Integrated (module docs) |
| KElimination.v | `crates/nine65/src/arithmetic/k_elimination.rs`; `crates/nine65/src/ops/rns_fhe.rs` | Integrated (module docs + unit tests + precondition validation) |
| MQReLU.v | `crates/nine65/src/arithmetic/mq_relu.rs` | Integrated (module docs + unit tests) |
| MobiusInt.v | `crates/nine65/src/arithmetic/mobius_int.rs`; `crates/nine65/src/ops/neural.rs` | Integrated (module docs) |
| MontgomeryPersistent.v | `crates/nine65/src/arithmetic/persistent_montgomery.rs`; `crates/nine65/src/arithmetic/ntt_fft.rs` | Integrated (module docs) |
| OrderFinding.v | `crates/nine65/src/arithmetic/order_finding.rs` | Integrated (module docs + unit tests) |
| PadeEngine.v | `crates/nine65/src/arithmetic/pade_engine.rs`; `crates/nine65/src/ops/neural.rs` | Integrated (module docs) |
| SideChannelResistance.v | `crates/nine65/src/security/secret_data.rs`; `crates/nine65/src/arithmetic/k_elimination.rs`; `crates/nine65/src/security/gro_gate.rs` | Integrated (module docs + SecretKeyPath trait + GRO gates) |
| StateCompression.v | [EXCLUDED] | Quantum state compression; out of scope for this build |

## Lean4 Proof Mapping

| Lean file | Rust module(s) | Integration status |
| --- | --- | --- |
| KElimination.lean | `crates/nine65/src/arithmetic/k_elimination.rs` | Integrated (module docs + validation methods) |
| Basic.lean | `crates/nine65/src/arithmetic/k_elimination.rs` | Integrated (module docs) |
| ZMod.lean | `crates/nine65/src/arithmetic/k_elimination.rs` | Integrated (module docs) |
| ShadowEntropy.lean | `crates/nine65/src/entropy/crt_shadow.rs` | Integrated (module docs) |

## v6 Additions (Clockwork Bootstrap)

| Component | Proof/Specification | Rust module(s) | Status |
| --- | --- | --- | --- |
| Circular Security | Clockwork Formal Spec D13-D16 | `crates/nine65/src/ops/bootstrap.rs` | Integrated (circular security validation tests) |
| GRO Timing Gate | Clockwork Formal Spec T8-T10, T16 | `crates/clockwork-core/src/gro.rs`; `crates/nine65/src/security/gro_gate.rs` | Integrated (equidistribution tests + maximal period) |
| Garner Reconstruction | Clockwork Formal Spec | `crates/clockwork-core/src/garner.rs` | Integrated (cross-validates K-Elimination) |
| Bound Tracking | Clockwork INV-1 through INV-4 | `crates/nine65/src/arithmetic/bounded_rns.rs` | Integrated (clockwork feature) |
| Key Lifecycle | Clockwork Key States | `crates/nine65/src/security/key_manager.rs` | Integrated (clockwork feature) |
| Limb Integrity | Clockwork INV-6 | `crates/nine65/src/security/integrity.rs` | Integrated (CRC32 checksums, clockwork feature) |

## Error Taxonomy to Theorem Mapping

| Error Variant | Derived From | Runtime Check |
| --- | --- | --- |
| `NotCoprime` | KElimination.v:kElimination_core | `validate_preconditions()` |
| `RangeOverflow` | KElimination.v:kElimination_core | `validate_value()` |
| `NoiseOverflow` | GSOFHE.v:noise_bounded | `NoiseBudget::consume()` |
| `DepthExceeded` | GSOFHE.v:depth_50_achievable | `TrackedEvaluator` depth tracking |
| `OrderNotFound` | OrderFinding.v:lagrange_bound | `find_order()` |
| `SecurityLevelNotMet` | HE Standard v1.1 Table 3 | `LatticeSecurityEstimator::estimate()` |
| `NoiseBudgetExhausted` | IBM 2025 BFV attack mitigation | `NoiseBudget::consume()` with `checked_sub()` |

## Notes

- Integration status reflects documentation linkage and test coverage for the
  corresponding Rust modules.
- [EXCLUDED] entries are intentionally out of scope for this build.
- Module documentation carries "Theorem Reference" blocks pointing to the
  relevant proof files.
- v6 additions are gated behind the `clockwork` feature flag.
- Error variant coverage tests in `tests/error_variant_coverage.rs` verify all 29 variants.
