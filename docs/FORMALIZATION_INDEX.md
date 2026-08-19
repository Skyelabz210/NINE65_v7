# Formalization Index (originally written for NINE65 v6 "a Clockwork Prime")

This index maps formal proofs (Coq/Lean) to the Rust implementation. It was
written as the proof-to-code reference for the v6 codebase and has not been
regenerated for v8; several entries below are stale (noted inline). For the
current, maintained formal-verification status, see CLAUDE.md's "Formal
Verification" section.

> **Coq status (2026-08-19):** the "Integration status" column below predates
> the project's move to Lean and should not be read as implying the Coq
> proofs are machine-checked evidence. Per CLAUDE.md: `proofs/coq/` and
> `verified-innovations/proofs/coq/` are a **legacy v2-era exploration**,
> **not maintained**, and **not the verification basis** — several files do
> not compile and several contain `Admitted` lemmas. **Lean 4
> (`lean4/KElimination/`) is the formalization of record**: `lake build`
> reports 0 errors and 0 `sorry` across all 19 modules, with a single
> documented axiom (`ahop_hardness`, the AHOP cryptographic hardness
> assumption). Do not cite a Coq mapping below as proof that the referenced
> Rust module is formally correct.

## Coq Proof Mapping (legacy — see status note above)

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

`ZMod.lean`, previously listed here, does not exist in `lean4/KElimination/`
and has been removed from this table — it is not one of the current 19
modules. See `lean4/KElimination/KElimination.lean` and the
`lean4/KElimination/KElimination/` subtree (AHOP/, Lattice/, plus
`AppBoundary.lean`, `CyclotomicPhase.lean`, `EncryptedQuantum.lean`,
`ExactCoefficient.lean`, `GSOFHE.lean`, `IntegerSoftmax.lean`, `MQReLU.lean`,
`MobiusInt.lean`, `Montgomery.lean`, `OrderFinding.lean`, `PadeEngine.lean`,
`ShadowEntropy.lean`, `ShadowNTTButterfly.lean`, `SideChannel.lean`,
`StateCompression.lean`, `Basic.lean`) for the current 19-module set.

| Lean file | Rust module(s) | Integration status |
| --- | --- | --- |
| KElimination.lean | `crates/nine65/src/arithmetic/k_elimination.rs` | Integrated (module docs + validation methods) |
| Basic.lean | `crates/nine65/src/arithmetic/k_elimination.rs` | Integrated (module docs) |
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

> **Scope note:** the noise-budget rows below (`NoiseOverflow`,
> `DepthExceeded`, `NoiseBudgetExhausted`) describe GSO-FHE's bounded,
> budget-tracked evaluator (`ops/gso_fhe.rs`, `TrackedEvaluator`,
> `noise::budget::NoiseBudget`) — a leveled-ladder execution mode that is
> distinct from the CRAM residue-native K-Elimination rescale path used by
> `mul_dual_public`/`mul_dual_symmetric`. Per `docs/RETIRED_MECHANISMS.md`,
> the latter path does not switch moduli and its noise-exhaustion test was
> retired because exhaustion is unreachable there under unbounded depth —
> that retirement does not apply to the GSO-FHE budget model described here.
> Do not read this table as evidence that modulus switching or noise
> exhaustion exist on the CRAM/K-Elimination path.

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
