# NINE65 architecture map

This map describes source organization, not production security admission.
Read [current public-refresh status and notation](PUBLIC_REFRESH_STATUS.md)
and the [security mode matrix](SECURITY_MODE_MATRIX.md) for capability scope.

| Source | Role |
| --- | --- |
| `crates/nine65/src/ops/rns_fhe.rs` | BFV/DualRNS encryption, evaluation and owner-side decryption |
| `crates/nine65/src/ops/public_refresh_circuit.rs` | Opt-in research public refresh with encrypted carry correction and key return |
| `crates/nine65/src/ops/bootstrap.rs` | Legacy Clockwork entry points; named-profile public refresh remains gated |
| `crates/nine65/src/ops/symmetric_bootstrap.rs` | Trusted-key-holder refresh; distinct confidentiality boundary |
| `crates/nine65/src/params/secure_configs.rs` | Named tuples, screening and admission predicates |
| `crates/nine65/src/arithmetic/` | Modular arithmetic, rescaling, K-Elimination and experimental kernels |
| `crates/cram-core/` | Residue state, basis validation, topology and counters |
| `crates/exact_transcendentals/` | Exact transcendental and CRAM arithmetic components |
| `crates/mana/`, `crates/unhal/` | Acceleration and hardware abstraction |
| `crates/fhe-service/` | Operator-owned session-key HTTP service |
| `crates/private-feedback-core/`, `crates/private-feedback-nine65/` | Structured feedback and encrypted aggregation reference path |
| `lean4/KElimination/` | Maintained formalization; theorem assumptions remain scoped |

The workspace contains `crates/*` except the explicitly excluded Python, WASM
and FFI binding crates; `fuzz` is separate too. The `NINE65-Rust-Guide`
submodule is independently maintained and is not a capability authority.

The evaluator's public/evaluation material must be distinguished from the
owner's secret key. A trusted-key-holder decrypt/re-encrypt refresh and the
service's operator-owned keys do not establish evaluator-blind public FHE.
Research refresh correctness does not discharge related-key confidentiality.

For execution semantics use the [CRAM integration contract](CRAM_INTEGRATION_CONTRACT.md):
reconstruction is permitted under the declared operation contract; Garner and
mixed-radix synthetic emissions remain prohibited. Division primitives retain
their own coprimality/range requirements; a general shared-factor encrypted
adapter is not enabled.

The former September map is [archived](../archive/hygiene/2026-11-04/docs/ARCHITECTURE.md).
Its service-outage diagnosis, implementation blockers, test counts and blanket
reconstruction ban are historical, not instructions for this checkout.
