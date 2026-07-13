# NINE65 Claim Evidence Ledger

The CSV registry is the machine-enforced index. This ledger supplies the scope and evidence state required to interpret each claim.

## Evidence labels

| Label | Meaning |
|---|---|
| `source_integrated` | implementation exists on the reviewed branch; compiler/runtime verification is pending |
| `machine_checked` | the exact theorem compiled under the pinned Lean toolchain and axiom audit |
| `executable_checked` | the exact source passed the declared executable gate on the identified commit |
| `prose_proven` | reviewed mathematical argument without current machine proof |
| `measured` | finite experiment under a stated substrate and scope |
| `open` | required evidence or proof is absent |
| `retired` | retained for history but not active evidence |

## Required fields for public claims

| Field | Meaning |
|---|---|
| Claim ID | Stable identifier matching `CLAIM_REGISTRY.csv` |
| Status | One evidence label above |
| Mode | Public evaluator, KSK-separated, symmetric protected, service operator, WASM client, or experimental |
| Parameter tuple | Exact N, plaintext modulus, ordered main primes, anchors, distributions, key-switch decomposition, and bootstrap configuration |
| Substrate | CPU/GPU/FPGA/WASM and enabled acceleration features |
| Commit | Exact source commit |
| Command | Reproduction command |
| Artifact | Raw checked output or proof record |
| Scope | Inputs, circuit, depth, trials, and failure criteria |
| Projection policy | Permitted boundary projections and architecture-counter result |

## Active claim interpretations

### `readme.current_functionality_scope`

- **Status:** `source_integrated`; combined-head Rust/WASM/Lean execution pending.
- **Modes:** public evaluator, KSK-separated, symmetric protected, service, WASM/edge.
- **Artifact:** `docs/LINEAGE.md`.
- **Scope:** identifies source surfaces; does not certify every surface for production.

### `security.mode_firewall`

- **Status:** `source_integrated`; Lean module and service enforcement exist, combined-head execution pending.
- **Artifact:** `docs/SECURITY_MODE_MATRIX.md`, `lean4/KElimination/KElimination/AppBoundary.lean`, and `crates/fhe-service/src/handlers.rs`.
- **Scope:** evaluator capability separation and default service decryption denial.

### `formal.lean_record`

- **Status:** `machine_checked` only for the modules and commit listed in `docs/LEAN_FORMAL_VERIFICATION_2026-06-03.md`; the new application-boundary module is pending the current Lean workflow.
- **Artifact:** the dated Lean report and current `AppBoundary.lean` source.
- **Scope:** do not extend the older report to newly added modules before CI.

### `audit.fail_closed_bootstrap_budget`

- **Status:** `source_integrated`; configured Rust workflow pending.
- **Artifact:** `docs/AUDIT_REMEDIATION_2026-07-13.md`.
- **Scope:** live DualRNS auto-bootstrap preflight, exact modulus products, and exact budget accounting on pinned audit profiles.

### `cram.residue_native_dag_foundation`

- **Status:** independent exact-integer harness evidence exists; Rust runner status remains pending.
- **Artifact:** `docs/CRAM_RESIDUE_NATIVE_DAG_EXECUTION.md`.
- **Projection policy:** no reconstruction, scalar materialization, Garner, or mixed-radix activity in the new path.

### `app.private_feedback_residue_core`

- **Status:** exact-integer Python differential artifact is checked; Rust tests/clippy pending.
- **Artifact:** `crates/private-feedback-core/README.md` and `artifacts/app_platform/private_feedback_correctness_2026-07-13.json`.
- **Scope:** bounded structured fields, next-question selection, safe-basis decomposition, and lane-wise aggregation. No raw-text FHE claim.

### `app.private_feedback_nine65_adapter`

- **Status:** `source_integrated`; live DualRNS round-trip test is present but has not executed on the combined head.
- **Artifact:** `crates/private-feedback-nine65/README.md` and its Rust test module.
- **Scope:** public-key slot encryption and homomorphic addition with no public decrypt API.

### `wasm.client_boundary`

- **Status:** `source_integrated`; wasm32 build pending.
- **Artifact:** `docs/SECURITY_MODE_MATRIX.md` and `crates/nine65-wasm/src/lib.rs`.
- **Scope:** boundary checks and disabled secret-key export. Browser memory is not claimed physically confidential.

### `entropy.role_separation`

- **Status:** documented source invariant; focused source/runtime gates pending on combined head.
- **Artifact:** `docs/ENTROPY_MODEL.md`.
- **Scope:** OS CSPRNG, deterministic `ShadowHarvester`, and SBNI are separate mechanisms.

### `security.ct_ntt_source_hardening`

- **Status:** source remediation integrated; source gate and targeted Rust tests pending on GitHub runner.
- **Artifact:** `docs/CT_NTT_AUDIT_2026-07-13.md`.
- **Scope:** CLASS-F prime enforcement, public NTT address schedule, branchless coefficient operations, branchless Persistent-Montgomery core, and CLASS-R odd composite support.
- **Exclusions:** compiler IR/disassembly, cache-line alignment, empirical timing, speculative execution, power, and EM closure.

### `bench.external_fhe_matrix_protocol`

- **Status:** harness/schema implemented; same-machine external implementation runs are open.
- **Artifact:** `docs/EXTERNAL_FHE_BENCHMARK_MATRIX.md` and `scripts/external_fhe_matrix.py`.
- **Scope:** protocol only; no comparative performance claim exists yet.

## Promotion rule

A claim may be public only when:

1. its CSV row is `public,secure`;
2. every required field is present;
3. the artifact was produced from the exact reviewed commit;
4. no newer lower reproducible result contradicts it;
5. wording includes mode, substrate, and scope;
6. residue-native paths report no Garner, mixed-radix, internal reconstruction, or hidden scalar materialization;
7. all required CI and independent-attestation gates pass.
