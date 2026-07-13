# NINE65 Claim Evidence Ledger

The CSV registry remains the machine-enforced index. This ledger supplies the fields required for a claim to be interpreted correctly.

## Required fields

| Field | Meaning |
|---|---|
| Claim ID | Stable machine identifier matching `CLAIM_REGISTRY.csv` |
| Status | `machine_checked`, `executable_checked`, `prose_proven`, `measured`, `open`, or `retired` |
| Mode | Public evaluator, KSK-separated, symmetric protected, service operator, WASM client, or experimental |
| Parameter tuple | Exact N, plaintext modulus, ordered main primes, anchors, noise distribution, key-switch decomposition, and bootstrap configuration |
| Substrate | CPU/GPU/FPGA/WASM and acceleration features |
| Commit | Exact source commit |
| Command | Reproduction command |
| Artifact | Raw checked output or proof record |
| Scope | Input set, circuit, depth, trials, and failure criteria |
| Projection policy | Permitted boundary projections and architecture-counter result |

## Active claim interpretations

### `readme.current_functionality_scope`

- **Status:** executable_checked plus documented boundaries
- **Modes:** public evaluator, KSK-separated, symmetric protected, service, WASM/edge
- **Artifact:** `docs/LINEAGE.md`
- **Scope:** identifies implemented surfaces; does not claim every surface is production certified.

### `security.mode_firewall`

- **Status:** machine_checked for the abstract capability theorem; executable enforcement required per service/app
- **Artifact:** `docs/SECURITY_MODE_MATRIX.md` and `lean4/KElimination/KElimination/AppBoundary.lean`
- **Scope:** evaluator capability separation and default service decryption denial.

### `audit.fail_closed_bootstrap_budget`

- **Status:** executable_checked only after the configured Rust workflow passes
- **Artifact:** `docs/AUDIT_REMEDIATION_2026-07-13.md`
- **Scope:** live DualRNS auto-bootstrap preflight and exact budget accounting on the pinned audit profiles.

### `cram.residue_native_dag_foundation`

- **Status:** executable_checked for the independent harness; Rust runner status must be attached before promotion
- **Artifact:** `docs/CRAM_RESIDUE_NATIVE_DAG_EXECUTION.md`
- **Projection policy:** no reconstruction, scalar materialization, Garner, or mixed-radix activity in the new path.

### `formal.lean_record`

- **Status:** machine_checked on the pinned Lean/Mathlib record
- **Artifact:** `docs/LEAN_FORMAL_VERIFICATION_2026-06-03.md`
- **Scope:** exact modules compiled by the Lean CI; one registered AHOP hardness assumption.

### `app.private_feedback_residue_core`

- **Status:** executable_checked after workspace tests pass
- **Artifact:** `crates/private-feedback-core/README.md`
- **Scope:** bounded structured fields, next-question class selection, safe-basis decomposition, and lane-wise aggregation. No raw-text FHE claim.

### `wasm.client_boundary`

- **Status:** executable_checked after the WASM CI job passes
- **Artifact:** `docs/SECURITY_MODE_MATRIX.md`
- **Scope:** buildability, boundary checks, and disabled secret-key export. Does not claim browser memory is physically confidential.

### `entropy.role_separation`

- **Status:** documented security invariant plus source/tests
- **Artifact:** `docs/ENTROPY_MODEL.md`
- **Scope:** CSPRNG, deterministic ShadowHarvester, and SBNI are distinct mechanisms.

## Promotion rule

A claim may be public only when:

1. its CSV row is `public,secure`;
2. every field above is present;
3. the exact artifact exists in the reviewed commit;
4. no newer lower result contradicts it;
5. the claim wording includes mode and scope;
6. the result does not depend on Garner/mixed-radix activity in a residue-native path;
7. all required CI gates pass.
