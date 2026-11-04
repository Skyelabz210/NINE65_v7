# NINE65 Lineage and Authority Map

**Purpose:** distinguish historical design stages from the current implementation so applications do not inherit stale security or performance claims.

## Lineage

### Stage A — symmetric bootstrap-free research line

The original NINE65 work centered on trusted-key-holder computation, DualRNS arithmetic, K-Elimination rescaling, persistent Montgomery representation, and long finite chains without a public evaluator bootstrap. Historical documents describing “bootstrap-free symmetric-mode FHE,” “no evaluation keys,” or fixed depth-50 behavior belong to this stage.

These documents remain useful for architectural provenance. They are not the complete description of the current repository.

### Stage B — public DualRNS evaluation

The codebase added public keys, DualRNS evaluation keys, public ct×ct multiplication, relinearization, modulus switching, and explicit separation between symmetric and public execution. Public-mode depth must be measured separately from symmetric-mode depth.

### Stage C — Clockwork bootstrap and v8 Shadow Butterfly

The repository added:

- real Clockwork bootstrap integration;
- circular and KSK-separated bootstrap paths;
- `AutoBootstrapEvaluator`;
- SBNI rerandomization and timing-noise hardening (added here, later retired — see below);
- CLASS-F / CLASS-R modulus separation;
- exact parameter-product accounting and fail-closed budget preflight.

A software noise-counter reset is not a bootstrap. Only a live ciphertext refresh that restores a usable budget may be reported as bootstrap.

**Stage C amendment (2026-08-09):** SBNI was retired. Its entropy source was
a deterministic, publicly recomputable function of the operation index and
delivered none of the rerandomization or timing-resistance properties
claimed for it in Stage C. See `docs/LADDER_REMOVAL.md` §1 and
`docs/RETIRED_MECHANISMS.md`. Modulus switching, added in Stage B, was
retired the same day for the same-scoped reason recorded in
`docs/RETIRED_MECHANISMS.md`: exact residue-space division unfuses "divide"
from "drop a lane," so the level ladder it depended on no longer exists.

### Stage D — service, WASM, edge, and acceleration surfaces

The repository added:

- `fhe-service` for session-based internal service operation;
- `nine65-wasm` for browser/device execution;
- MANA/UNHAL acceleration and hardware abstraction;
- Python/FFI experimental bindings.

Each surface has a distinct key boundary and must use the security mode matrix.

### Stage E — CRAM residue-native integration

The integration line adds canonical CRAM state and architecture counters.
The [CRAM integration contract](CRAM_INTEGRATION_CONTRACT.md), incorporating
the 2026-10-27 policy clarification, governs current residue computation:

- reconstruction is permitted under declared semantics and provenance;
- Garner/mixed-radix synthetic emissions remain prohibited;
- information loss must not violate the declared reversible operation;
- compute uses exact integers with explicit range and anchor state;
- K-Elimination and division retain their operation-specific preconditions.

Reconstruction/projection counts must report actual activity; nonzero counts
are not automatic policy failures. The general encrypted shared-factor division
adapter remains unenabled. For working research refresh and notation, use
[current public-refresh status](PUBLIC_REFRESH_STATUS.md).

## Authority order

When two artifacts disagree, use this order:

1. current executable code on the reviewed commit;
2. passing CI and checked raw evidence for that commit;
3. current Lean formalization of record;
4. current normative docs (`SECURITY_MODE_MATRIX`, claim ledger, benchmark policy);
5. dated audits and benchmark reports;
6. historical papers and archived reports.

No document can promote a measured result to a theorem, or a historical design target to current functionality.

## Current implementation statement

NINE65 is an exact-integer BFV/DualRNS privacy substrate with public, KSK-separated, symmetric protected, service, browser/edge, and acceleration surfaces. It includes finite leveled computation plus real low-depth refresh paths. Application claims must identify the selected mode, parameter tuple, commit, and evidence artifact.

## Deprecation rules

The following phrases require qualification or removal when they appear without a dated artifact and mode:

- “unlimited depth”;
- “depth 50”;
- “bootstrap-free”;
- “zero-cost entropy”;
- “production ready”;
- “constant-time”;
- “consumer-side privacy.”

Approved replacements state the exact mode and evidence, for example:

> Under `PublicEvaluatorKsk`, on commit `<sha>`, using parameter tuple `<tuple>`, the checked depth/refresh run in `<artifact>` completed with `<result>`.
