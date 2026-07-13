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
- SBNI rerandomization and timing-noise hardening;
- CLASS-F / CLASS-R modulus separation;
- exact parameter-product accounting and fail-closed budget preflight.

A software noise-counter reset is not a bootstrap. Only a live ciphertext refresh that restores a usable budget may be reported as bootstrap.

### Stage D — service, WASM, edge, and acceleration surfaces

The repository added:

- `fhe-service` for session-based internal service operation;
- `nine65-wasm` for browser/device execution;
- MANA/UNHAL acceleration and hardware abstraction;
- Python/FFI experimental bindings.

Each surface has a distinct key boundary and must use the security mode matrix.

### Stage E — CRAM residue-native integration

The current integration line adds a canonical CRAM state and hard architecture counters. The production rule is residue-native execution:

- no internal number-line projection;
- no hidden scalar materialization;
- no Garner reconstruction;
- no mixed-radix conversion;
- exact integer bounds and explicit winding/anchor state;
- K-Elimination and, when completed in the FHE path, Fused Piggyback Division for exact division routing.

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
