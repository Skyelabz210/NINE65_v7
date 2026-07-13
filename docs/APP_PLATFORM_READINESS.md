# NINE65 Application Platform Readiness Ledger

**Integration branch:** `hardening/beyond-100-app-platform`

This ledger maps the pre-application hardening report to repository artifacts. “Implemented” means the source change exists. “Verified” requires CI or a checked local runner artifact on the exact commit.

| Item | Implementation | Current state | Release requirement |
|---|---|---|---|
| Security-mode matrix | `docs/SECURITY_MODE_MATRIX.md` | Implemented | Mode declared by every app |
| Decrypt endpoint hard gate | `crates/fhe-service/src/handlers.rs` | Implemented | Service tests and production negative probe pass |
| WASM first-class CI | `.github/workflows/app_platform_gates.yml` | Implemented | wasm32 build passes and key export stays disabled |
| Claim governance | `CLAIM_REGISTRY.csv`, `CLAIM_EVIDENCE_LEDGER.md`, retirement record | Implemented | Registry and stale-claim gates pass |
| Lineage reconciliation | `docs/LINEAGE.md` | Implemented | README/docs use current mode-qualified language |
| External benchmark harness | `scripts/external_fhe_matrix.py` | Protocol implemented | Same-machine pinned competitor runs required for comparative claims |
| Entropy separation | `docs/ENTROPY_MODEL.md` | Implemented | Source audit confirms key paths use secure entropy |
| CT-NTT/cache roadmap | `docs/CT_NTT_CACHE_ROADMAP.md` | Completion gates defined | CT-0 through CT-6 evidence required for broad constant-time claim |
| App-critical proof spine | Lean `AppBoundary` plus formal spine doc | Implemented | Lean workflow passes with no new axioms/sorry |
| First structured private app | `crates/private-feedback-core` | Implemented | Rust tests/clippy pass; NINE65 ciphertext adapter remains next integration node |
| Current bootstrap/parameter remediation | merged PR #26 | Integrated | Audit remediation workflow passes |
| Residue-native scale DAG | based on PR #28 | Integrated | N02 and N05-N30 gates remain tracked by DAG ledger |

## No-merge conditions

Do not merge this line to `main` while any of the following holds:

- Rust compilation or tests have not executed on the combined branch;
- Lean `AppBoundary` has not elaborated under the pinned toolchain;
- WASM does not compile for `wasm32-unknown-unknown`;
- default production service configuration can reach `/decrypt`;
- claim registry references a missing or superseded artifact;
- the new CRAM path reports nonzero reconstruction, scalar materialization, Garner, or mixed-radix counters;
- the audit remediation statistical run is not coupled to process exit status;
- an application path uses a shared-factor divisor without either FPD or explicit rejection.

## Next integration nodes

1. Attach NINE65 public-evaluator encryption/evaluation adapters to `private-feedback-core` fixed slots.
2. Add browser-generated client key flow and ciphertext upload example.
3. Implement tenant identity and signed request envelopes for service mode.
4. Complete the FPD production path and machine-checked wrapper preconditions.
5. Execute the external benchmark matrix on one pinned machine.
6. Complete CT-0 reachability inventory and CT-2 NTT address-trace evidence.
