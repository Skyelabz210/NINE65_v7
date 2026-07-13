# Claim Retirements — 2026-07-13

The following IDs were removed from the active claim registry because their wording or artifact scope no longer describes the current codebase reliably.

| Retired ID | Reason | Replacement |
|---|---|---|
| `readme.depth50_symmetric_secure` | Historical symmetric survey; later source audit identified real secure_128 leveled behavior and mode-dependent depth. | Per-mode depth evidence under the audit remediation workflow. |
| `readme.fhe_ops_secure_128_192` | Aggregated benchmark row did not encode the exact current parameter and mode boundary. | External/internal benchmark matrix with exact tuple and commit. |
| `readme.bootstrap_zero_symmetric` | “Bootstrap zero” is ambiguous and can be mistaken for public unlimited depth. | Symmetric protected refresh is documented separately in the security mode matrix. |
| `readme.lwe_estimator_secure_configs` | Named-profile claims require pinned independent estimator inputs and raw outputs for the exact tuple. | Candidate parameter status in the July audit remediation artifact. |
| `readme.public_mode_depth_baseline` | Older public-mode baseline predates current fail-closed bootstrap and exact budget accounting. | `audit.fail_closed_bootstrap_budget` after CI execution. |

Retirement does not delete historical artifacts. It prevents them from acting as current public evidence.
