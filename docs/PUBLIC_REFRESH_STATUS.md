# Current public-refresh status and notation

Updated 2026-11-01. Read this before diagnosing public refresh from older
handoffs, issue descriptions, parameter predicates or failure artifacts.

**Ref scope:** this guide describes `fix/public-refresh-research-gates`.
At this audit, GitHub `main` was `091c4ff` and did not contain the new backend
or README update. Always identify the branch/commit being analyzed. Publishing
a review branch does not merge it into `main` or admit production security.

| Scope | Current result | Implementation / evidence |
| --- | --- | --- |
| Explicit research refresh | Working encrypted correction, message restoration and original-key return | `ops::public_refresh_circuit::PublicRefreshCircuit`; requires `allow_insecure` |
| Native execution | Five refreshes and five following squares, all 8,192 coefficients checked after each: 81,920 comparisons | [Native evidence manifest](../artifacts/execution/2026-10-28/public-refresh-circuit/manifest.json), `extended_native_run` |
| Current return certificate | 562 error bits after slot return below a 633-bit threshold; next square/source radius 48 within support 49 | [Lift/return proof](execution/2026-10-31/PUBLIC_REFRESH_LIFT_REFINEMENT.md) |
| Canonical plaintext-root binding | Same sealed value-root capability survives refresh; ciphertext lineage advances | [Canonical root](execution/2026-10-31/CANONICAL_PLAINTEXT_ROOT.md) |
| Legacy/default Clockwork entry points | Still fail closed; their component-rounding path lacks its correction | `ops::bootstrap`; `params::secure_configs` support predicates |
| Production security | Not admitted for the complete correlated evaluation-key setup | [Key graph](execution/2026-10-31/PUBLIC_REFRESH_KEY_GRAPH.md), [conditional reduction](execution/2026-10-31/PUBLIC_REFRESH_SECURITY_REDUCTION.md) |

The native five-cycle snapshot predates the later root/inventory additions.
Those have separate current regressions; do not claim a new latest-head full
native run. The measured five-cycle run took 56.6 minutes including setup and
8.70 GiB peak RSS. It is functionality evidence, not low-latency evidence.

The [evidence summary](execution/2026-10-31/PUBLIC_REFRESH_EVIDENCE_SUMMARY.md)
collects the supporting facts. The [new attack assessment](execution/2026-10-31/HOU_JIANG_ASSESSMENT.md)
executes a pinned authors' implementation. Its model costs are not security
certificates; corrected-theorem conformity, complete quantum-hybrid coverage
and the joint/KDM setup premise remain unestablished. An open security premise
is not itself a demonstrated plaintext failure or a key-recovery attack.

## Notation must identify its producer

| Symbol | Meaning and scope |
| --- | --- |
| Legacy `K_0` / `K_j` | Displaced correction lost by independently rounding Clockwork ciphertext components; issues #95/#117 diagnose that path |
| Native `x` | Source-derived integer phase `d0+d1*s`, with `x=rho+p*K_native` |
| `rho` | Native residual supported on [-49,49]; this is not the quotient K |
| `K_native` | Native source quotient supported on [-48,48], computed under encryption by the G/H circuit; not automatically the legacy intermediate `K_0` |
| `Y` | Shifted native lift `K_native+48`, in [0,96] |
| `kappa_36/37` | `floor(Y/36)`, in [0,2], derivable from authentic same-source remainders. The full restoration round-trip contracts to K_native without materializing remainder ciphertexts |
| `Q_RLWE` | Product of ciphertext worker moduli; not a winding epoch counter |
| Root identity | Local producer-issued identity for canonical plaintext m; not K, a carried arithmetic epoch, or a remote cryptographic attestation |

Neither the standalone digit primitive's full F_65537 domain nor an old
canonical-lift LUT cost is a universal impossibility result for the bounded
native producer. The 832-bit post-extraction remainder-lookup objection and
667-bit separate sheet-consumer return do not describe the fused 562-bit
message-restoration path. Independent protected remainder emission and legacy
phase-integer Root211 APIs are still separate constructions.

## Evidence and navigation rules

* Identify the module/API, tuple, source commit and whether a statement concerns
  correctness, resource cost, security assumptions or production integration.
* Date-stamped handoffs and task acceptance flags describe their recorded
  snapshot. They do not override later executable evidence or grant later work
  automatic task acceptance.
* Preserve hashed raw logs, manifests and failed experiments. Correct their
  current interpretation in navigation/index documents rather than rewriting
  historical measurements.
* An open legacy issue or a closed issue is not a repository-wide capability
  test. Keep the legacy gate closed while describing the separate working API.
* Do not present an estimator executable as the encrypted refresh implementation,
  or label a successful arithmetic test as production-security approval.

Key-free inspection and the expensive encrypted example are documented in
[README](../README.md#public-refresh-status). See the
[stale-diagnosis correction record](maintenance/PUBLIC_REFRESH_STALE_DIAGNOSES_2026-11-01.md)
for affected paths and dispositions.
