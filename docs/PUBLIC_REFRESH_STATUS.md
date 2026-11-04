# Current public-refresh status and notation

Updated 2026-11-04. Read this before diagnosing public refresh from older
handoffs, issue descriptions, parameter predicates or failure artifacts.

**Ref scope:** this guide describes the implementation in this checkout.
The research backend and the older recumbent/CI repairs are integrated through
[PR #201](https://github.com/Skyelabz210/NINE65_v7/pull/201), which also reconciles
PRs #187, #195, #197 and #198. Check that PR's merge state and the exact commit
when comparing a different checkout. Production security admission is separate.
The stale-diagnosis corrections are tracked in
[issue #200](https://github.com/Skyelabz210/NINE65_v7/issues/200).

The [November 1 assessment remediation](execution/2026-11-01/ASSESSMENT_REMEDIATION.md)
records the security-policy correction, open Montgomery timing finding,
scoped real-FHE architecture counters and comparison classification repair.
Its unsigned exact-input packet prepares independent review; joint-key
confidentiality and external attestation remain unestablished.

The [November 2 hosted follow-up](execution/2026-11-02/CT_EVIDENCE_CONTINUATION.md)
confirms the smoke/audit repairs at `a186dd8`: 13 of 14 workflows pass, with
the strict comparison still unsupported. Timing-job success includes three
inconclusive observations; it does not close the original measurement finding.

| Scope | Current result | Implementation / evidence |
| --- | --- | --- |
| Explicit research refresh | Working encrypted correction, message restoration and original-key return | `ops::public_refresh_circuit::PublicRefreshCircuit`; requires `allow_insecure` |
| Native execution | Five refreshes and five following squares, all 8,192 coefficients checked after each: 81,920 comparisons | [Native evidence manifest](../artifacts/execution/2026-10-28/public-refresh-circuit/manifest.json), `extended_native_run` |
| Memory-optimized native execution | One N8192 refresh and following square at commit 4fc4328: 16,384 coefficient comparisons, within an 8 GiB environment | [Native memory result](execution/2026-11-01/NATIVE_REFRESH_MEMORY.md) |
| Native error-renewal observation | At commit 2352435, 24,576 phase-error checks pass alongside the native plaintext checks; measured maximum scaled error contracts from 762490188487606471 to 1043073383 | [Independent phase-error witness](execution/2026-11-01/NATIVE_PHASE_ERROR_OBSERVER.md) |
| Assessment integration rerun | At source commit 1c553f6, one native refresh and following square pass 16,384 plaintext comparisons and 24,576 phase-error checks in 579.60 seconds | [Assessment acceptance](execution/2026-11-01/ASSESSMENT_REMEDIATION.md) |
| Current outer/return certificates | Outer ideal-grid error after slot return: 562 bits below its 633-bit half-Delta threshold. Final scaled work-ring return error: 122782933364666 (47 bits); next square/source radius 48 within support 49 | [Lift/return proof](execution/2026-10-31/PUBLIC_REFRESH_LIFT_REFINEMENT.md) |
| Canonical plaintext-root binding | Same sealed value-root capability survives refresh; ciphertext lineage advances | [Canonical root](execution/2026-10-31/CANONICAL_PLAINTEXT_ROOT.md) |
| Legacy/default Clockwork entry points | Still fail closed; their component-rounding path lacks its correction | `ops::bootstrap`; `params::secure_configs` support predicates |
| Production security | Not admitted for the complete correlated evaluation-key setup | [Key graph](execution/2026-10-31/PUBLIC_REFRESH_KEY_GRAPH.md), [conditional reduction](execution/2026-10-31/PUBLIC_REFRESH_SECURITY_REDUCTION.md) |

The native five-cycle snapshot predates the later root/inventory additions.
Those have separate current regressions; do not claim a new latest-head full
five-cycle native run. The single-cycle result linked above includes the root
checks on its own identified memory-optimized snapshot. The measured
five-cycle run took 56.6 minutes including setup and
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
phase-integer Root211 APIs are still separate constructions. The older sister-tray
prototype's raw remainder winding is not its lifted plaintext quotient without
binding the source phase, encoding-scale residue and any source Q-winding.
Executed counterexamples now pin the exact phase identity and refuse the
unbound correction; they do not negate
the separately implemented G/H refresh producer. The old triple-precharge
fixture also refuses its first following square at 138 error bits versus a
137-bit limit; its former resource assumptions were stale.


## Security claim surface

The publishable statement, and nothing stronger, is:

> PublicRefreshCircuit is executable under allow_insecure. Correctness was observed on an identified older arithmetic snapshot: five refresh cycles and five following squares, 81,920 coefficient comparisons, not a latest-head rerun. A deterministic noise certificate is published (documented 562-bit return bound against a 633-bit threshold); a probabilistic decryption-failure bound is not derived. Confidentiality of the related-key setup is not established. External parameter attestation is not obtained. Constant-time posture is not established. The circuit is not admitted for production use. Legacy Clockwork bootstrap remains disabled (issues #95 and #117).

The [security pack](security/README.md) is the model, the Route D related-key analysis, the deterministic noise note, and the attestation and constant-time non-claims. [Machine-readable status](status/CURRENT.json) repeats the same flags. CI rejects a registry that promotes any of those rows to `public,secure`, a probabilistic failure bound, a latest-head native rerun, or confidentiality marked established. The conditional lemma is unchanged and still does not prove its joint-setup premise.

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

The [machine-checked arithmetic proofs](execution/2026-11-01/PUBLIC_REFRESH_PROOFS.md)
cover the G/H digit identity, bounded native quotient lift, and conditional
phase-clock return/error model. They do not establish Rust refinement or
security of the full key setup. They add no new latest-head native execution
claim and preserve the archived five-cycle snapshot above.

The [written proof packet](proofs/README.md) supplies explicit arithmetic and
composition derivations before further Lean development. A key-free native
preflight on 2026-11-04 recomputed the separate outer and final work bounds;
this is not a new encrypted native run. Existing five-module Lean proofs and
their ten negative/positive gate controls were rerun successfully after
installing the pinned tooling. See the [verification continuation](maintenance/VERIFICATION_2026-11-04.md).
