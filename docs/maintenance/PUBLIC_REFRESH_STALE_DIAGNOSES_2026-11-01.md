# Filed findings: public-refresh stale diagnosis and ref mismatch

Audit date: 2026-11-01. Reviewed local branch:
`fix/public-refresh-research-gates`, starting at `ab4fcfa`. The correction
is scoped to status, notation, navigation and the legacy refusal diagnostic;
it changes no cryptographic arithmetic, admission decision or noise target.

## Findings and corrections

| ID | Source of misdiagnosis | Disposition |
| --- | --- | --- |
| REF-01 | The working branch was unpublished. GitHub main at `091c4ff` returned 404 for `ops/public_refresh_circuit.rs` and still showed the old README | Record branch/commit scope explicitly; publish the review branch. An analyst examining main was not examining the implemented research backend |
| DOC-01 | `CLAUDE.md` instructed analysts to begin with August/September handoffs and said refresh was disabled on every config | Route first to `docs/PUBLIC_REFRESH_STATUS.md`; document the separate research API and scope the three old entry points to legacy Clockwork |
| DOC-02 | The same file said `allow_insecure` was blocked in release, contradicting the executable research example | Correct the feature description: release research opt-in exists and does not grant security approval |
| DOC-03 | `CRAM_SHOWCASE.md`, `ARCHITECTURE.md` and the bootstrap contract generalized legacy failure to repository-wide unavailability | Name the legacy API; link the implemented research route and its evidence |
| DOC-04 | `crates/nine65/README.md` labeled August test counts as a current baseline | Date the counts explicitly; route refresh readers to current status |
| DOC-05 | Date-stamped “current/live” handoffs, feasibility notes and task plans continued to look like current capability verdicts | Add historical refresh scope banners to 16 indexed snapshots. Rename the misleading October STATUS heading. Do not alter recorded arithmetic or measured failures |
| CODE-01 | Legacy module comments and a global-sounding error said the carry was missing without identifying the path | Scope bootstrap/config comments and the typed refusal to legacy Clockwork; retain the refusal and add an assertion for the scope wording |
| NOT-01 | Legacy K_0, native K, residual rho, adjacent kappa and Q were conflated | Publish a producer-specific notation table, including native K∈[-48,48], rho∈[-49,49], and the distinction from epoch state |
| ART-01 | The live root-profile JSON said protected views were pending without explaining whether that blocked restoration | Explicitly record that independent view generation does not block the implemented fused restore, with its 562/633-bit bounds. Keep independent-output and security flags false |
| ART-02 | Native manifest top-level fields describe three cycles, while its later `extended_native_run` contains the five-cycle evidence | Point readers to the precise nested record. Preserve the original manifest, logs and hashes |
| ART-03 | Root/inventory code added after the native run could be mistaken for latest-head full-native evidence | Retain the source-snapshot caveat in the current guide; separate later regression evidence from the archived native run |
| REG-01 | The claim registry indexed only the old profile-admission story | Register research correctness and open joint-key admission separately as internal/exploratory; clarify their different scopes in the ledger |
| GATE-01 | The stale-claim checker verified IDs and artifact existence but not refresh status routing | Add a routing/evidence checker, mutation controls, and invocation from the existing CI stale-claim gate |

## Historical evidence handling

The routing manifest `docs/public_refresh_status_sources.json` indexes live
entry points, historical snapshots, and SHA-256 values for key immutable
evidence. Its records are documentation routing, not cryptographic authority.
The raw native failure/success records and attack-assessment results are not
rewritten. The legacy runtime gate still refuses; no issue closure is used as
evidence of correctness or security.

The older full-domain digit capacity and circuit-specific noise refusals remain
valid in their stated scope. They are not universal impossibility statements
for the bounded native producer. Independent protected remainder emission is
still separate from message restoration and canonical-root preservation.

## Validation

* `scripts/check_public_refresh_status.py --self-test` checks routing and
  historical banners; mutation controls reject unscoped legacy verdicts,
  missing routes/banners and rewritten raw evidence.
* Existing claim-registry and stale-claim checks pass with the additional
  refresh routing guard; all newly added routing links resolve.
* Both exact legacy gate tests pass, verifying typed refusal, its new
  diagnostic scope and unchanged production-support behavior.
* All 44 Python refresh checks, Rust formatting and diff whitespace checks pass.

Publication and GitHub tracking are recorded after the local correction is
committed. No claim is made that publishing the branch updates main.
