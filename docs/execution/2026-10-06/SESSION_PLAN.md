# NINE65 v7: current remote plan and session execution order

Updated 2026-10-07 after hosted run 37639373719. This is the live-session
control sheet for the 43 cards in
[`tasks.json`](../2026-10-03/tasks.json). The detailed contracts and acceptance
criteria remain in the individual task cards and the
[October 5 runbook](../2026-10-05/SESSION_RUNBOOK.md). A listed card is queued,
not accepted. Record a result and independent review before advancing a card's
dependents. Preserve red correctness assertions and explicit refusals.

## Pinned starting state

* The intake checkout and `origin/main` were
  `017f0163be76c0adb102e581c9e7157ea7ae736a` (PR #162). PR #163 merged
  the initial execution plan at `4666570868456b84fc76929a433450e7281cc477`.
  PR #164 carries the later plan correction, F02 evidence and CI bootstrap
  changes. The original 29-issue manifest is historical and must not be
  rewritten.
* `python3 scripts/nine65_execution_plan.py validate --self-test` passes 12
  self-tests and validates the 43-card DAG, while correctly reporting source
  drift from the original baseline. `ready` reports F00 alone until acceptance
  is established. Neither result verifies ciphertext correctness.
* At intake the latest listed Actions run was the cancelled 2026-02-27 run.
  Publishing PR #163 resumed hosted CI. On PR #164 at `ed6ec8f`, the
  cargo-deny action resolves, formatting and static policy checks pass, and
  the WASM boundary builds and passes. T1 and two application jobs reach real
  Clippy failures; local T1 reports 23 `exact_transcendentals` lint errors.
  T2 is skipped after T1 failure. Fuzz Smoke now installs its pinned nightly
  and runs targets. The latest run finds a five-byte bincode input that
  attempts a 4.04 GB allocation, a K-Elimination harness oracle that reaches
  its panic-on-overflow helper, and three stale fuzz targets that lack the
  release-available configuration. The latest patch uses `for_depth`, checked
  K-Elimination APIs and preserves artifacts; see the
  [Fuzz Smoke triage](FUZZ_SMOKE_TRIAGE.md). The
  [CI bootstrap record](CI_BOOTSTRAP.md) retains the exact pass/fail boundary.
  Actions are enabled, but there are still no
  repository rulesets. #79 remains open until checks execute and pass.
* At intake this host had about 745 MiB free on `/home/acid`, 2.7 GiB RAM and
  no swap. The 1.0 GiB rebuildable Cargo `target` cache was cleared. A damaged
  partial toolchain was removed and Rust 1.89.0 reinstalled serially. `rustc`
  and `cargo` now report the pinned 1.89.0. The serial release sweep completed;
  the filesystem now has roughly 4.4 GiB free.
* The depth-four repeated-square plaintext assertions still fail; the exact
  scalar rescale oracle at the last step does not cure the prior phase overrun.
  No public bootstrap tuple has passed R03 admission. Checked decrypt #158 and
  Recumbent carry/parking #159 remain separate active defects.

The fresh F00 observation is in
[`artifacts/execution/2026-10-06-session/F00/baseline.json`](../../../artifacts/execution/2026-10-06-session/F00/baseline.json).
It records the recovery and is **ready for independent review**, not accepted.

## Current session checkpoint

PRs #163 and #164 merged the plan, F02 record and CI bootstrap. PR #165 is
open at `f0545a058b236c71f81650ed2b8953e585855db8`; it makes the fuzz targets
release-buildable and fixes the K-Elimination harness oracle. Its hosted
Fuzz Smoke run
[37639373719](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37639373719)
completed all five bounded target runs: NTT and K-Elimination pass; deserialize,
encrypt/decrypt and homomorphic addition fail on saved reproducers. The latest
short-input decoder witness requests a 101.9 GB allocation; the other two
targets produce wrong plaintexts. Exact data and artifact hashes are in
[Fuzz Smoke triage](FUZZ_SMOKE_TRIAGE.md). Treat all three as open gates. The
local exact-toolchain replay stopped before target execution when the
ASan-instrumented build left 44 MiB free RAM on this 2.7 GiB host. Hosted logs
and uploaded artifacts remain the failure evidence.

On the same PR head, WASM boundary, static analysis, T3 and mode/claim policy
pass. Strict Clippy fails in T1 and application jobs; T2 and T4 are skipped.
The full 43-card order below remains the execution contract. For this session,
run every independent task in the earliest unblocked wave, capture its evidence,
and keep dependent waves queued whenever an acceptance gate fails. Do not mark
F00/F02 accepted: F00 still lacks an independent review, and F02's default
matrix failed with 21 failures while its 28 feature-gated integration targets
remain unexecuted.

After the hosted run, the local working tree was updated to clear the strict
Clippy findings without blanket lint allowances. The exact pinned-toolchain
command `cargo +1.89.0 clippy --offline -j1 --workspace --all-targets -- -D
warnings` now passes for the whole workspace. This is local, uncommitted
follow-up work on top of the recorded plan commit; PR #165 and its hosted
statuses still refer to the older head until the follow-up is published and
Actions reruns. Focused tests for `cram-core`, `fhe-service`, `mana`, and
`private-feedback-core` also pass (12, 52, 28, and 6 tests respectively; 29
fhe-service tests remain intentionally ignored under the documented wire-Q
outage).

The current-tree pinned release sweep completed with exit 101. The changed
workspace took 61m54s to compile under the release LTO profile; test execution
then took about 50 minutes in `nine65`. The `nine65 --lib` target ran 1,074
tests: 941 passed, 8 failed, and 125 were ignored. Four failures are the
`repeated_squaring_is_exact_under_auto_refresh_*` cases and
`squaring_refresh_costs_exactly_one_bootstrap`; all stop at the explicit
public BFV refresh refusal. `diag_measure_noise_growth` catches
`supports_public_refresh` admitting a corrupting path. The secure-128 and
secure-192 symmetric max-depth benchmarks return wrong plaintexts at depth 4.
`diagnostic_zero_noise_constant_self_square_secure_128` also fails its depth-4
zero-noise controls. The `k_elimination_basis_regression` integration target
ran 3 tests successfully and failed
`class_f_alpha_lanes_must_be_prime_and_distinct`, which expected a composite
Class-F alpha lane to be rejected. These are the only two failed targets in
this local workspace run; other default targets and doc tests passed. The
unrestricted local host did not reproduce the earlier sandbox-only HTTP socket
failures. The 28 feature-gated integration targets remain unexecuted. A
concise result record is under
[`artifacts/execution/2026-10-07-session/F02`](../../../artifacts/execution/2026-10-07-session/F02/).

PR #166's hosted run on head `651d6469bfa8c7777c3559e12fd1cce9a500e7d0`
confirms the local strict-Clippy fix: T1 Static Analysis, T3 review,
correctness, source inventory, WASM, authenticated service boundary,
private-feedback stack and policy checks pass. T1 Fast Gate fails while
parsing the old cargo-deny advisory values; therefore T2 and T4 are skipped.
The same SHA also fails architecture and exact CRAM/dual-RNS assertions,
the release build that enables forbidden `allow_insecure`, the four-candidate
modulus probe (release-mode constructor panic on an invalid composite), three
fuzz targets (deserialize, encrypt/decrypt and homomorphic), and CT inventory /
timing gates. Fuzz NTT and K-Elimination pass. The forced-real-refresh check
reaches the intentional release guard because `nine65_bench` still uses the
test-only `ShadowHarvester`; that path does not establish a production refresh.
Full details and links are in the [#92 hosted checkpoint](https://github.com/Skyelabz210/NINE65_v7/issues/92#issuecomment-6044169517).

The follow-up now corrects the CI harness boundaries without relaxing product
assertions: `deny.toml` uses cargo-deny's current fail-closed advisory schema;
the modulus probe calls `NTTEngine::try_new` and records rejected candidates;
the CRAM-public deterministic fixtures run in the debug test profile because
`allow_insecure` is intentionally unavailable in release; and the CT inventory
check/documentation now expect the 21 tests present on this tree (9 robust-CV,
12 dudect). The current Cargo metadata confirms 28 feature-gated integration
targets: 27 `nine65` targets are running with `allow_insecure` in debug, and
the `nine65-extreme-tests` target remains to run with `extreme-tests`. These
workflow/harness fixes do not resolve the release-suite failures, fuzz
reproducers, or open architecture/security gates. Re-run hosted CI after these
changes; keep T2, F00 acceptance, and later DAG cards queued behind their own
passing gates.

## Execute in dependency order

The following waves cover each of the 43 task cards once. Within a wave, use
the DAG for exact prerequisites and distinct files for any concurrent work.
Advance only after the prior card's own gate passes; a blocked card leaves its
dependents queued. Re-fetch `main`, review open issues/PRs, and pin the parent
commit before each patch.

| Wave | Cards | Work and advance gate |
| --- | --- | --- |
| 0 | **F00** | Preserve the clean starting tree, live issue inventory and exact toolchain/resource record. Recover enough build space and a single working pinned 1.89 toolchain. Independent review of the fresh baseline is still required. |
| 1 | **F01, F02, F03, S00** | Repair tuple/evidence producers; inventory every target and execute a serial `--no-fail-fast` sweep; reconcile historical mechanisms and proof statements; freeze the live S8 root/2-11 phase contract. For #157/#158, export every depth's components, fold and full phase against an independent integer/negacyclic oracle. Locate the first divergence or certified margin crossing. Keep wrong-plaintext tests red until behavior is fixed. |
| 2 | **C00, C01, C06, S02, V00** | Expose the distinct main-Q exact route, derive sound noise bounds, check fallible/capacity edges, validate composite unit-domain operators and capture exact security inputs. Require coherent tensor provenance and independent signed/boundary oracles before an arithmetic repair. |
| 3 | **C02, S01** | Make ciphertext history immutable and provenance-bound, and bind on-demand lift to the intact root after C06's capacity review. |
| 4 | **S03** | Integrate sister frames while preserving the S8 priming root and exact phase relation. |
| 5 | **S04** | Certify operator domains and DIV3 scope. Refuse capacity aliases and nonunit inverses. |
| 6 | **S05, R00, H00** | Connect preserved S8 execution to the public CRAM route, test the tighter-parameter hypothesis term by term, and capture real off-path shadow-source traces with provenance. No regenerated fingerprint or synthetic entropy claim counts as integration. |
| 7 | **C03, R01, H01** | Define strict main-Q wire import/export, derive the live bounded-digit input radius, and evaluate shadow entropy conditioned on the attacker's stated view. Imported bytes alone cannot create a noise certificate. |
| 8 | **C04, R02, H02** | Route the service through certified exact operations, compile the encrypted digit DAG with nodewise bounds, and freeze the Three Locks key/mask and interruption model. Require a real ciphertext/plaintext service test. |
| 9 | **C05, V03, R03, G00, H03** | Stabilize Python on the same route; make CI execute all declared targets and reject zero-test/missing-artifact results; select a secure complete tuple only if every inequality passes; allow GSO only to optimize certified plans; implement the reviewed Shadow Lock lifecycle. R03 remains `blocked_design` until R01/R02/V00 yield an admitted tuple. Do not enable hosted required checks before Actions actually runs. |
| 10 | **B00, B02** | Implement required fixed-work capacity and independently specified clear transforms for the admitted tuple. Verify full coefficient and boundary oracles. |
| 11 | **B01** | Implement exact scale-round, transient NTT capacity and relinearization with coherent main/auxiliary provenance. |
| 12 | **B03, B04** | Add public Galois transforms and the reviewed error/key-domain transition. Verify key relationships and all floor/noise terms. |
| 13 | **B05** | Evaluate the bounded canonical digit under encryption; no evaluator secret, clear digit or component-wise BFV rounding shortcut. |
| 14 | **B06** | Contract and return to the work-key domain; verify every coefficient and exact plaintext. |
| 15 | **B07** | Assemble the admitted native public refresh backend. Refuse unsupported inputs before keygen or output. |
| 16 | **B08** | Predict next-operation and per-ciphertext refresh eligibility across branched/rejoined DAGs; no session-wide counter reset. |
| 17 | **B09** | Prove refresh, multiply, refresh on admitted tuples plus all boundary refusals. #95/#117/#16 remain open until this actually decrypts correctly. |
| 18 | **H04, V01, V02, V04** | Test interruption transitions, close constant-time boundaries on the chosen runtime, connect formal statements to actual kernels, and measure fixed complete workloads with raw before/after integer timings. External lattice estimation and audit remain explicit gates. |
| 19 | **V05** | Reconcile every issue, target, claim, proof, tuple and artifact on one final SHA. Release only after required hosted CI executes and passes, no accepted wrong-output path remains, and independent security evidence exists. |

## First commands and stop rules for this session

1. Obtain independent F00 review without changing the original historical
   baseline. The pinned toolchain and build space are restored. The fresh
   baseline artifact is an observation awaiting review, not acceptance.
2. Inventory the workspace with Cargo metadata and classify all 94 targets
   across 12 packages, including the 43 integration-test targets (34 in
   `nine65`). F02's serial release `--no-fail-fast` sweep has now exercised 59
   targets: 1,859 passed, 21 failed and 193 ignored, exit 101. Only 15 of 43
   integration targets run by default; the other 28 require features. Twelve
   HTTP failures came from sandbox socket denial and all 28 HTTP tests pass
   outside that sandbox. Eight library failures and one K-Elimination
   integration failure remain real gates. Preserve exact logs and positive
   matched counts; run required feature matrices separately.
3. On the accepted parent, run the focused depth oracle and the two expected
   red repeated-square tests from the October 5 runbook. Extend the depth dump
   only after the first failing boundary is specified. No auto-refresh claim
   follows from a counter or from zero-error synthetic keys.
4. For each completed card, save source SHA, toolchain, tuple fingerprint,
   checks, logs and hashes under a new execution ID. Review the diff and
   independent oracle, then update #92 with the exact pass/fail gate and next
   blocked dependency. A merge, a model statement or a zero-match test is not
   acceptance.
5. Analyze the three PR #165 fuzz failures from their uploaded artifacts and
   confirm them on a runner with enough build memory if local replay is needed.
   Repair bounded deserialization and investigate the encrypt/decrypt and
   homomorphic plaintext mismatches with independent integer oracles; retain
   failing assertions until fixed. The run now compiles all five targets; NTT
   completed 7,591 executions and K-Elimination completed 5,445,050 runs in
   61 seconds.
6. The local strict Clippy backlog is clear: the pinned-toolchain
   `--workspace --all-targets -- -D warnings` gate passes on the current
   working tree. The current-tree release matrix has reproduced the eight
   `nine65` library failures and the K-Elimination integration failure, with
   all other default targets passing. Preserve all red assertions. Publish
   this follow-up and rerun hosted CI so T1 passes and T2 executes on the exact
   SHA; preserve all T2 failures, then run the 28 feature-gated integration
   targets on the pinned toolchain.
7. Return to the ready dependency order: complete F00's independent review;
   finish F02 target and feature inventory; then execute F01/F02/F03/S00 and
   continue each wave only after its own gate and review. The depth-four
   repeated-square assertion, the prior eight library failures, one
   K-Elimination integration failure, three new fuzz failures, the 28
   unexecuted feature-gated targets, and the required hosted rerun remain
   visible blockers. The local Clippy pass does not accept F00 or F02.
8. Before release, run the complete serial `--no-fail-fast` matrix and hosted
   CI on the final SHA. Keep external lattice estimation, external audit, and
   required-check rulesets on the visible blocker list until evidenced.

The session will attempt every dependency-ready wave in order. A failed gate
halts its dependent branch; it does not authorize weakening tests, guessing a
cryptographic construction or marking the remaining cards complete.
