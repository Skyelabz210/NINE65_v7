# NINE65 v7: current remote plan and session execution order

Updated 2026-10-07 after PR #167 merged as `25e19ee`. This is the
live-session control sheet for the 43 cards in
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
Full details and links are in the [#92 hosted checkpoint](https://github.com/Skyelabz210/NINE65_v7/issues/92#issuecomment-6044369172).

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

PR #166 subsequently merged at `f3bde560644fd079526719fb2231d7b194f5060d`.
The post-merge harness changes are on draft PR #167. Its first hosted rerun
passes the CT source/inventory job and completes the exact NTT candidate probe
(one compatible candidate passes; three invalid candidates are rejected). The
quick FHE matrix still has four missing result files because the release probe
uses seeded `ShadowHarvester` and correctly trips the release security guard.
The next PR #167 update runs that test-entropy probe in debug mode and records
its build profile, keeping those measurements distinct from release evidence.
That rerun also found the removed `licenses.unlicensed` cargo-deny key; commit
`cb6b4a9` removes it. On `cb6b4a9`, CRAM-public gates and application-platform
gates pass, while CI, the seeded exploratory matrix, CT verification, and three
fuzz targets fail. CI now parses `deny.toml` but reports the real dependency
policy findings: `rand 0.8.5` (`RUSTSEC-2026-0097`),
`crossbeam-epoch 0.9.18` (`RUSTSEC-2026-0204`), unmaintained `bincode`
(`RUSTSEC-2025-0141`), and the missing `BSD-3-Clause` allowance for `subtle`.
The follow-up lockfile updates rand to 0.8.8 and crossbeam-epoch to 0.9.21,
allows the detected BSD-3-Clause license, and gives a reasoned exception for
the bincode unmaintained advisory while a versioned codec migration and
compatibility fixtures are planned. The cargo-deny action's current config
schema accepts only the advisory ID and reason, so this exception cannot be
restricted mechanically by dependent crate. The current workspace graph has
two direct users (`fhe-service` and `nine65`); re-review the graph before
adding consumers, and keep all other advisories fail-closed. The attempted
dependent-scope field was rejected by hosted cargo-deny and is removed.

The latest CT dudect run identifies a real timing signal in
`mod_switch_down_dual` when comparing all-zero with uniform coefficients:
`t_control=0.5894`, `t_signal=91.7987` against threshold 5, with medians
85,774,551 ns and 86,839,093 ns. The same-class control is below threshold,
so the result tracks the input class. Keep this gate red until the
data-dependent behavior is removed or independently justified; do not lower
the threshold. The full hosted measurement is in
[`dudect_blocking_output.txt`](../../../artifacts/execution/2026-10-07-session/CI/pr167-ct-37668430997/ct-dudect-blocking/dudect_blocking_output.txt).
Source review found a plausible cause along the timed path: `to_u256_level`
calls `crt_reconstruct_u256`, whose `U512::mod_u256` reduction loop branches on
`rem.ge(m_512)` for each input-derived remainder. Isolate and test that path
before claiming it is the measured cause; the full-operation dudect result
does not by itself attribute the signal to one branch.
The matrix fix selects a debug-profile seeded FHE probe and writes its build
profile into case metadata and comparison compatibility. The NTT candidate
probe remains a separate release build. Debug timings stay informational.
The hosted v6/v7 comparative smoke also exposed a release build with
`allow_insecure`; update that deterministic harness to run both comparison
sides in debug and record the profile consistently before resuming its smoke.

The local `allow_insecure` run is executing the 27 `nine65` integration
targets after an 11m02s serial compile. Its first target,
`anchor_drift_diagnostics`, passed 3/3 tests in 420.61s. The second target,
`arrow_emission_fhe_gate_matrix`, is active; G1 winding and early G2 checks
passed, including depth-1 decrypt/noise-margin. A G3 test is active. The one
`nine65-extreme-tests` target remains queued. Preserve the
full log and record the exact source SHA, toolchain, target count and exit
status when the run finishes.

### Historical checkpoint: PR #167 head `13306310547ef96e8737365a8ffab1f8a74d385d`

This run snapshot is superseded by the merged checkpoint below. The fixes it
describes were subsequently committed, hosted, and merged; its then-current
follow-up instructions are historical.

Hosted run set 37671711811–37671712033 confirms these passing gates: T1 Static
Analysis, T3 review, exploratory `probe-smoke` and `source-inventory`, CT
source/functional tests, NTT and K-Elimination fuzz targets, WASM boundary,
authenticated service boundary, private-feedback stack, mode/claim policy,
and CRAM-public correctness. CRAM-public debug timings are still running as
an informational job. The failed gates
are T1 Fast Gate (cargo-deny licenses rejects the first-party
`LicenseRef-Proprietary-AllRightsReserved` declaration), scale sweep
`quick-correctness` (builds the seeded probe with forbidden release
`allow_insecure`), and comparative smoke (the expected legacy `mul_ct`
refusal is counted as an ordinary failed correctness assertion). CT dudect
remains blocking-red. Three fuzz targets remain red with preserved
reproducers: deserialize requests a 37.95 GiB allocation from a six-byte
input; encrypt/decrypt decrypts 65,536 as 65,533; homomorphic addition returns
65,289 for 65,292 + 0. NTT and K-Elimination fuzz targets pass. The complete
check list is on [PR #167](https://github.com/Skyelabz210/NINE65_v7/pull/167).

That follow-up added only the exact custom license identifier already
declared by first-party manifests; moves both scale-sweep builds and its
runner to debug while recording `build_profile`; and makes the comparative
smoke accept only the exact `mul_ct=false` plus `mul_ct_status="refused-#135"`
pair while keeping that refusal visible. Local Python regression, syntax,
TOML parse, formatting and whitespace checks pass; cargo-deny is unavailable
on this host. The follow-up was later committed, pushed, and merged; inspect
the merged and current hosted results in the checkpoints below.
Require T1 Fast Gate and T2 to execute and pass before treating the CI
foundation as complete. Keep the dudect and three fuzz regressions open;
do not change timing thresholds or correctness assertions. Finish the local
27-target debug matrix, then run the separate
`nine65-extreme-tests/full_system_measurement` target and retain both results.

After those independent gates, resume the 43-card DAG below in earliest-ready
waves. In particular, keep the F02 release failures, fuzz/security gates and
architecture prerequisites visible; do not accept F00/F02, claim production
security or performance, or advance dependent cards while their own gates are
red. The bincode exception remains advisory-ID-and-reason only under the
current cargo-deny schema; re-review its two direct consumers before adding
any consumer and replace the deployed format only through a versioned codec
migration with compatibility fixtures.

### Historical checkpoint: follow-up head `57af1de6a08803f8893f23f00f446a1728d8e69b`

This code head and its “still running” statuses are preserved as a run record;
the evidence-only head and merged checkpoint below supersede them.

The hosted rerun set is CI 37672722326, Fuzz Smoke 37672722486, CT
verification 37672722432, CRAM-public 37672722228, application platform
37672722576, exploratory matrix 37672722294, v7 scale sweep 37672722502,
and comparative harness 37672722619. T1 Fast Gate (including cargo-deny),
static analysis, T3 review, both seeded smoke jobs, application platform,
and exploratory probe/source inventory pass. The scale sweep passes both
cases with complete depth and zero operation failures. The comparative probe
passes while preserving legacy `mul_ct=false` and `refused-#135` in its JSON.
The full T2 workspace suite is now running because T1 passed.

Fuzz Smoke has three reproduced failures again: a six-byte deserialize input,
a 16-byte encrypt/decrypt input, and a 33-byte homomorphic input. Their raw
corpus files are retained under
[`pr167-57af1de/fuzz`](../../../artifacts/execution/2026-10-07-session/CI/pr167-57af1de/fuzz/);
NTT and K-Elimination fuzz targets pass. CT source and functional gates pass;
the blocking dudect measurement is still running. CRAM-public correctness is
also still running after its mode, rescale, relin, and tripwire tests passed.
Retain the raw timing artifact when the CT job finishes and record exact
CRAM-public outcome before changing the gate plan. Comparative and scale
outputs, the scale manifest, CT source report, and all three fuzz inputs are
saved under
[`pr167-57af1de`](../../../artifacts/execution/2026-10-07-session/CI/pr167-57af1de/).

At that snapshot, the next actions were to collect T2, CT dudect, and CRAM-public completion;
read the full fuzz regressions and keep them open; finish the local 27-target
debug matrix and then run the separate extreme target. Do not merge or accept
F00/F02 while these gates or the existing release correctness failures remain
red. Isolate the measured CT path before attributing the previously observed
signal to a specific operation.

### Merged checkpoint `0f85873` / merge commit `25e19ee`

PR #167 was merged by the repository owner at
`25e19eeffc82ef3a84d77d76c50e5fc9eb9a026f` at 2026-10-07 19:27 UTC. Its
configuration fixes are confirmed: cargo-deny/T1, static analysis, T3,
comparative smoke, both scale quick cases, application platform, exploratory
checks, and CRAM-public correctness and timings pass. T2 workspace tests are
still running in CI run 37673287983, job 112970736953.

The remaining hosted failures reproduce on `0f85873`. Dudect reports
`mod_switch_down_dual` all-zero versus uniform at `t_control=0.8098`,
`t_signal=49.4668` (threshold 5), with medians 64,466,796 ns and 66,017,183
ns. Fuzz Smoke again fails deserialize, encrypt/decrypt, and homomorphic
addition; its eight-byte deserialize input requests 95.72 GiB, encryption
roundtrip returns 65,289 for plaintext 65,292, and addition returns 65,328
for 65,331 + 0. NTT and K-Elimination fuzz targets pass. Raw outputs are
retained under
[`pr167-0f85873`](../../../artifacts/execution/2026-10-07-session/CI/pr167-0f85873/).

Source review found a plausible CT contributor in `U512::mod_u256`, called by
CRT reconstruction: it branches on dividend bits and remainder comparisons.
The new follow-up branch, based on merged `main`, has an unvalidated prototype
that uses a fixed eight-word borrow chain and mask selection, adds differential
arithmetic coverage, and measures the reducer directly inside the existing
blocking dudect test. This is a hypothesis test, not an attribution yet. If
the isolated reducer passes but the full path remains red, inspect the other
input-derived operations in CRT reconstruction and modulus switching before
claiming a fix.

The local feature-gated matrix remains active on
`arrow_emission_fhe_gate_matrix`; `anchor_drift_diagnostics` passed 3/3 in
420.61s, and G1 plus early G2 assertions passed in the second target. Finish
all 27 targets, then run the separate
`nine65-extreme-tests/full_system_measurement` target. Next collect T2's final
result, validate the reducer prototype and end-to-end dudect path, triage the
three current fuzz inputs, preserve each new artifact set, and continue only
through dependency-ready cards with their own evidence and review.

### Next and following execution order for this session

1. Collect the final T2 result for run 37673287983. Keep the workspace gate
   open until its job completes and record any failures against the exact
   merged SHA.
2. Let the already-running 27-target `allow_insecure` debug matrix finish in
   `/home/acid/Projects/NINE65_v7`; save the complete log and exit status.
   Then run `nine65-extreme-tests/full_system_measurement` serially and record
   it as a separate gate. Do not start a competing local Cargo build while
   this matrix is consuming the host.
3. On `codex/2026-10-07-ct-fuzz-followup`, finish the CT reducer hypothesis.
   Draft PR #168 is open at `c61edecedda489039868f3082abb70fd779273fb`;
   source and documentation formatting checks passed before publication.
   Collect hosted T1/T2 plus the blocking isolated-reducer and full-path
   dudect measurements. Keep the timing gate red unless both required
   contrasts pass with clean controls; if the isolated reducer passes but the
   full path fails, inspect the remaining CRT and modulus-switch operations.
4. Triage the three merged-head fuzz reproducers independently: the
   short-input deserialize allocation, encrypt/decrypt roundtrip mismatch,
   and homomorphic-addition mismatch. Add a minimal regression for each
   demonstrated defect, fix only with an exact correctness-preserving change,
   and retain the original and minimized corpus plus hosted logs. Rerun all
   five fuzz targets; the two passing targets must remain passing.
5. Update issue #92 and the session record with final T2, matrix, extreme,
   CT, and fuzz evidence. Keep the merged PR status and follow-up PR linked;
   do not treat a green configuration gate as acceptance of F00/F02 or as
   evidence that the release correctness defects are resolved.
6. Resume the 43-card DAG in the dependency order below, completing every
   independent card in the earliest ready wave with its specified evidence
   and independent review. F00 needs its independent baseline review; F02
   needs its failing release assertions resolved and its complete matrices
   executed. Leave each dependent wave queued until its prerequisites pass.
   Continue through Waves 0–19 only while those per-card gates pass, then
   reconcile V05 on one final SHA. A session stop or failed gate records the
   exact next card and blocker; it does not waive the acceptance criteria.

### Follow-up PR #168 checkpoint

Draft PR [#168](https://github.com/Skyelabz210/NINE65_v7/pull/168) is based on
merged main and carries commit `c61edecedda489039868f3082abb70fd779273fb`.
Its first hosted check set is running: CI run 37675698603, CT run
37675698599, Fuzz Smoke run 37675698606, CRAM-public run 37675698506,
application platform run 37675698466, exact CRAM run 37675698618, and exact
Dual-RNS run 37675698455. At the last check, all unscheduled checks were
pending; T2 had not started because the T1 Fast Gate was still pending. The
separate T2 run on merged PR #167, 37673287983, also remains in progress.
This PR's reducer and arithmetic test are still uncompiled and unmeasured
locally; hosted results are the validation gate. Its fuzz jobs are evidence
replays only, and all three regressions remain open.

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
9. Finish the active 27-target debug feature matrix and separately run the
   `nine65-extreme-tests` target. Save source SHA, exact command, full log,
   target/test counts and exit status. Treat debug entropy timings as
   functional evidence only, never as optimized performance evidence.
10. Replace the deployed bincode 1/2 formats through a versioned codec
    migration with golden compatibility fixtures before expanding serialized
    key/ciphertext formats. Keep the reasoned `RUSTSEC-2025-0141` exception
    limited to that advisory, and re-review dependency consumers until the
    current cargo-deny action supports a narrower dependent scope.
11. After the current harness/dependency follow-up is pushed, confirm the
    cargo-deny policy and debug seeded matrix in hosted CI, require T2 to run,
    then preserve and triage every remaining fuzz, CT, arithmetic and explicit
    refusal failure on the exact head SHA. Do not merge while required gates
    are red or skipped.
12. On the latest Fuzz Smoke run, `fuzz_deserialize` requests a 37.95 GiB
    allocation from the six-byte input `/N/fMWUA`; `fuzz_encrypt_decrypt`
    decrypts 65,536 as 65,533 for seed 0; and `fuzz_homomorphic` reports
    `65,292 + 0 = 65,289`. These are separate malformed-input and exactness
    gates. Reproduce each saved corpus input and repair the decoder bound or
    arithmetic path with an independent oracle. Preserve the downloaded raw
    inputs under
    [`pr167-fuzz-37668431023`](../../../artifacts/execution/2026-10-07-session/CI/pr167-fuzz-37668431023/).

The session will attempt every dependency-ready wave in order. A failed gate
halts its dependent branch; it does not authorize weakening tests, guessing a
cryptographic construction or marking the remaining cards complete.
