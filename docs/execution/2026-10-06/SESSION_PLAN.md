# NINE65 v7: current remote plan and session execution order

Updated 2026-10-07 after PR #168 merged as `c93a058`. This is the
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

1. Record T2 run 37673287983 for merged PR #167 as failed, and PR #168 run
   37676097379 as complete with 856 passed, 94 failed, 125 ignored. The new
   arithmetic differential test fails at dividend 2, modulus 2, confirming
   the partial-mask bug in the tested prototype. Merge-ref T2 run
   37676889216 is complete: 856 passed, 94 failed, and 125 ignored. Its
   arithmetic differential test fails at dividend 2/modulus 2, and the
   separate `class_f_alpha_lanes_must_be_prime_and_distinct` regression also
   fails. Verify the one-bit widening fix on PR #169 before accepting any
   dependent arithmetic result.
2. Let the already-running 27-target `allow_insecure` debug matrix finish in
   `/home/acid/Projects/NINE65_v7`; save the complete log and exit status.
   Then run `nine65-extreme-tests/full_system_measurement` serially and record
   it as a separate gate. Do not start a competing local Cargo build while
   this matrix is consuming the host.
3. Continue on `codex/2026-10-07-ct-regression-followup`, based on the new
   merge commit. PR #168 was merged by the repository owner at
   `c93a058e2106441029647e69e252d3b410fdeab1` while T2 and correctness gates
   were unresolved. Its isolated reducer and full `mod_switch_down_dual`
   timing contrasts were below threshold, but those measurements came from an
   incorrect selector mask and do not validate the fix. Two CRAM-public
   multiply tests that passed on merged `0f85873` fail on the changed head.
   Source review found that the code widened a 64-bit all-ones selector and
   then negated it in `u128`, producing a partial mask. Draft PR
   [#169](https://github.com/Skyelabz210/NINE65_v7/pull/169), head
   `84ce6da2a18faa2c63a55fa7d662aff670fbe472`, expands the one-bit condition
   directly at 128-bit width. Its T1 Fast Gate is running; static analysis
   and T3 pass, while T2, CT, CRAM, architecture and fuzz checks are pending.
   Keep this fix unaccepted until the arithmetic differential test, T2, CT
   rerun, and CRAM tests pass. Do not merge further changes through these
   failures.
4. Triage the current fuzz failures independently: a five-byte deserialize
   allocation, the encrypt/decrypt result 65,292 → 65,289, and homomorphic
   scalar multiplication 512 × 65,404 → 61,587 (expected 62,978). Preserve
   the earlier homomorphic-addition witness 65,331 + 0 → 65,328 as a
   separate case. Add minimal regressions for demonstrated defects; keep
   assertions intact and retain original/minimized corpora and logs. Rerun all
   five fuzz targets; NTT and K-Elimination must remain passing.
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

### Historical initial PR #168 check snapshot

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

### PR #168 merged checkpoint `c93a058`

PR #168 was merged by the repository owner at
`c93a058e2106441029647e69e252d3b410fdeab1` at 2026-10-07 19:45:24 UTC. The
tested PR head was `904448a73fb17427a7d05bde16e2d74c6b74e4d0`.

On that head, T1 Fast Gate, static analysis, T3, CT source/functional, and
application platform pass. T2 run 37676097379 completed with 856 passed, 94
failed, and 125 ignored. The new arithmetic differential test fails for
dividend 2 and modulus 2, confirming the partial-mask bug in that tested
prototype; the full failure list is retained in `t2-workspace.log`.

CT run 37676097485 has a below-threshold isolated reducer score
(`t_control=1.1190`, `t_signal=0.1719`) and full-path score
(`t_control=0.0504`, `t_signal=1.0673`), but its overall job fails a separate
`AdjacencyKElim::extract_k` contrast (`t_control=4.0863`, `t_signal=6.3291`).
Merge-ref CT run 37676889107 passes its statistical tests, including the
reducer (signal 1.1272), full path (signal 1.2671), and adjacency contrast
(signal 3.6537). Both sets used the incorrect arithmetic prototype, so neither
set validates the fix. CRAM-public run 37676097325 fails two multiply tests
with gadget-capacity errors, despite both passing on merged `0f85873`. The
mask-width cause is fixed on branch `codex/2026-10-07-ct-regression-followup`;
the arithmetic differential test, T2, CT rerun, and CRAM tests on that repair
still need hosted validation.

Fuzz run 37676097295 reproduces the short-input deserialize allocation and
encryption round-trip mismatch. Its homomorphic case passes addition and
subtraction but fails scalar multiplication (`512 * 65,404` returns `61,587`,
expected `62,978`). NTT and K-Elimination pass. Exact CRAM and exact Dual-RNS
checks fail the recorded source-bound architecture findings. Raw logs and
corpora for this head are retained under
[`pr168-904448a`](../../../artifacts/execution/2026-10-07-session/CI/pr168-904448a/).

The merge-ref CI run 37676889216 has T1 Fast Gate and static analysis passing;
T2 completes with 856 passed, 94 failed, and 125 ignored. Its arithmetic
differential test fails at dividend 2/modulus 2, and the separate
`class_f_alpha_lanes_must_be_prime_and_distinct` regression fails. The complete
failed-job log is retained under `pr168-merge-c93a/ci/`. Merge-ref CT run
37676889107 passed its timing tests, but
those scores use the incorrect arithmetic prototype and are not accepted.
Fuzz Smoke run 37676889257 fails on a five-byte deserialization allocation,
encrypt/decrypt 15,110 → 15,109, and addition 0 + 35,073 → 35,071. CRAM-public
run 37676889200 repeats the two gadget-capacity failures. Scale run
37676889143 and comparative run 37676889066 both stop at DualRNS multiplication
because exact values need 254–256 bits while the evaluation key spans 96–128
bits. Residue-native run 37676889104 fails its existing `garner_reconstruct_subset`
source gate; exact CRAM and exact Dual-RNS retain their source-bound failures.
Audit remediation run 37676889186 and exploratory run 37676889127 also fail.
These results are saved under `pr168-merge-c93a/`.

The partial-mask cause is now concrete: `select_mask_ct` subtracted a widened
`u64::MAX` from zero in `u128`, which is not a 128-bit all-ones mask. PR #169
head `84ce6da2a18faa2c63a55fa7d662aff670fbe472` expands the one-bit selector
after conversion to `u128`. Its T1, application-platform, CT source/functional,
and CRAM-public correctness/timing checks pass. The arithmetic differential
and rest of T2 are still running. The full-path CT timing contrast fails at
`t_signal=18.2519` with control `0.9809`, although the isolated reducer
contrast passes once at `2.9168`; this head does not close the end-to-end CT
finding.

### PR #169 first correction checkpoint (`84ce6da`, historical)

Draft [PR #169](https://github.com/Skyelabz210/NINE65_v7/pull/169) is based on
merge commit `c93a058` and remote head
`84ce6da2a18faa2c63a55fa7d662aff670fbe472`. T1 Fast Gate, static analysis,
T3, application platform, CT source/functional, and CRAM-public correctness
and timings pass. CRAM-public correctness reports 5/5 M1, 7/7 M2b/M3, 4/4
API guardrails, 2/2 in-module guards, 3/3 M3 correctness, 3/3 Arrow witnesses,
and 24/24 unified-rescale tests passing. T2 run 37678425778, job
112988404676, is still running.

The CT statistical run 37678425725 fails the full all-zero-vs-uniform
`mod_switch_down_dual` contrast (`t_control=0.9809`, `t_signal=18.2519`,
medians 134.46 ms and 134.64 ms). The isolated reducer contrast passes once
(`t_signal=2.9168`); the magnitude-matched sign contrast passes once
(`t_signal=0.5676`). Fuzz run 37678425578 still fails deserialize, encrypt/decrypt,
and homomorphic targets; NTT and K-Elimination pass. Exact CRAM run 37678425652
and exact Dual-RNS run 37678425775 fail their existing source-bound checks.
Scale quick run 37679066010 passes both configurations through depth 2/2.
Comparative smoke run 37679073764 passes v7 correctness through depth 2/2;
the v6 same-machine portion is skipped because the required repository secret
is absent, so no v6/v7 performance result exists. Logs, manifests, and fuzz
reproducers are retained under `pr169-84ce6da/`.

Source review of the full-path signal found additional coefficient-derived
branches and variable-latency reductions in centering, rounding, signed lane
encoding, and residue normalization. Commits `48ef562` and `c1a502c` implement
the fixed-work follow-up and preserve existing `SignedU256::is_neg` callers.
The next checkpoint records validation of that code.

### Current checkpoint: `c1a502c` (2026-10-07)

The user requested committing and pushing the session work to `main`.
The code SHA validated here is
`c1a502cafaa90aeeb53b90e9df2c18097c42dab7`; the publication commit adds this
checkpoint and raw evidence without changing the tested Rust code.

T1 static analysis, formatting, Clippy, dependency checks, application platform,
and CT source/functional gates pass. CRAM-public run 37680342717 is complete:
48 correctness tests and 2 informational timing tests pass. Quick scale run
37680831309 passes both configurations through required depth 2/2. Comparative
v7 smoke run 37680837528 also passes depth 2/2; its v6 comparison is skipped
because `NINE65_CROSS_REPO_TOKEN` is absent. These short runs establish
correctness for their inputs, not a performance baseline.

Blocking CT run 37680342677 is green. The isolated reducer reports control
`0.0954` and signal `1.7807`; full zero-vs-uniform modulus switching reports
control `0.9485` and signal `0.0290`; magnitude-matched signs report control
`0.5590` and signal `0.1890`. These are single-run measurements. Adjacency
K-Elimination magnitude is inconclusive because control `34.2862` exceeds the
threshold; keep that independent finding open. CI T2 run 37680342663 remains
in progress at this checkpoint.

Fuzz run 37680342693 reproduces deserialize allocation failure and exact-output
mismatches in encrypt/decrypt and homomorphic operations; NTT and K-Elimination
fuzz pass. Real Refresh run 37680342700 reaches the secure RNG guard before
refresh because its release benchmark supplies the test Shadow RNG. The
exact-noise, CRAM recumbency, and residue-native architecture gates remain red.
Raw reports, crash inputs and hashes are archived in
`artifacts/execution/2026-10-07-session/CI/pr169-c1a502c/`.

The passing float scans have explicit scope exclusions. CT statistics use
`f64` for means, variances and square-root standard error; compiler estimates
and benchmark reporting also retain floats. GitHub issue #90 is closed, but
#92 Phase 5 still requires an all-owned-source gate. Reconcile those exclusions
with that requirement before accepting the parent checklist item.

Next, collect T2 and repeat the relevant CT measurements with clean controls;
repair the three fuzz defects and the secure-RNG refresh harness; then resolve
the architecture findings in the dependency order below. Let the serial local
27-target feature matrix finish before running
`nine65-extreme-tests/full_system_measurement`. Publishing to `main` does not
accept any still-failing or pending card.

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

### CRAM transduction follow-up (2026-10-08)

PR #171 merged the first correction from the PR #170 review: the slice and
provider lifted APIs now use the typed fallible transduction builder. The
follow-up on this branch closes the remaining invalid-target panic, restores
the generated-artifact ignore rules, fixes modular normalization at the
`i128::MAX` boundary, and records the result of the previous anti-Garner test
being unable to detect a correct scalar Garner replacement. A deliberate
mutation now fails the new named-Garner call-counter test. The S6/S8 output
oracle passes; scalar rank aggregation is still an explicit architecture gap.
Focused results, commands, failure scope, and ordered next work are in
[`CRAM transduction follow-up`](../../../artifacts/execution/2026-10-08/CRAM/transduction-followup/README.md).

Do not treat that focused crate run as full Cargo workspace acceptance. PR
#173's draft addition fixes the S8 boundary example by reconstructing both
operands and re-encoding their sum, as explicitly acknowledged in its body.
That does not implement issue #159's required phase witness. Keep the
carry/recumbency architecture card open until the witness contract is proved
or the operations fail closed under the admitted interface. The local debug
feature-matrix log stops before a final target/exit summary; preserve it as an
incomplete run, then repeat that matrix before advancing F02.
