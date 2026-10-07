# F02 test inventory and failure triage — 2026-10-06 session

Status: **failed validation, not accepted**. Source under test was
`017f0163be76c0adb102e581c9e7157ea7ae736a` with pinned Rust 1.89.0.
The [machine inventory](../../../artifacts/execution/2026-10-06-session/F02/test_inventory.json)
and [raw release sweep](../../../artifacts/execution/2026-10-06-session/F02/release-sweep.log)
retain the exact discovery and test outputs. The sweep used
`cargo test --locked --offline --release --workspace --exclude nine65-python
--exclude nine65-wasm --no-fail-fast -j1` and exited **101**. Both named
exclusions are absent from the current workspace; Cargo warned but continued.

| Scope | Observed result | Meaning |
| --- | --- | --- |
| Metadata | 12 packages, 94 targets, 43 declared integration targets | Target declaration only; no compile/pass claim. |
| Default-feature release sweep | 59 result blocks: 33 unit/bin, 15 integration, 11 doctest | `--no-fail-fast` reached integration and doctests after library failures. |
| Assertions | 1,859 pass, 21 fail, 193 ignored | Three target binaries failed. The raw exit remains red. |
| Feature-gated integration | 28 declared targets did not run (27 `nine65`, one `nine65-extreme-tests`) | All 28 declare required features. A default workspace sweep is not the required feature matrix. |
| `fhe-service` HTTP group | 12 failures in the sandbox; all 28 HTTP tests pass outside it | The 12 failures panic at `TcpListener::bind` with `PermissionDenied`, so they are an execution-environment artifact for this run, not observed HTTP logic failures. The full service target remains red in the raw sweep. |
| `nine65 --lib` | 941 pass, 8 fail, 125 ignored | Real unresolved crypto/correctness gates; not reclassified by the HTTP rerun. |
| `k_elimination_basis_regression` | 3 pass, 1 fail | Constructor permits composite alpha `[15,17]`; test, public docs and CLASS-F field contract require prime alpha lanes. The pure CRT lift's composite-carrier use is separately valid. Resolve the API role boundary rather than deleting the negative test or blanket-rejecting composite target views. |

The eight library failures are three auto-refresh repeated-square configurations,
one auto-refresh bootstrap-count check, one bootstrap noise diagnostic, two GSO
depth benchmarks (`secure_128`, `secure_192`), and one zero-error GSO control.
The depth-four plaintext witness and fail-closed public refresh work remain
governed by #157/#158 and #95/#117/#16 respectively. A successful scalar
rescale oracle does not make the whole phase correct. The K-Elimination
source/target classification conflict belongs with S00/C06; the constructor's
current comment, its August composite-lane commit and the regression's CLASS-F
promise disagree. No source edit has been made to hide that disagreement.

The inventory retains every ignored test reason printed by libtest. These
reasons are evidence for review, not a blanket waiver. Resource classes remain
`unmeasured` until the feature targets and fixed workloads are profiled. The
separate ignored service functionality tests remain linked to the WIRE-Q outage.

The CRAM gate runner has been patched to use `--no-fail-fast` for its workspace
sweep and to run one filter per Cargo invocation with a positive-match check.
Its former `lock_witness` filter matched zero tests; the selected phase-lock
filters now cover default locks, tampering checks and the anchor inverse. A
targeted C0–C5 run passed with respective positive test counts 3, 15, 8, 16,
40 and 10. This is a **selected-gate** result; B/T gates were skipped. The
fast library runner also now continues across packages after a failing target.
The isolated T3 rerun was interrupted during a redundant release rebuild;
the original full sweep had already executed all 10 `cram_ct_wrap::tests`
successfully. T3's new positive-match wrapper remains unverified as a separate
command and is not counted as a pass here.

## CI discovered during remote publication

PR #163 started new hosted Actions on 2026-10-07 after a long run gap, so
Actions are currently able to start runners. CI is still red before its full
test job: `embark-studios/cargo-deny-action` cannot be resolved, the claim
registry script assumes `rg` is installed, and T2 is skipped after T1 failure.
Application-platform jobs also report pre-existing `cargo fmt` drift, a WASM
manifest that cannot inherit its workspace root, and `cargo clippy -p
fhe-service --lib --bins` asking for a library target that package lacks.
No ruleset currently requires the mechanical checks. #79 remains open until
actual current-head jobs execute and the required checks are enforced.

## Next F02 actions

1. Finish the T3 wrapper gate check and independently review the F02 runner
   patch and target inventory. The CI medium tier already uses
   `--no-fail-fast`; verify the hosted job executes after T1 is repaired.
2. Run the required feature-gated targets serially in resource classes. Keep
   unavailable/OOM/ignored/zero-match cases distinct from passes.
3. Isolate the first GSO fold/phase divergence or certified margin crossing,
   and keep all eight library assertions red until the relevant crypto route
   actually changes. Preserve the K-Elimination negative test until S00/C06
   resolves its CLASS-F versus composite-carrier API boundary.
4. After CI bootstraps, fix the deterministic workflow/tooling failures and
   run the same declared acceptance matrix on the actual PR head. Do not mark
   #79, #130, #137 or F02 complete from this default-feature sweep.
