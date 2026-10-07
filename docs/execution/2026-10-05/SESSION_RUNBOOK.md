# NINE65 v7: execution runbook after the depth-four audit

The [2026-10-06 session plan](../2026-10-06/SESSION_PLAN.md) records the latest
remote state, infrastructure blockers and complete dependency order. Use it
with this runbook's existing correctness gates.

Status: **active plan, not a release certificate**. This runbook orders the
existing [43 task packets](../2026-10-03/tasks.json) for the current session.
The packets retain their detailed scopes and acceptance rules; a merge, a model
answer, or a passing test filter with zero matches does not mark one accepted.
Use [the worker guide](../2026-10-03/WORKER_GUIDE.md) for isolated branches,
evidence and independent review. Recheck remote `main` and issue state before
each merge because other agents may land work concurrently.

## What is actually established

* PRs [#154](https://github.com/Skyelabz210/NINE65_v7/pull/154) and
  [#155](https://github.com/Skyelabz210/NINE65_v7/pull/155) merged a fail-closed
  bootstrap candidate ledger and current parameter evidence. No public
  bootstrap tuple is admitted; R03 remains `blocked_design`.
* PR [#160](https://github.com/Skyelabz210/NINE65_v7/pull/160) fixed a
  demonstrated canonical-phase error in scalar dual-RNS rescale. PR
  [#161](https://github.com/Skyelabz210/NINE65_v7/pull/161) added bounded
  adjacent-winding checks. Neither proves arbitrary signed magnitude or FHE
  depth.
* PR [#156](https://github.com/Skyelabz210/NINE65_v7/pull/156) merged the
  plaintext assertions **while they fail at depth four**. Its historical
  50-operation counter is not a correctness result. The new
  [coefficient audit](../../../artifacts/execution/2026-10-04-depth-gate/coefficient-audit-128.json)
  and [matrix](../../DEPTH_CORRECTNESS_MATRIX.md) are the current diagnostic
  evidence. On the deterministic zero-fresh-error `secure_128` witness,
  component rescale agrees with an independent exact `round(X/Delta)` oracle
  for all 16,384 coefficients at the failing step. The whole phase is already
  outside the correct-decode margin; 8,000 nonconstant coefficients exceed
  `Delta/8`. Substituting exact `round(tX/Q)` only at that step still gives
  plaintext 65532 instead of 65536. Earlier fold/phase behavior and the lack
  of real refresh remain to be separated.
* [#159](https://github.com/Skyelabz210/NINE65_v7/issues/159) records a
  separate Recumbent S8 carry loss and saturating parking defect. It is not
  wired to this GSO depth path. Lane 2 can carry parity or a separately
  specified phase-locked view; its residue alone cannot certify global sign
  (`+1` and `-1` both reduce to 1 modulo 2).

## Run order and pass/fail gates

Each row is a bounded patch or evidence packet. Work on independent files may
run in parallel, but the downstream gate must wait for its listed inputs.
Keep each red test red until the actual ciphertext/plaintext behavior changes.

| Order | Packet / issue | Execute next | Gate to advance |
| --- | --- | --- | --- |
| 0 | F00, F02, V03; [#79](https://github.com/Skyelabz210/NINE65_v7/issues/79), [#130](https://github.com/Skyelabz210/NINE65_v7/issues/130), [#137](https://github.com/Skyelabz210/NINE65_v7/issues/137) | Pin the fetched commit and toolchain; inventory all lib/integration/feature targets; restore active CI and a serial `--no-fail-fast` acceptance command. | Every required target executes or is explicitly unavailable; current failures remain visible. CI must execute on the actual PR head, not merely have workflow files. |
| 1 | F01 depth follow-up; [#157](https://github.com/Skyelabz210/NINE65_v7/issues/157), [#158](https://github.com/Skyelabz210/NINE65_v7/issues/158) | Extend the ignored, deterministic zero-error diagnostic to export **each** depth's pre-rescale `d0,d1,d2`, post-rescale components, relinearization/fold outputs, secret evaluation and full polynomial phase. Add an independent arbitrary-integer/negacyclic oracle at every boundary. Identify the first incorrect phase identity or first certified noise-margin crossing. | All 8,192 coefficients and both components agree with their stated mathematical operation at each earlier stage, or the first mismatch is localized with a minimal fixture. The depth-four plaintext tests remain asserting their expected values. A wrong checked decrypt must return an explicit insufficient-margin/error result rather than certify plaintext. |
| 2 | C00, C01, C02, C06, R00; [FPD contract](../2026-10-03/FPD_BFV_RESCALE_CONTRACT.md) | Compare the live symmetric/public routes with the remainder-adjusted FPD `ExactScaleRound` contract. Use coherent pre-multiply main/auxiliary tensors; derive bounds including summed `d1`, key-switch error and every floor term. Bind input provenance and choose a mathematically justified repair only after row 1. | Signed/nondivisible and rounding-boundary oracles agree, capacity/coherence failures are typed, no Garner or full-coefficient reconstruction enters public hot paths, and `secure_128`/`secure_192` per-step plaintext gates pass to their **claimed** finite depth or refuse the next operation before wrong plaintext. Do not substitute a constant `+1` patch or metadata collapse for refresh. |
| 3 | S00-S05, [#159](https://github.com/Skyelabz210/NINE65_v7/issues/159), [#29](https://github.com/Skyelabz210/NINE65_v7/issues/29) | Freeze the live S8 root/2-11 phase relation, on-demand bounded K, signed adapter and sister-tray operator assignment. Repair Recumbent carry and saturating parking by a capacity-checked phase-locked representation; test adjacency alias boundaries and composite shared-factor views. Integrate the preserved root into actual public execution. | Exact oracle agreement at every admitted boundary; `M-1+1` and capacity-alias cases refuse or promote without loss; no carried winding state, Garner/MRS hot path or standalone mod-2 sign claim. A sister-tray inverse is used only on unit-domain lanes. |
| 4 | R01-R03, V00, [#95](https://github.com/Skyelabz210/NINE65_v7/issues/95), [#117](https://github.com/Skyelabz210/NINE65_v7/issues/117) | Derive live bounded-digit input radius and compile the encrypted digit-removal DAG with nodewise arithmetic/noise/key-domain bounds. Search current and wider exact tuples; review all key distributions and evaluation-key relationships. Only then implement B00-B09: transforms, public keys, encrypted digit removal, contraction, return key, automatic admission and repeated refresh. | At least one exact tuple passes every capacity, noise and security inequality **before** expensive keygen; every coefficient survives refresh, a multiply and another refresh. Existing corrupting componentwise Phase 1 stays refused. No secret-dependent value is published to satisfy a local proof. |
| 5 | C03-C05, V01-V05, H00-H04 | Land a validated main-Q wire, certified service route and Python surface. Characterize actual shadow-source entropy conditioned on the attacker view; freeze Three Locks key/mask lifecycle and physical interruption model; test interruption at each transition. Close constant-time, serialization, CI, parameter and external-review gates. | Release inventory links source, tests, formal statements and measured workloads to one commit. No claim of post-quantum or physical-interruption immunity exceeds the tested deployment profile. External lattice estimation and security review remain explicit gates, not model attestations. |

Row 0 can proceed beside the row 1 diagnostic. Rows 2 and 3 may advance on
disjoint source scopes after their contracts are frozen, but S05 and R03 depend
on both. Row 5's wire skeleton may be developed before bootstrap; a released
auto-refresh claim waits for row 4. The task graph gives the finer dependencies
and ownership; do not silently accept all 43 packets because these rows exist.

## Immediate commands and evidence

From the repository root, run the plan validator and the focused present-code
checks before changing arithmetic. Use `CARGO_TARGET_DIR` on a filesystem with
space. The benchmark tests below are expected to fail today and are retained
as regression gates, not treated as a successful command group.

```sh
python3 scripts/nine65_execution_plan.py validate --self-test
python3 scripts/nine65_execution_plan.py ready
cargo test --locked --offline -p nine65 --lib k_elim_rescale_large_winding_oracle_and_output_phase -- --nocapture
cargo test --locked --offline -p nine65 --lib benchmark_symmetric_max_depth_secure_128 -- --nocapture
cargo test --locked --offline -p nine65 --lib benchmark_symmetric_max_depth_secure_192 -- --nocapture
```

The diagnostic exporter is intentionally ignored in routine suites. Run it
only in the isolated audit branch, then compare its `/tmp` dump with
`scripts/analyze_depth4_residue_pairs.py`; preserve exit codes, source commit,
logs, summary hashes and the count of matched tests. Do not commit the raw
synthetic-key dump. Run the arrow/emission suite after any CRAM transduction or
carry edit, and the target-specific FHE suites after any BFV arithmetic edit.
Finally run the resource-checked full `--no-fail-fast` suite and required CI on
the integrated head. A test command that found zero cases supplies no evidence.

The coordinator updates [#92](https://github.com/Skyelabz210/NINE65_v7/issues/92)
after each accepted patch with the exact passing/failing gate and next blocked
dependency. No issue closes solely because code was merged or another model
reported success.

### This checkout's first execution result

`python3 scripts/nine65_execution_plan.py validate --self-test` passed 12
self-tests and validated the 43-card graph; it reported expected drift from the
historical baseline. The source, analyzer and audit-summary hashes still match
the recorded coefficient-audit evidence. A fresh run of the focused
`k_elim_rescale_large_winding_oracle_and_output_phase` Rust test stopped during
`rustc` linking with `No space left on device` (exit 101) before executing any
test. At that point `/home/acid` had about 784 MiB free and the workspace
`target` occupied about 1.4 GiB. This is `blocked_infrastructure` for a new
build, not a newly observed arithmetic failure or a passing test. Preserve the
earlier source-bound successful run and make build space available before
claiming a fresh-head test result.
