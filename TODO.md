# NINE65 execution TODO

Updated 2026-10-13 from the repository review. This checklist follows the
[session plan](docs/execution/2026-10-06/SESSION_PLAN.md) and the
[43 task contracts](docs/execution/2026-10-03/tasks.json).
Complete each card's evidence, checks, and required review before advancing
its dependents. A checked navigation step does not accept a task card.

## Product target

Deliver exact computation on encrypted data through the intended CRAM
architecture, followed by automatic public refresh without evaluator-side
decryption secrets. Three Locks is a separate physical-protection milestone.

| Milestone | Current evidence |
| --- | --- |
| Exact CRAM core | Component repairs and passing checks exist; preserved-root and phase/parking integration remain incomplete. |
| Useful encrypted evaluator | Operations and service boundaries exist; depth, decode, architecture, and fuzz acceptance gates remain open. |
| Native public auto-refresh | Complete tuple admission, encrypted construction, and repeated refresh correctness remain outstanding. |
| Three Locks profile | Source characterization, key/mask lifecycle, interruption experiments, and independent security evidence remain outstanding. |

The next bounded correctness deliverable is to reproduce one failing encrypted
arithmetic case on current main, locate its first oracle divergence, and repair
it or enforce the supported boundary with a typed refusal. Execute this within
the task cards' prerequisite and review requirements below.

## Completed preparation

- [x] Locate the live session plan and `scripts/nine65_execution_plan.py`.
- [x] Fetch `origin/main`: observed commit `a51f641`.
- [x] Identify the existing workspace changes: 139 artifact deletions and a
  `.gitignore` modification.
- [x] Create a clean detached worktree at
  `/tmp/nine65-main-review-20261013` for inspecting current main.
- [x] Check the archived F00 baseline hash, nine check-log hashes, and six
  recorded tested-input hashes; all match their records.
- [x] Collect current-main Cargo metadata: 12 packages, 95 targets, 44
  integration targets, and 28 feature-gated integration targets.
- [x] Identify the additional integration target:
  `exact_transcendentals::transduction_boundaries`.

## Next actions, in order

- [ ] **F00:** Record a fresh snapshot of the current checkout and all local
  changes, including hashes and provenance. Preserve historical manifests.
- [ ] **F00:** Finish and record independent acceptance of the baseline.
  Hash consistency checks alone do not establish complete acceptance.
- [x] Review the intake branch's unique bootstrap commit `e8b9c21` against
  main at `a51f641`. Main's `dd40fd6` removes the secret-key shortcut entirely;
  resolve the history merge to main's implementation. Pin a fresh parent for
  each subsequent implementation task.
- [ ] **F02:** Update the target inventory from the historical 94/43 counts
  to the observed 95/44 counts. Include every target, required feature,
  ignored reason, resource class, and execution status.
- [ ] **F02:** Assess storage and memory before compiling the full matrix.
  The primary filesystem currently has about 1.3 GiB free. Arrange sufficient
  build space without deleting existing source or evidence.
- [ ] **F02:** Run the serial default release sweep on the pinned parent:

  ```sh
  cargo +1.89.0 test --locked --offline --release --workspace \
    --exclude nine65-python --exclude nine65-wasm --no-fail-fast -j1
  ```

- [ ] **F02:** Run all 28 feature-gated integration targets with their
  declared features. Use debug for fixtures requiring `allow_insecure`;
  execute the `extreme-tests` target separately.
- [ ] **F02:** Reproduce each failure individually and reconcile target and
  test totals. Record positive matched counts, ignored counts, failures,
  skipped targets, and exit codes. Preserve every failing assertion.
- [ ] Capture current hosted checks for the same source commit. The merged
  PR #182 and #183 full suites failed; earlier successful jobs do not accept
  the complete matrix.
- [ ] Save fresh results, source/toolchain/tuple hashes, raw logs, and review
  decisions under a new execution ID.

## Remaining dependency waves

Advance these groups only when their exact prerequisites are accepted.

- [ ] **Wave 1 — F01, F02, F03, S00:** Complete tuple evidence, test inventory,
  historical/proof reconciliation, and the live S8/2–11 phase contract.
- [ ] **Wave 2 — C00, C01, C06, S02, V00:** Establish the main-Q route,
  sound noise bounds, capacity refusals, composite operator domains, and
  exact security inputs.
- [ ] **Wave 3 — C02, S01:** Bind immutable ciphertext history and on-demand
  lift to the intact priming root.
- [ ] **Wave 4 — S03:** Integrate sister frames with the preserved phase relation.
- [ ] **Wave 5 — S04:** Certify operator domains, inverse validity, and DIV3 scope.
- [ ] **Wave 6 — S05, R00, H00:** Integrate public CRAM, derive parameter
  bounds, and capture real shadow-source traces.
- [ ] **Wave 7 — C03, R01, H01:** Define strict main-Q wire handling, the
  live digit radius, and conditional shadow entropy.
- [ ] **Wave 8 — C04, R02, H02:** Connect certified service operations,
  the encrypted digit DAG, and the Three Locks key/interruption model.
- [ ] **Wave 9 — C05, V03, R03, G00, H03:** Integrate Python and complete CI,
  tuple admission, certified optimization, and the Shadow Lock lifecycle.
- [ ] **Wave 10 — B00, B02:** Implement admitted fixed-work capacity and
  independently specified clear transforms.
- [ ] **Wave 11 — B01:** Complete exact scale-round and relinearization provenance.
- [ ] **Wave 12 — B03, B04:** Add public Galois transforms and reviewed key transitions.
- [ ] **Wave 13 — B05:** Evaluate the bounded canonical digit under encryption.
- [ ] **Wave 14 — B06:** Contract into the work-key domain with coefficient oracles.
- [ ] **Wave 15 — B07:** Assemble the admitted native public refresh backend.
- [ ] **Wave 16 — B08:** Track refresh eligibility per ciphertext across DAGs.
- [ ] **Wave 17 — B09:** Demonstrate refresh, multiply, refresh and boundary refusals.
- [ ] **Wave 18 — H04, V01, V02, V04:** Complete interruption experiments,
  repeated CT measurements, implementation-linked proofs, and performance evidence.
- [ ] **Wave 19 — V05:** Reconcile all issues, claims, tuples, proofs, tests,
  and artifacts on the final commit; complete external estimation/audit and
  passing required hosted checks before release.

## Correctness and design gates to retain

- [ ] Resolve the depth-four and checked-decode gates (#157, #158, #176).
- [ ] Finish the live phase/parking witness and source/epoch invariant (#159).
- [ ] Resolve exact CRAM, dual-RNS, architecture, and real-refresh gate failures.
- [ ] Resolve the deserialize, encrypt/decrypt, and homomorphic fuzz failures.
- [ ] Admit a complete native public-refresh tuple and encrypted circuit
  before accepting R03/B00–B09 or closing #95/#117.
- [ ] Complete conditional entropy, deployment, external security review,
  and release evidence obligations.
