# Start here: one bounded task per coding session

The owner’s target is the architecture in [PLAN.md](PLAN.md). This package is
designed for different coding models to make small changes without rediscovering
or silently changing the cryptographic design. It cannot guarantee that an
unproved circuit or physical-protection hypothesis will succeed.

Read [the Safe Basis revision](SAFE_BASIS_REVISION.md) and
[the supplied-monograph reconciliation](OWNER_MODEL_RECONCILIATION.md).
The queue now has 43 packets. An exact BFV arithmetic wrapper with an unused
S8 fingerprint does not satisfy the owner's preserved priming-substrate goal.

## Coordinator commands

Run from the NINE65 repository root:

```sh
python3 scripts/nine65_execution_plan.py validate --self-test
python3 scripts/nine65_execution_plan.py list
python3 scripts/nine65_execution_plan.py ready
python3 scripts/nine65_execution_plan.py packet F00
```

At initial handoff, add `--check-baseline` to `validate` to require all recorded
source hashes to match. After accepted implementation changes, ordinary
`validate` reports baseline drift without rejecting legitimate progress. Keep
the original manifest and record each new run; never rewrite baseline hashes
just to silence drift. Future inputs must have an upstream producer in the task
graph, not merely a promised writer elsewhere in the queue.

After independently accepting F00, ask for the next dependency-ready tasks:

```sh
python3 scripts/nine65_execution_plan.py ready --accepted F00
python3 scripts/nine65_execution_plan.py packet F01 --output /tmp/NINE65-F01.md
```

`--accepted` is an explicit coordinator assertion, not an automatic proof of
completion. The tool rejects unknown IDs and acceptance sets missing prerequisites.
It executes no build, model, network request, git mutation or release action.
It never marks tasks accepted by inspecting a model’s prose.

Every [task card](tasks/) includes dependencies, bounded reads/writes, steps,
acceptance criteria, exact intended test commands, stop conditions and issue
references. Paths for future modules are proposals; they become available after
their producer task. A review/protocol task’s packet command is navigation,
not an acceptance test. A complete research gate needs the listed derivation
and independent review even if its script exits zero.

## Running a small model

Give a worker its task card and only the listed relevant source files. Use an
isolated task branch/worktree created from the accepted parent state. Preserve
the initial dirty changes; the coordinator must prepare a coherent baseline
before multiple workers edit source. Never have two workers write the same file
concurrently. Do not feed `.env`, API keys, private keys, credential files or
unrelated chat history into model context.

For example, with the already configured Aider installation:

```sh
python3 scripts/nine65_execution_plan.py packet F01 --output /tmp/NINE65-F01.md
aider --no-auto-commits --read /tmp/NINE65-F01.md \
  scripts/verify_wr1_transient_exact.py \
  scripts/generate_depth_correctness_matrix.py
```

First message: `Execute F01 exactly as specified in the task packet. Read the
listed inputs before editing. Report evidence and unresolved obligations.`
Add further owned files only when the task needs them. Current provider model
availability/pricing is not fixed by this plan. A 402/quota/context failure is
an infrastructure event, not a reason to choose a paid model, shrink validation
or change the crypto contract silently.

For Gemini/Mistral or another coding CLI use the same packet and source scope.
The model is interchangeable; accepted contracts and evidence are not.
The initial Aider, Gemini and Mistral reviews are retained under `reviews/`.
Read [their dispositions](reviews/REVIEW_DISPOSITIONS.md) before using them:
reviewer output is evidence to check, not implementation instructions.
Research/protocol/external tasks require specialist review. A small model may
implement an oracle or search a fixed candidate space; it must return a precise
blocker when a construction, proof or physical boundary is missing.

## Mandatory worker rules

1. Read the task, referenced contract and relevant source. Check whether the
   requested change already exists. Older notes are evidence, not authority
   over executable behavior or the owner’s current architecture.
2. Keep the integer runtime, residue representation, main-Q wire boundary and
   explicit evaluator/client key separation. No Garner/full-coefficient
   reconstruction in the public hot path. Oracle/client-boundary reconstruction
   is permitted where documented.
   Keep the S8 root intact, derive winding on demand and distinguish source
   identity factors from arbitrary target views. Never impose a prime-only
   requirement on all sister lanes, count overlapping moduli by raw product,
   or treat root membership as an inverse/exact-division proof for every operand.
3. Do not delete public-refresh gates, downgrade security/noise targets, loosen
   tests, introduce hardcoded successful outputs, or grant an arbitrary object
   a fresh certificate. No secret key, clear digit or decryption oracle inside
   an evaluator shortcut.
4. Exact arithmetic capacity, BFV error headroom, source unpredictability and
   attack cost are different quantities. More random output is not more
   ciphertext headroom. A metadata reset is not a ciphertext transformation.
5. Test the actual changed path. New tests must assert behavior and an
   independent expected result; test-filter count must be positive. Record
   ignored counts and exit status. Passing `cargo test ... nonexistent_filter`
   with zero tests is a failed verification attempt.
6. Do not run the full heavy suite after every trivial change. Run the packet’s
   checks, then the required acceptance suite at integration. Record blocked
   dependencies, disk/RAM limits, OOM and network failures honestly.
7. Never overwrite existing evidence. Store fresh artifacts under an execution
   ID with source hashes and preserve failure output. No real secret values,
   API keys, production shadow traces or user plaintexts in logs.
8. One concern per patch. If work exceeds the packet, split subpatches or return
   `BLOCKED_DESIGN` with the missing equation/API; do not broaden the design.
9. Produce a reviewable diff and evidence report. Commit, push, PR publication,
   package release and external messages are coordinator/owner actions.

## Worker result format

Write `artifacts/execution/<run-id>/<task-id>/result.json` and a short report:

```json
{
  "task_id": "F01",
  "status": "ready_for_review",
  "source_commit": "actual-sha",
  "worktree_manifest_sha256": "actual-hash",
  "files_changed": [],
  "checks": [
    {"command": "exact command", "exit_code": 0,
     "passed": 1, "failed": 0, "ignored": 0,
     "log": "relative/log/path", "log_sha256": "actual-hash"}
  ],
  "acceptance_evidence": [],
  "unresolved": [],
  "claims_changed": []
}
```

This is a shape example, not an artifact to copy with invented values. Allowed
statuses: `ready_for_review`, `blocked_design`, `blocked_infrastructure`,
`failed_validation`. The coordinator records acceptance separately after
reviewing source, evidence, dependencies and failure cases. For non-test
commands, omit test counts rather than fabricating them.

Independent review asks: does the patch satisfy the exact contract, does the
oracle check the property instead of restating implementation, can a negative
fixture fail, and do the recorded tests cover this source/tuple/route? A second
model’s agreement is useful review input, not cryptographic certification.

## Suggested working order

F00 first. Then F01/F02/F03/S00 can proceed on disjoint outputs. S00–S05 preserve
the intended substrate and gate public service integration. C00/C06 and the
bound/source research follow their prerequisites. C01/R00/R01/R03/H01/H02
are deliberate design gates: leave them visible if unresolved. C03/C04/C05
make current CRAM usable while public refresh is constructed. B00–B09 implement
and validate the frozen public-refresh route. V-series tasks tie the actual
system to release evidence; M3 additionally needs H04’s deployment evidence.

Current existing work and issue numbers are in [evidence.json](evidence.json).
Never assume an issue is still a code defect merely because GitHub lists it as
open, and never assume a claimed theorem proves more than its actual statement.
