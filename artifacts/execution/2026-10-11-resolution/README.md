# Evidence record

Use `baseline.json` and `checks.json` for the final source/policy inputs and
check commands. `baseline-initial.json` and `checks-initial.json` preserve the
earlier observation; their stale final-input hashes and descriptive cargo-deny
label were rejected in PR #181 and are superseded.

`logs/cargo-deny-invocation.json` identifies the executable, actual argv,
archived configuration, normalized policy equality and frozen RustSec database.
The reproduction procedure is in `docs/execution/2026-10-11/RESOLUTION_CHECK.md`.

`replay-add-benchmark.py` verifies all six archived source modules against
`add-benchmark.json`, compiles the two probes, and replays three independent
runs. `logs/benchmark-replay.json` records the successful replay; the original
timings remain unchanged.
The replay invokes Rust 1.89.0 explicitly and rejects a mismatched recorded
compiler/profile. The database checker requires a clean checkout at the pinned
revision before and after checking, and refuses dependency inputs that change
during the check. `check-replay-refusals.py` verifies three invalid-input cases.

`codec-candidate.patch.gz`, `codec-compatibility/`, and the codec logs preserve the
tested migration proposal and fixtures independently of a local Git branch.
The proposal remains outside the production build pending the #178 gates.

The PR inventories are dated observations. The current snapshot includes
merged #179/#180 and open follow-up #181; consult GitHub for later state.
The full-suite logs preserve the nine existing correctness failures. This
record accepts no execution-plan card and does not declare the release ready.
