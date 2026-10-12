# PR resolution and execution checkpoint — 2026-10-11

Current parent: `main@ba4c46b57d79337fadee3304e532f18c0dec68d1` after #180.
The earlier main CI inventory is pinned separately to `33f0616`.
Evidence: [resolution artifacts](../../../artifacts/execution/2026-10-11-resolution/).
This checkpoint records completed maintenance and the gates still required by
the [43-card plan](../2026-10-03/PLAN.md).

## Pull requests and review resolution

The initial check after #179 merged found no open PRs. The later inventory
captured concurrent #180; it has now merged at `ba4c46b` after its full CI result
was reviewed. This checkpoint is the remaining follow-up #181. Its open status
is explicitly represented in the refreshed inventory.
#179 supersedes closed #173; #175 and its child #177 were already merged.
All five inline #179 findings are resolved: add-chain reconstruction counts,
preserved extension lanes, checked large-basis extraction, coprimality after
product overflow, and full-range modular reduction. The current
`exact_transcendentals` suite passes 632 tests without failures or ignores.
#159 remains open for the phase/parking witness, multiplication across laps,
and the full carrier acceptance contract. A PR merge does not close those gates.

## Dependency gate repair

The main CI run [38200604711](https://github.com/Skyelabz210/NINE65_v7/actions/runs/38200604711)
passes formatting and Clippy but fails cargo-deny on `subtle`'s BSD-3-Clause
license and the old Rand dependency. This follow-up explicitly allows that
existing license, preserves #180's Rand 0.8.6/0.9.5 updates, and removes
the obsolete UNHAL MIT clarification so its declared proprietary metadata is
used. The main branch's fixed Crossbeam 0.9.21 is preserved.

Local formatting, strict workspace Clippy, and all four cargo-deny checks pass.
`clockwork-core` passes 46 tests against the new Rand lockfile. The narrow
RUSTSEC-2025-0141 exception remains as explicitly permitted by #178; other
advisories remain enforced. At #180 head `9ac1adf`, hosted T1 passes and the
complete default suite reports 1,881 passed, nine failed and 193 ignored in
[run 38201693119](https://github.com/Skyelabz210/NINE65_v7/actions/runs/38201693119).
The failures match the previously archived eight `nine65 --lib` cases and
`class_f_alpha_lanes_must_be_prime_and_distinct`; the raw current log is archived.
They remain release blockers. #181 adds evidence and policy metadata without
changing the production arithmetic; capture its exact-head hosted gates too.

The maintained-codec candidate is archived as `codec-candidate.patch.gz`, with its
six-fixture probe, lockfile and golden-test log beside it. Its Bincode 2.0.1 versus
bincode-next 2.1.0 probe matches six byte fixtures, and its actual ciphertext
golden test passes once. It needs rebasing onto the updated parent, inventory
and corpus checks for the excluded Python/WASM codecs, malformed-input fuzzing,
and full review before integration. #178 is not closed by that candidate.

## Add-path performance evidence

Three independent runs compare `b0b01ea9` with `33f0616` using the same Rust
1.89.0 compiler, optimized profile, source modules and fixed input workload.
Each run executes 10,000 chains of 30 additions; every readout must equal 465.
The raw integer timings and source hashes are in `add-benchmark.json`. The exact
module snapshots are under `sources/base` and `sources/head`; run
`python3 artifacts/execution/2026-10-11-resolution/replay-add-benchmark.py` to
verify their hashes, build each optimized probe, and replay all three runs.
The script invokes the pinned Rust 1.89.0 compiler, checks its full version
against the original record, and includes the actual compiler/profile in output.
These measurements cover the staged carriers.

| Carrier | Before median ns | After median ns | Before scalar extractions per chain | After scalar extractions per chain |
| --- | ---: | ---: | ---: | ---: |
| WindingCRT | 47,932,034 | 874,995,743 | 1 | 61 |
| Recumbent | 110,238,047 | 1,696,243,140 | 2 | 122 |

The current addition extracts both operands before every sum; Recumbent adds
both primary and hot carriers. That work explains the measured increase. The
fail-closed repair prevents lost carries but does not satisfy the planned
lane-parallel phase/parking contract. The workload stays inside the basis so
both versions return correct answers; the wrap-boundary regressions separately
check the defect that motivated the fallback. No public BFV performance or
noise conclusion follows from these carrier measurements.

## Reproduce the dependency-policy check

The executable invocation, binary version/hash, generated configuration/hash,
Cargo.lock hash and frozen RustSec revision are in
`logs/cargo-deny-invocation.json`. The archived generated configuration differs
from `deny.toml` only in its advisory-cache path; `verify-deny.py` checks the
parsed policies for equality before invoking cargo-deny with `--offline`.
It requires the database to be clean at the requested revision before and after
checking, and verifies the dependency inputs did not change during the run.
The replay requires clean repository manifests, hashes the root/member and
resolved-package manifests, and gives cargo-deny the archived, frozen Cargo
metadata graph. Five refusal fixtures cover the compiler, dirty database and
initially/during-run changed manifest cases.
The original preliminary snapshot is preserved separately; the primary
`baseline.json` and `checks.json` identify the final source and policy inputs.

Use the official cargo-deny 0.20.2 binary, run `cargo fetch --locked`, and clone
`https://github.com/RustSec/advisory-db` into
`/tmp/nine65-deny-advisory-db/advisory-db-3157b0e258782691`. Check out its
recorded revision `7eebec69c352c7191b1f13eb95dd510eeca5d1de`, then run:

```sh
python3 artifacts/execution/2026-10-11-resolution/verify-deny.py \
  --cargo-deny /path/to/cargo-deny \
  --advisory-db /tmp/nine65-deny-advisory-db \
  --advisory-revision 7eebec69c352c7191b1f13eb95dd510eeca5d1de \
  --output-directory /tmp/nine65-deny-replay
```

The codec probe can be rerun with
`cargo run --locked --manifest-path artifacts/execution/2026-10-11-resolution/codec-compatibility/Cargo.toml`.
The candidate patch remains outside the production build and needs its stated
compatibility, malformed-input and integration gates.

## Remaining execution gates

Cargo metadata still declares 94 targets in 12 packages, including 43 integration
targets and 28 requiring features. This session ran the two package suites
above; it does not claim the full workspace or all feature combinations passed.
The original intake's deleted evidence and bootstrap edit are preserved and
hashed in the fresh F00 observation. F00 still requires independent acceptance.

| Gate | Source-bound observation | Required next work |
| --- | --- | --- |
| F00 | Fresh baseline identifies the intake changes and tested patch; original historical manifests are preserved | Independently review and accept the baseline |
| F02 / #64 / #137 | Target inventory is refreshed; historical full-suite and fuzz failures remain evidence | Finish the exact-head `--no-fail-fast` and feature matrices, retain every failure and positive test count |
| CRAM architecture | Main residue-native, recumbency and exact-noise jobs fail | Repair the admitted source/epoch, exact-bound and production-route contracts; preserve assertions |
| Comparative harnesses | Two main workflows try to build forbidden release `allow_insecure` | Repair the harness's parameter/RNG/profile contract and rerun before claiming comparative results |
| #157 / #158 / #176 | Depth-four and full-range single-modulus decode acceptance remain open | Locate the first oracle divergence or supported-bound crossing; accept an exact result or an earlier typed refusal |
| R00–R03 / B00–B09 / #95 / #117 | No complete native public-refresh admission has been established | Supply live radius, certified encrypted DAG, complete tuple/security disposition and repeated full-coefficient refresh oracles |
| S00–S05 / #159 | Partial carrier and composite-operator repairs exist | Finish the independently admitted live phase/parking and sister-frame integration |
| H00–H04 / V00–V05 | Conditional entropy, deployment interruption, repeated CT, external estimation and audit gates remain | Obtain the stated derivations, experiments and independent reviews |

The coordinator validator passes its 12 self-tests and checks the 43-card DAG.
`ready` continues to return F00 without accepted prerequisites. No new packet
acceptance is asserted here. The next execution wave follows the existing
dependency order once its evidence and required review are accepted.
