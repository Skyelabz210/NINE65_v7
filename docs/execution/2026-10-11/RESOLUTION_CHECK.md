# PR resolution and execution checkpoint — 2026-10-11

Parent: `main@33f06166bdcef8250b32e4a663334b34f8488bfc`.
Evidence: [resolution artifacts](../../../artifacts/execution/2026-10-11-resolution/).
This checkpoint records completed maintenance and the gates still required by
the [43-card plan](../2026-10-03/PLAN.md).

## Pull requests and review resolution

The refreshed inventory had no open PRs after #179 merged at `33f0616`.
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
existing license, updates Rand 0.8.5 to 0.8.6 and 0.9.2 to 0.9.3, and removes
the obsolete UNHAL MIT clarification so its declared proprietary metadata is
used. The main branch's fixed Crossbeam 0.9.21 is preserved.

Local formatting, strict workspace Clippy, and all four cargo-deny checks pass.
`clockwork-core` passes 46 tests against the new Rand lockfile. The narrow
RUSTSEC-2025-0141 exception remains as explicitly permitted by #178; other
advisories remain enforced. Hosted T1 and T2 must be captured on the published
follow-up before assigning it a final resolution state.

The maintained-codec candidate is preserved on local branch
`codex/oct11-serialization-maintenance` at `40d62f7`. Its Bincode 2.0.1 versus
bincode-next 2.1.0 probe matches six byte fixtures, and its actual ciphertext
golden test passes once. It needs rebasing onto the updated parent, inventory
and corpus checks for the excluded Python/WASM codecs, malformed-input fuzzing,
and full review before integration. #178 is not closed by that candidate.

## Add-path performance evidence

Three independent runs compare `b0b01ea9` with `33f0616` using the same Rust
1.89.0 compiler, optimized profile, source modules and fixed input workload.
Each run executes 10,000 chains of 30 additions; every readout must equal 465.
The raw integer timings and source hashes are in `add-benchmark.json`, with the
standalone probe beside it. These measurements cover the staged carriers.

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
