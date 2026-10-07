# CI bootstrap after hosted runners resumed

The first PR #163 push triggered hosted CI and application-platform jobs on
2026-10-07. This establishes that Actions runners can now start; it does not
close #79. The runs failed before the full T2 suite. Initial failures were an
unresolvable lowercase cargo-deny action reference, `rg` missing on the runner,
formatting drift, `--lib` requested for the binary-only `fhe-service`, and
workspace metadata inheritance in the excluded WASM crate.

This patch makes the mechanical setup commands executable without bypassing
their checks:

* Use the action owner's published
  [`EmbarkStudios/cargo-deny-action@v2`](https://github.com/EmbarkStudios/cargo-deny-action/tree/v2)
  reference with its exact repository name. Hosted resolution of this corrected
  reference still needs a fresh PR-head run.
* Use standard `grep` in the claim script and application-platform assertions.
  The claim registry check and all eight selected static assertion steps pass
  locally. They retain their previous positive and negative predicates.
* Request only `--bins` for service Clippy. It now reaches actual linting and
  fails on 23 existing `exact_transcendentals` errors; the gate is still red.
* Give the excluded `nine65-wasm` package explicit version/edition/authors and
  track its standalone lockfile. The exact hosted WASM `cargo check --release
  --manifest-path crates/nine65-wasm/Cargo.toml --target
  wasm32-unknown-unknown --features wasm` command passes locally on Rust 1.89.
* Apply Rust 1.89 formatting to the two files the hosted format job identified.
  `cargo fmt --all -- --check` now passes. These edits are formatting only; they
  do not repair the red FHE correctness assertions.

Source-bound local logs are under
[`artifacts/execution/2026-10-06-session/CI/`](../../../artifacts/execution/2026-10-06-session/CI/).
The first sandbox WASM attempt failed at DNS; the network-enabled rerun passed.
The service Clippy failure is preserved as a failure, not suppressed.

The first hosted run on follow-up PR #164 at `ed6ec8f` verifies that the
corrected cargo-deny action resolves and formatting passes. Static analysis,
mode/claim policy, and the WASM client boundary pass. Service tests and both
private-feedback test steps also pass. T1 Fast Gate, the service boundary, and
the private-feedback stack stop at strict Clippy; T2 is skipped after T1 fails.
The exact local T1 Clippy command fails on 23 existing
`exact_transcendentals` errors, starting with `int_plus_one` and
`should_implement_trait`. The service-specific local Clippy run encounters the
same dependency errors. None have been suppressed.

The first Fuzz Smoke attempt failed before target execution because the
`dtolnay/rust-toolchain@nightly-2025-08-04` action reference does not exist.
The follow-up uses the action's documented `@master` plus
`toolchain: nightly-2025-08-04`. The next run installed nightly but
`cargo install` selected the repository's 1.89.0 toolchain file, while
`cargo-fuzz 0.13.2`'s `cargo-platform 0.3.3` dependency requires Rust 1.91.
The workflow then set `RUSTUP_TOOLCHAIN` for the whole fuzz job and pinned
`cargo-fuzz` to 0.13.2.

That run reached the targets and exposed three issues: one target reported a
4.04 GB allocation from a five-byte bincode input; one K-Elimination target
hit the panic-on-overflow helper after the fuzz harness computed its oracle
with unchecked arithmetic; and three targets did not compile because their
test config is gated behind `allow_insecure`. Enabling that feature hit the
crate's intentional release compile guard. The current patch switches those
targets to the release-available `for_depth` constructor, uses checked
arithmetic and APIs in the K-Elimination harness, and preserves failing
artifacts. See the [Fuzz Smoke triage](FUZZ_SMOKE_TRIAGE.md) for inputs,
interpretations and next actions. Hosted confirmation is pending.

PR #165's latest hosted run completed at head `f0545a0`. In Fuzz Smoke run
[37639373719](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37639373719),
all five targets compiled and completed their bounded run: `fuzz_ntt` passed
7,591 executions in 61 seconds, `fuzz_k_elimination` passed, and the
deserializer, encrypt/decrypt and homomorphic targets failed on preserved
inputs. The latest deserialize witness attempts a 101,866,518,432-byte
allocation from six bytes; the other two report plaintext round-trip and add
mismatches. These are unresolved correctness/safety gates, recorded with exact
repro data and artifact hashes in [Fuzz Smoke triage](FUZZ_SMOKE_TRIAGE.md).

On the same PR head, WASM client boundary, T1 static analysis, T3 Gemini and
mode/claim/benchmark policy pass. T1 Fast Gate fails strict Clippy; the
authenticated service boundary and private-feedback stack also fail at
Clippy. T2 and all T4 jobs are skipped. The workflow wiring is active, but the
required checks are not green or enforced.

Next CI gate: triage the workspace Clippy errors without blanket lint allows;
make T1 green so T2 runs on the same indexed head; preserve T2's failing tests;
then configure required check names/rulesets. In parallel, reproduce and
resolve the three preserved fuzz failures without weakening their assertions.
A job skipped because T1 failed does not count as execution. #79 and release
remain open.
