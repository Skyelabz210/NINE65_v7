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

That run reached the targets and exposed three remaining issues: one target
reported a 4.04 GB allocation from a five-byte bincode input; one K-Elimination
target hit the panic-on-overflow helper after the fuzz harness computed its
oracle with unchecked arithmetic; and three targets did not compile because
their insecure test config is gated behind `allow_insecure`. The latest patch
enables that feature only in the separate fuzz dependency graph and preserves
failing artifacts. See the
[Fuzz Smoke triage](FUZZ_SMOKE_TRIAGE.md) for inputs, interpretations and
next actions. Hosted confirmation is pending.

Next CI gate: triage the workspace Clippy errors without blanket lint allows;
make T1 green so T2 runs on the same indexed head; preserve T2's failing tests;
then configure required check names/rulesets. A job skipped because T1 failed
does not count as execution. #79 and release remain open.
