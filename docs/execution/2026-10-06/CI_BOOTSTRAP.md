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

Next CI gate: publish this patch on an indexed PR head, observe `cargo-deny`
resolution, then triage the full workspace Clippy backlog without blanket lint
allows. Make T2 run on that exact head, preserve its failing tests, and only
then configure required check names/rulesets. A job skipped because T1 failed
does not count as execution. #79 and release remain open.
