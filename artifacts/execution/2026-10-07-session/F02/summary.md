# F02 current-tree release rerun

Source commit: `d1d082c9579e0b0026398cd08fec15c092c361f4`  
Source tree: `0da0812d3da71a5eadb96b68461c925298168149`  
Toolchain: Rust 1.89.0

The follow-up branch contains the identical tested tree as
`a5f5cfd7d5ecf69cc6d4f83bc6e1e9c0bafb4b3a` after the original commits were
replayed on the newly updated `main`.

The strict workspace Clippy gate passes:

```text
cargo +1.89.0 clippy --offline -j1 --workspace --all-targets -- -D warnings
```

The full pinned release sweep completed with exit 101:

```text
cargo +1.89.0 test --release --offline -j1 --workspace --no-fail-fast
```

The `nine65 --lib` target reports 941 passed, 8 failed, and 125 ignored. Four
auto-refresh tests stop at the explicit public refresh refusal. The other four
failures expose an overbroad public-refresh admission gate or wrong depth-4
plaintexts. The K-Elimination regression target reports 3 passed and 1 failed;
it expects composite Class-F alpha lanes to be rejected. These are the only
failed targets from the local workspace run. Other default targets and doc
tests passed. The local run did not reproduce the earlier sandbox-only HTTP
socket failures. The 28 feature-gated integration targets remain unexecuted.

The build took 61m54s under release LTO; `nine65 --lib` ran for 3013.20
seconds. Full failure names and the observed outcomes are in `result.json`.
The terminal output was not captured to a raw log file.
