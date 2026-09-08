#!/usr/bin/env bash
# run_tests_fast.sh — Test Tier: FAST
#
# Issue #78 ([M3] Add test categorization (fast/medium/slow) for tiered CI
# execution). See docs/TEST_TIERS.md for the full scheme, rationale, and
# measured counts/timings.
#
# WHAT THIS RUNS
#   Every workspace crate's own `--lib` unit-test target, release profile.
#   `--lib` is a Cargo-native selector: it restricts to each crate's in-tree
#   `#[cfg(test)] mod tests` unit tests and excludes every `tests/*.rs`
#   integration-test binary, every `[[bench]]` target, every `[[bin]]`, and
#   doctests. That is exactly the boundary this repo already draws in
#   practice: the heavy, multi-multiply, `allow_insecure`-gated correctness
#   suites all live under `crates/nine65/tests/` as separate `[[test]]`
#   targets (see crates/nine65/Cargo.toml), not inside `src/`.
#
# WHY THIS IS THE "FAST" TIER, NOT AN INVENTED SUBSET
#   No test's `#[ignore]`/`#[cfg]` attributes are touched by this script or
#   by this categorization effort. This is a pure Cargo target-selection
#   split of exactly the tests that already run under the "medium" tier
#   (run_tests_medium.sh) — a strict subset, never a different set. Nothing
#   that passes today stops running; nothing that fails today starts being
#   silently skipped.
#
# WHEN TO USE
#   Local inner-dev-loop feedback, and a candidate for a future T1 fast-gate
#   step once CI can actually measure its wall time (see docs/TEST_TIERS.md
#   "CI wiring" section for why that wiring is DESCRIBED, not applied, in
#   the PR that introduced this script).
#
# Extra arguments are forwarded to `cargo test` verbatim, e.g.:
#   scripts/run_tests_fast.sh -- --nocapture
#   scripts/run_tests_fast.sh -p nine65

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

echo "=== Test Tier: FAST (cargo test --lib, release) ==="
cargo test --release --workspace --lib \
  --exclude nine65-python --exclude nine65-wasm \
  "$@"
