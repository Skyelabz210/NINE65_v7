#!/usr/bin/env bash
# run_tests_medium.sh — Test Tier: MEDIUM
#
# Issue #78 ([M3] Add test categorization (fast/medium/slow) for tiered CI
# execution). See docs/TEST_TIERS.md for the full scheme, rationale, and
# measured counts/timings.
#
# WHAT THIS RUNS
#   The complete default-feature workspace test suite: every crate's `--lib`
#   unit tests (see run_tests_fast.sh) PLUS every `tests/*.rs` integration
#   target, at whatever features each crate unifies in by default. This is
#   the "required, complete release suite" the PR #97 assignment for #78
#   fixed as non-negotiable: "keeping the complete release suite reachable
#   and required" and "Categorization must improve runtime, not hide
#   failing tests." Nothing is filtered out here relative to what ci.yml's
#   T2 "Full Test Suite" job already runs today.
#
#   Deliberately mirrors ci.yml's `full-test` job command exactly (same
#   flags, same package excludes, same lack of `--release`) so this script
#   is a drop-in replacement with zero behavior change — see docs/TEST_TIERS.md
#   "CI wiring" for why `--release` is NOT added here even though the
#   CLAUDE.md "Run all tests" line documents a --release invocation: that is
#   a separate, pre-existing (not introduced by this change) discrepancy
#   between the documented local command and ci.yml's actual command, and
#   this categorization effort does not silently resolve it by picking one
#   side inside a script CI would then run unreviewed.
#
# WHEN TO USE
#   Every PR, every push to main, `[full-ci]` commits, manual dispatch — the
#   existing T2 gate. Required. Unchanged in scope from what runs today.
#
# Extra arguments are forwarded to `cargo test` verbatim.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

echo "=== Test Tier: MEDIUM (cargo test --workspace, full default-feature suite) ==="
cargo test --workspace --verbose \
  --exclude nine65-python --exclude nine65-wasm \
  "$@"
