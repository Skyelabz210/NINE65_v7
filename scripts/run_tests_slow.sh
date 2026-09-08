#!/usr/bin/env bash
# run_tests_slow.sh — Test Tier: SLOW
#
# Issue #78 ([M3] Add test categorization (fast/medium/slow) for tiered CI
# execution). See docs/TEST_TIERS.md for the full scheme, rationale, and
# measured counts/timings.
#
# WHAT THIS RUNS
#   The genuinely expensive, deliberately opt-in surfaces that already exist
#   in this codebase — none of them invented by this script, all three
#   pre-dating issue #78 and individually documented at their own source:
#
#   1. `nine65`'s `slow_tests` feature (crates/nine65/Cargo.toml):
#      "TEST-ONLY: gates long-running tests in ops/rns_fhe.rs". Off by
#      default, so these do not run under run_tests_fast.sh or
#      run_tests_medium.sh.
#   2. `op_timings` (crates/nine65/tests/op_timings.rs): the per-operation
#      timing suite CLAUDE.md's "Performance Baselines" table is measured
#      from. Marked `#[ignore]` in its own source — see the file's own doc
#      comment for the exact command this line reproduces.
#   3. `nine65-extreme-tests`'s `extreme-tests` feature
#      (crates/nine65-extreme-tests/src/lib.rs): "This crate answers 20
#      questions the existing test suite does not ask... opt-in ... to avoid
#      slowing normal `cargo test` runs." 13 adversarial/boundary modules,
#      entirely `#[cfg]`'d out without the feature.
#
#   Explicitly NOT included: the `#[ignore]`d tests scattered through
#   crates/nine65/src/ops/{bootstrap,rns_fhe,...}.rs and
#   crates/nine65/tests/bootstrap_*.rs. Those are ignored for a DIFFERENT
#   reason than runtime cost — they encode RETIRED MECHANISM / TEST-ONLY BUG
#   premises this substrate no longer has (see each ignore reason, and
#   CLAUDE.md's "Bootstrap Paths" section) and are not expected to pass.
#   Folding them into a timing tier via a blanket `--include-ignored` would
#   make "slow" a tier that fails by construction, which is not what a CI
#   tier is for. That is a pre-existing quarantine/retirement concern,
#   tracked separately from test *timing* categorization.
#
# WHEN TO USE
#   Weekly schedule / `[deep-ci]` / manual "deep" dispatch — matches ci.yml's
#   existing T4 tier semantics and runtime tolerance.
#
# WHY EACH PART RUNS EVEN IF AN EARLIER ONE FAILS
#   nine65's `--lib` currently has 5 pre-existing failures (see
#   docs/TEST_TIERS.md's FAST section — unrelated to this categorization
#   work, present on `main` independent of it). Under a naive `set -e`
#   script, part [1/3] failing would abort the whole script before parts
#   [2/3] and [3/3] ever ran — silently giving 0% coverage of the op_timings
#   and nine65-extreme-tests surfaces this tier exists to cover, for as long
#   as those 5 failures stand. That is exactly the kind of hiding issue #78's
#   acceptance bar rules out ("must improve runtime, not hide failing
#   tests"), so each part below runs unconditionally, its exit status is
#   recorded, and the script exits nonzero at the end iff any part failed —
#   never masking a failure, but never letting one part's failure suppress
#   the other two from running and reporting.
#
# Extra arguments are forwarded to every `cargo test` invocation below.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

overall_status=0

echo "=== Test Tier: SLOW [1/3] — nine65 slow_tests feature ==="
cargo test -p nine65 --lib --release --features slow_tests "$@"
status_1=$?
[ "$status_1" -ne 0 ] && overall_status=1

echo
echo "=== Test Tier: SLOW [2/3] — op_timings performance suite ==="
cargo test -p nine65 --test op_timings --release --features allow_insecure \
  -- --ignored --nocapture
status_2=$?
[ "$status_2" -ne 0 ] && overall_status=1

echo
echo "=== Test Tier: SLOW [3/3] — nine65-extreme-tests adversarial suite ==="
cargo test -p nine65-extreme-tests --release --features extreme-tests "$@"
status_3=$?
[ "$status_3" -ne 0 ] && overall_status=1

echo
echo "=== Test Tier: SLOW summary ==="
printf '  [1/3] slow_tests feature:   %s\n' "$( [ "$status_1" -eq 0 ] && echo PASS || echo "FAIL (exit $status_1)" )"
printf '  [2/3] op_timings:           %s\n' "$( [ "$status_2" -eq 0 ] && echo PASS || echo "FAIL (exit $status_2)" )"
printf '  [3/3] nine65-extreme-tests: %s\n' "$( [ "$status_3" -eq 0 ] && echo PASS || echo "FAIL (exit $status_3)" )"

exit "$overall_status"
