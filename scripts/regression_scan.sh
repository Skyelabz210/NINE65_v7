#!/usr/bin/env bash
# regression_scan.sh — Comprehensive CI regression gate for NINE65
#
# Checks, in order:
#   0. crates/nine65/src exists                 (structural — always hard)
#   1. #[test] annotation count >= floor        (calibrated — hard when enforcing)
#   2. no f32/f64 in production code            (calibrated, currently clean)
#   3. no panic!/unwrap()/expect() in prod code  (BACKLOG — advisory, see below)
#
# ---------------------------------------------------------------------------
# REPAIRED 2026-08-12 — Execution Plan Phase 2 (docs/EXECUTION_PLAN_2026-08-12.md)
# ---------------------------------------------------------------------------
# Four defects were fixed:
#
# 1. WRONG TEST FLOOR. MIN_TEST_COUNT was hardcoded to 1000 against a real
#    count of ~888. Check 1 could never pass, so the script failed on every
#    invocation regardless of code quality. The floor is now the measured
#    count (see MIN_TEST_COUNT below).
#
# 2. $1 WAS IGNORED. ci.yml invokes `bash scripts/regression_scan.sh enforced`
#    (T4 · Benchmark Regression). The argument was never read; every run
#    behaved identically. MODE is now honoured — see MODE below.
#
# 3. NO EXCLUSION LIST. Checks 2 and 3 scanned compiler.rs,
#    comprehensive_benchmarks.rs and bin/, which the sibling gate
#    scripts/check_no_floats_runtime.sh has always documented as exempt
#    (explicit clippy allowance, offline benchmark reporting, and
#    benchmark/demo binaries respectively). That mismatch is where the
#    "46 float violations" figure came from; with the sibling's own exemptions
#    applied the real production float count is 0.
#
# 4. TEST CODE COUNTED AS PRODUCTION. Test exclusion used the heuristic "a
#    `#[cfg(test)]` appears fewer than 2000 lines above". ops/rns_fhe.rs has a
#    ~7000-line test module, so most of it was scanned as production — the
#    source of the "238 panic violations" figure. Test items are now delimited
#    by brace depth.
#
# ---------------------------------------------------------------------------
# MODE — $1 is advisory (default) | enforced | strict
# ---------------------------------------------------------------------------
#   advisory  Report everything; fail only on check 0. Use for local scans.
#   enforced  Fail on checks 0-2 (the calibrated, currently-clean gates).
#             The panic backlog is reported but does not fail. This is what
#             ci.yml passes today, and it passes today.
#   strict    Fail on everything including the panic backlog. Nothing invokes
#             this yet — it exists so the switch is a one-word change once the
#             backlog decision below is made.
#
# Why check 3 is not hard even under `enforced`: the remaining panic findings
# are real debt, but docs/EXECUTION_PLAN_2026-08-12.md Phase 2 records an OPEN
# DECISION reserved for the repo owner — hard cutover (burn the backlog to
# zero, then gate) vs ratchet (baseline the current count, gate on new
# violations only). Hard-failing before that decision would turn CI red on
# `main` immediately. See also scripts/check_no_panics.sh, which carries the
# same switch for the same reason.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

CRATE_DIR="$PROJECT_ROOT/crates/nine65/src"

# Measured floor, not an aspiration: 889 `#[test]` annotations under
# crates/nine65/src on 2026-08-12 (branch claude/fhe-check-execution-plan-w6f3k3).
# This is a ratchet — the count must not go down. Execution Plan Phase 2 notes
# this number should be re-measured once Phase 1's test changes land.
MIN_TEST_COUNT=889

TOTAL_VIOLATIONS=0
HARD_FAILURES=0

MODE="${1:-advisory}"
case "$MODE" in
    enforce|enforced) MODE="enforced" ;;
    strict) MODE="strict" ;;
    *) MODE="advisory" ;;
esac

echo "=============================================="
echo "  NINE65 Regression Scan"
echo "=============================================="
echo ""
echo "Project Root: $PROJECT_ROOT"
echo "Target Dir:   $CRATE_DIR"
echo "Mode:         $MODE"
echo ""

# Emit "FILE:LINE:CONTENT" for lines that are NOT inside a test-gated item
# (#[cfg(test)], #[cfg(all(test, ...))], #[test]). Item extent comes from brace
# depth on a string- and comment-stripped view of each line, so braces inside
# literals cannot desynchronise the scanner. Anything that does not parse as a
# balanced item stays visible rather than being hidden.
read -r -d '' PROD_AWK <<'AWK' || true
function code(l,   c) {
  c = l
  gsub(/"(\\.|[^"\\])*"/, "\"\"", c)
  sub(/\/\/.*$/, "", c)
  return c
}
BEGIN { skip = 0; pending = 0; depth = 0; started = 0 }
FNR == 1 { skip = 0; pending = 0; depth = 0; started = 0 }
{
  line = $0
  c = code(line)
  if (skip) {
    if (!started) {
      if (index(c, "{") > 0) { started = 1; depth = 0 }
      else if (index(c, ";") > 0) { skip = 0; next }
      else { next }
    }
    n = gsub(/\{/, "{", c); m = gsub(/\}/, "}", c)
    depth += n - m
    if (depth <= 0) { skip = 0; started = 0 }
    next
  }
  if (pending) {
    if (c ~ /^[[:space:]]*#\[/ || line ~ /^[[:space:]]*\/\//) { print FILENAME ":" FNR ":" line; next }
    pending = 0; skip = 1; started = 0; depth = 0
    if (index(c, "{") > 0) {
      started = 1
      n = gsub(/\{/, "{", c); m = gsub(/\}/, "}", c)
      depth = n - m
      if (depth <= 0) { skip = 0; started = 0 }
    } else if (index(c, ";") > 0) { skip = 0 }
    next
  }
  if (c ~ /^[[:space:]]*#\[cfg\(test\)\][[:space:]]*$/ || c ~ /^[[:space:]]*#\[cfg\(all\(test,/ || c ~ /^[[:space:]]*#\[test\][[:space:]]*$/) {
    pending = 1
    print FILENAME ":" FNR ":" line
    next
  }
  print FILENAME ":" FNR ":" line
}
AWK

drop_comment_lines() { grep -v '^[^:]*:[0-9]*:[[:space:]]*//' || true; }

# ============================================================
# CHECK 0: Verify source directory exists (MUST NOT SILENTLY PASS)
# ============================================================
echo "=== Check 0: Source Directory Verification ==="
if [ ! -d "$CRATE_DIR" ]; then
    echo "  [FATAL] CRITICAL: crates/nine65/src does NOT exist!"
    echo "  [FATAL] Path checked: $CRATE_DIR"
    echo "  [FATAL] This script MUST NOT pass when source is missing."
    echo ""
    echo "RESULT: REGRESSION SCAN FAILED - Source directory missing"
    exit 1
fi
echo "  [PASS] Source directory exists: $CRATE_DIR"
echo ""

# ============================================================
# CHECK 1: Count #[test] annotations
# ============================================================
echo "=== Check 1: Test Coverage Scan ==="

TEST_COUNT=0
FILES_SCANNED=0
while IFS= read -r -d '' file; do
    FILES_SCANNED=$((FILES_SCANNED + 1))
    count=$(grep -c '#\[test\]' "$file" 2>/dev/null || true)
    if [[ "$count" =~ ^[0-9]+$ ]]; then
        TEST_COUNT=$((TEST_COUNT + count))
    fi
done < <(find "$CRATE_DIR" -name "*.rs" -type f -print0 2>/dev/null)

echo "  Files scanned: $FILES_SCANNED"
echo "  Total #[test] annotations found: $TEST_COUNT"
echo "  Minimum required (ratchet floor): $MIN_TEST_COUNT"

TEST_COUNT_OK=1
if [ "$TEST_COUNT" -lt "$MIN_TEST_COUNT" ]; then
    echo "  [FAIL] Test count ($TEST_COUNT) is below the ratchet floor ($MIN_TEST_COUNT)"
    TEST_COUNT_OK=0
    TOTAL_VIOLATIONS=$((TOTAL_VIOLATIONS + 1))
else
    echo "  [PASS] Test count meets the ratchet floor"
fi
echo ""

# ============================================================
# CHECK 2: Float contamination scan (f32/f64 in runtime code)
# ============================================================
echo "=== Check 2: Float Contamination Scan ==="
echo "  Exemptions (same list as scripts/check_no_floats_runtime.sh):"
echo "    compiler.rs, comprehensive_benchmarks.rs, bin/, test-gated items"

FLOAT_VIOLATIONS=0
FLOAT_PATTERNS=(
    '\bf32\b'
    '\bf64\b'
)

FLOAT_LINES="$(find "$CRATE_DIR" -name '*.rs' -type f \
    -not -path '*/bin/*' \
    -not -name 'compiler.rs' \
    -not -name 'comprehensive_benchmarks.rs' \
    -print0 | xargs -0 -r awk "$PROD_AWK" | drop_comment_lines)"

for pattern in "${FLOAT_PATTERNS[@]}"; do
    matches=$(printf '%s\n' "$FLOAT_LINES" | grep -E "$pattern" || true)
    if [ -z "$matches" ]; then
        echo "  [PASS] No '$pattern' in production code"
        continue
    fi
    count=$(printf '%s\n' "$matches" | wc -l)
    echo "  [FAIL] '$pattern' — $count occurrences in production code:"
    printf '%s\n' "$matches" | head -10 | sed 's/^/    /'
    FLOAT_VIOLATIONS=$((FLOAT_VIOLATIONS + count))
done

if [ "$FLOAT_VIOLATIONS" -eq 0 ]; then
    echo "  [PASS] No float contamination in production code"
else
    echo "  [FAIL] Found $FLOAT_VIOLATIONS float violations in production code"
    TOTAL_VIOLATIONS=$((TOTAL_VIOLATIONS + 1))
fi
echo ""

# ============================================================
# CHECK 3: Panic patterns in release code (BACKLOG — see MODE above)
# ============================================================
echo "=== Check 3: Panic Pattern Scan ==="
echo "  Exemptions: bin/, test-gated items"

PANIC_VIOLATIONS=0
PANIC_PATTERNS=(
    'panic!'
    '\.unwrap()'
    '\.expect('
)

PANIC_LINES="$(find "$CRATE_DIR" -name '*.rs' -type f \
    -not -path '*/bin/*' \
    -print0 | xargs -0 -r awk "$PROD_AWK" | drop_comment_lines)"

for pattern in "${PANIC_PATTERNS[@]}"; do
    matches=$(printf '%s\n' "$PANIC_LINES" | grep "$pattern" || true)
    if [ -z "$matches" ]; then
        echo "  [PASS] No '$pattern' in production code"
        continue
    fi
    count=$(printf '%s\n' "$matches" | wc -l)
    echo "  [BACKLOG] '$pattern' — $count occurrences in production code:"
    printf '%s\n' "$matches" | head -5 | sed 's/^/    /'
    if [ "$count" -gt 5 ]; then
        echo "    ... and $((count - 5)) more"
    fi
    PANIC_VIOLATIONS=$((PANIC_VIOLATIONS + count))
done

if [ "$PANIC_VIOLATIONS" -eq 0 ]; then
    echo "  [PASS] No panic patterns in production code"
else
    echo "  [BACKLOG] $PANIC_VIOLATIONS panic-pattern violations in production code"
fi
echo ""

# ============================================================
# FINAL SUMMARY
# ============================================================
echo "=============================================="
echo "  REGRESSION SCAN SUMMARY"
echo "=============================================="
echo ""
echo "Mode:                 $MODE"
echo "Files scanned:        $FILES_SCANNED"
echo "Test count:           $TEST_COUNT (floor: $MIN_TEST_COUNT)"
echo "Float violations:     $FLOAT_VIOLATIONS"
echo "Panic violations:     $PANIC_VIOLATIONS (backlog)"
echo ""

if [ "$MODE" != "advisory" ]; then
    if [ "$TEST_COUNT_OK" -eq 0 ]; then
        HARD_FAILURES=$((HARD_FAILURES + 1))
    fi
    if [ "$FLOAT_VIOLATIONS" -gt 0 ]; then
        HARD_FAILURES=$((HARD_FAILURES + 1))
    fi
fi

if [ "$MODE" = "strict" ] && [ "$PANIC_VIOLATIONS" -gt 0 ]; then
    HARD_FAILURES=$((HARD_FAILURES + 1))
fi

if [ "$HARD_FAILURES" -gt 0 ]; then
    echo "RESULT: REGRESSION SCAN FAILED"
    echo ""
    if [ "$TEST_COUNT_OK" -eq 0 ]; then
        echo "  - Test count ($TEST_COUNT) below the ratchet floor ($MIN_TEST_COUNT)"
    fi
    if [ "$FLOAT_VIOLATIONS" -gt 0 ]; then
        echo "  - Float contamination detected ($FLOAT_VIOLATIONS violations)"
    fi
    if [ "$MODE" = "strict" ] && [ "$PANIC_VIOLATIONS" -gt 0 ]; then
        echo "  - Panic patterns detected ($PANIC_VIOLATIONS violations)"
    fi
    echo ""
    echo "Fix violations before merging."
    exit 1
fi

echo "RESULT: REGRESSION SCAN PASSED (mode: $MODE)"
echo ""
echo "  [OK] Source directory verified"
echo "  [OK] Test coverage at/above floor ($TEST_COUNT tests)"
echo "  [OK] No float contamination in production code"
if [ "$PANIC_VIOLATIONS" -gt 0 ]; then
    echo "  [BACKLOG] $PANIC_VIOLATIONS panic patterns reported, not gated."
    echo "            Enforcement is blocked on the open repo-owner decision in"
    echo "            docs/EXECUTION_PLAN_2026-08-12.md Phase 2 (hard cutover vs"
    echo "            ratchet). Run with 'strict' to gate on it."
else
    echo "  [OK] No panic patterns in production code"
fi
if [ "$MODE" = "advisory" ] && [ "$TOTAL_VIOLATIONS" -gt 0 ]; then
    echo ""
    echo "  NOTE: advisory mode — $TOTAL_VIOLATIONS calibrated check(s) reported"
    echo "        findings but did not fail. Run with 'enforced' to gate on them."
fi
exit 0
