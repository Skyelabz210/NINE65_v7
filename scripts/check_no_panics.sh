#!/usr/bin/env bash
# check_no_panics.sh — Quality gate: no panic!/unwrap()/expect() in production code
#
# Scans Rust source under crates/nine65/src for panic patterns outside test code.
#
# ---------------------------------------------------------------------------
# REPAIRED 2026-08-12 — Execution Plan Phase 2 (docs/EXECUTION_PLAN_2026-08-12.md)
# ---------------------------------------------------------------------------
# Two defects were fixed:
#
# 1. STRUCTURALLY UNABLE TO FAIL. The old script ended with a hardcoded
#    `exit 0` on the violation branch, so it reported findings and then passed
#    unconditionally. It could not fail no matter what entered the tree.
#    Enforcement is now a real, switchable decision (see MODE below) rather
#    than a constant.
#
# 2. INACCURATE COUNT. Test code was excluded by the heuristic "a `#[cfg(test)]`
#    appears somewhere above this line, and fewer than 2000 lines above".
#    `ops/rns_fhe.rs` has a ~7000-line `#[cfg(test)] mod tests` block, so every
#    test line past the 2000-line window was counted as production. That is
#    where the widely-quoted figure of 238 violations came from. Test items are
#    now delimited by brace depth, which is what produced the real number.
#
# ---------------------------------------------------------------------------
# MODE — advisory (default) vs enforced
# ---------------------------------------------------------------------------
# Default is ADVISORY: it prints the true violation count and exits 0.
#
# This is deliberate and temporary. The remaining findings are a real backlog,
# not noise, but Phase 2 of the execution plan records an OPEN DECISION that
# belongs to the repo owner: hard cutover (burn the backlog down to zero, then
# gate) versus ratchet (baseline today's count, gate on "no new violations").
# Flipping this gate to hard-fail before that decision would turn CI red on
# `main` immediately — this script runs in ci.yml tier T1 on every push and PR.
#
# To enforce, pass `enforced` as $1 or set NINE65_PANIC_GATE=enforce:
#     bash scripts/check_no_panics.sh enforced
#     NINE65_PANIC_GATE=enforce bash scripts/check_no_panics.sh
# In enforced mode a non-zero violation count exits 1.
#
# Exit 0 if clean (or advisory), exit 1 if enforcing and violations remain.

set -euo pipefail

CRATE_DIR="crates/nine65/src"
VIOLATIONS=0

MODE="${1:-${NINE65_PANIC_GATE:-advisory}}"
case "${MODE}" in
    enforce|enforced) MODE="enforced" ;;
    *) MODE="advisory" ;;
esac

# Emit "FILE:LINE:CONTENT" for lines that are NOT inside a test-gated item
# (#[cfg(test)], #[cfg(all(test, ...))], #[test]). Item extent is determined by
# brace depth on a string- and comment-stripped view of each line, so braces
# inside literals cannot desynchronise the scanner. Anything that does not
# parse as a balanced item stays visible rather than being hidden.
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

# bin/ holds benchmark and demo binaries, not library code — the same exemption
# scripts/check_no_floats_runtime.sh documents and applies.
production_lines() {
    find "$CRATE_DIR" -name '*.rs' -type f -not -path '*/bin/*' -print0 \
        | xargs -0 -r awk "$PROD_AWK"
}

echo "=== No-Panics Quality Gate ==="
echo "Scanning: $CRATE_DIR (excluding bin/ and test-gated items)"
echo "Mode:     $MODE"
echo ""

PROD_LINES="$(production_lines)"
PROD_LINE_COUNT=$(printf '%s\n' "$PROD_LINES" | wc -l)
echo "Production source lines in scope: $PROD_LINE_COUNT"
echo ""

PATTERNS=(
    'panic!'
    '\.unwrap()'
    '\.expect('
)

for pattern in "${PATTERNS[@]}"; do
    # Drop whole-line comments; `//` mid-line is left alone so that a genuine
    # trailing-comment violation is not hidden by its own annotation.
    matches=$(printf '%s\n' "$PROD_LINES" \
        | grep -v '^[^:]*:[0-9]*:[[:space:]]*//' \
        | grep "$pattern" || true)

    if [ -z "$matches" ]; then
        echo "  [PASS] '$pattern' — none in production code"
        continue
    fi

    count=$(printf '%s\n' "$matches" | wc -l)
    echo "  [FAIL] '$pattern' — $count occurrences in production code"
    printf '%s\n' "$matches" | head -10 | sed 's/^/    /'
    if [ "$count" -gt 10 ]; then
        echo "    ... and $((count - 10)) more"
    fi
    VIOLATIONS=$((VIOLATIONS + count))
done

echo ""
if [ "$VIOLATIONS" -eq 0 ]; then
    echo "RESULT: No panic patterns in production code"
    exit 0
fi

echo "RESULT: $VIOLATIONS panic-pattern violations in production code"
echo "NOTE: Some .expect() calls on the OS CSPRNG are intentional (CRITICAL path);"
echo "      others should become try_*/? returns. Each needs individual review."

if [ "$MODE" = "enforced" ]; then
    echo "Mode 'enforced': failing on the remaining backlog."
    exit 1
fi

echo ""
echo "ADVISORY MODE — not failing CI."
echo "  Enforcement is blocked on an open repo-owner decision recorded in"
echo "  docs/EXECUTION_PLAN_2026-08-12.md Phase 2: hard cutover (burn the"
echo "  backlog to zero, then gate) vs ratchet (baseline this count, gate on"
echo "  new violations only). Re-run with 'enforced' once that is settled."
exit 0
