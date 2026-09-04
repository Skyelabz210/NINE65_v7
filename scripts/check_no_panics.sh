#!/usr/bin/env bash
# check_no_panics.sh — Quality gate: no panic!/unwrap()/expect() in production code
#
# Scans Rust source under crates/nine65/src and crates/fhe-service/src for
# panic patterns outside test code.
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
# RATCHET — issue #89
# ---------------------------------------------------------------------------
# The 2026-08-12 repair left enforcement genuinely switchable but never
# switched on: MODE defaulted to advisory, and ci.yml invoked the script with
# no argument, so the backlog (real, not noise -- see NOTE below) was never
# actually gated on. Phase 2 of the execution plan framed the open decision as
# hard cutover (burn the backlog to zero, then gate) vs ratchet (baseline
# today's count, gate on new violations only). Hard cutover across ~100
# call sites, several inside cryptographic hot paths, is not a change to make
# mechanically or inside one work request -- issue #85 fixes one concrete
# instance (RNSFHEContext::try_new's production-safety assert) but the rest
# of the backlog is unaddressed. Ratchet is the part that ships today: this
# gate now compares the current per-pattern, per-directory count against a
# committed baseline (PANIC_BASELINE_FILE) and fails on any INCREASE, while
# a decrease updates nothing on its own (regenerate the baseline deliberately
# with `generate-baseline` once a real fix lands, so the improvement is
# visible in the diff instead of silently absorbed).
#
# ---------------------------------------------------------------------------
# MODE — advisory (default) | ratchet | enforced | generate-baseline
# ---------------------------------------------------------------------------
# advisory (default): prints the true violation count and exits 0. No baseline
#   comparison. Kept as the default for local/ad-hoc runs.
#
# ratchet: compares current counts against PANIC_BASELINE_FILE. Fails (exit 1)
#   if ANY (directory, pattern) count exceeds its baseline value. This is what
#   ci.yml now runs on every push and PR -- it cannot go red from the existing
#   backlog (the baseline IS that backlog), only from a NEW production
#   panic!/unwrap()/expect() site added on top of it.
#     bash scripts/check_no_panics.sh ratchet
#     NINE65_PANIC_GATE=ratchet bash scripts/check_no_panics.sh
#
# enforced: the original hard-zero mode (any violation at all fails), kept for
#   whoever eventually drives the backlog to zero and wants to flip the final
#   switch without inventing new script surface.
#     bash scripts/check_no_panics.sh enforced
#
# generate-baseline: (re)writes PANIC_BASELINE_FILE from the current counts.
#   Run this deliberately, after reviewing that a count change is a real fix
#   (or an intentionally reviewed new site), never as a way to silence a
#   ratchet failure without looking at what regressed.
#     bash scripts/check_no_panics.sh generate-baseline
#
# Exit 0 if clean/advisory/within baseline, exit 1 if a gate mode finds a
# regression (or, for `ratchet`, if PANIC_BASELINE_FILE is missing --
# fail closed rather than silently pass with nothing to compare against).

set -euo pipefail

CRATE_DIRS=("crates/nine65/src" "crates/fhe-service/src")
PANIC_BASELINE_FILE="scripts/panic_gate_baseline.txt"
PATTERNS=(
    'panic!'
    '\.unwrap()'
    '\.expect('
)

MODE="${1:-${NINE65_PANIC_GATE:-advisory}}"
case "${MODE}" in
    enforce|enforced) MODE="enforced" ;;
    ratchet) MODE="ratchet" ;;
    generate-baseline|generate_baseline) MODE="generate-baseline" ;;
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
    local dir="$1"
    find "$dir" -name '*.rs' -type f -not -path '*/bin/*' -print0 \
        | xargs -0 -r awk "$PROD_AWK"
}

echo "=== No-Panics Quality Gate ==="
echo "Scanning: ${CRATE_DIRS[*]} (excluding bin/ and test-gated items)"
echo "Mode:     $MODE"
echo ""

TOTAL_VIOLATIONS=0
REGRESSED=0
# Rows to (re)write if MODE=generate-baseline.
declare -a BASELINE_ROWS=()

for dir in "${CRATE_DIRS[@]}"; do
    PROD_LINES="$(production_lines "$dir")"
    PROD_LINE_COUNT=$(printf '%s\n' "$PROD_LINES" | grep -c . || true)
    echo "--- $dir ---"
    echo "Production source lines in scope: $PROD_LINE_COUNT"

    for pattern in "${PATTERNS[@]}"; do
        # Drop whole-line comments; `//` mid-line is left alone so that a
        # genuine trailing-comment violation is not hidden by its own
        # annotation.
        matches=$(printf '%s\n' "$PROD_LINES" \
            | grep -v '^[^:]*:[0-9]*:[[:space:]]*//' \
            | grep "$pattern" || true)

        count=0
        if [ -n "$matches" ]; then
            count=$(printf '%s\n' "$matches" | wc -l)
        fi
        TOTAL_VIOLATIONS=$((TOTAL_VIOLATIONS + count))
        BASELINE_ROWS+=("${dir}|${pattern}|${count}")

        if [ "$count" -eq 0 ]; then
            echo "  [PASS] '$pattern' — none in production code"
            continue
        fi

        echo "  [FAIL] '$pattern' — $count occurrences in production code"
        printf '%s\n' "$matches" | head -10 | sed 's/^/    /'
        if [ "$count" -gt 10 ]; then
            echo "    ... and $((count - 10)) more"
        fi

        if [ "$MODE" = "ratchet" ]; then
            baseline_count=0
            if [ -f "$PANIC_BASELINE_FILE" ]; then
                baseline_count=$(grep -F "${dir}|${pattern}|" "$PANIC_BASELINE_FILE" \
                    | tail -1 | cut -d'|' -f3 || true)
                baseline_count="${baseline_count:-0}"
            fi
            if [ "$count" -gt "$baseline_count" ]; then
                echo "    RATCHET REGRESSION: baseline for ${dir} '${pattern}' is ${baseline_count}, found ${count}"
                REGRESSED=1
            fi
        fi
    done
    echo ""
done

if [ "$MODE" = "generate-baseline" ]; then
    {
        echo "# panic_gate_baseline.txt — committed ratchet baseline for check_no_panics.sh"
        echo "# Format: <dir>|<pattern>|<count>. Regenerate deliberately with"
        echo "# 'bash scripts/check_no_panics.sh generate-baseline' after reviewing"
        echo "# that a count change is a real, reviewed fix or addition — never to"
        echo "# silence a ratchet failure without looking at what regressed."
        for row in "${BASELINE_ROWS[@]}"; do
            echo "$row"
        done
    } > "$PANIC_BASELINE_FILE"
    echo "Wrote $PANIC_BASELINE_FILE ($TOTAL_VIOLATIONS total violations across ${#CRATE_DIRS[@]} dirs)."
    exit 0
fi

if [ "$TOTAL_VIOLATIONS" -eq 0 ]; then
    echo "RESULT: No panic patterns in production code"
    exit 0
fi

echo "RESULT: $TOTAL_VIOLATIONS panic-pattern violations in production code"
echo "NOTE: Some .expect() calls on the OS CSPRNG are intentional (CRITICAL path);"
echo "      others should become try_*/? returns. Each needs individual review."

if [ "$MODE" = "enforced" ]; then
    echo "Mode 'enforced': failing on the remaining backlog (hard-zero policy)."
    exit 1
fi

if [ "$MODE" = "ratchet" ]; then
    if [ ! -f "$PANIC_BASELINE_FILE" ]; then
        echo ""
        echo "RATCHET MODE — no baseline file at $PANIC_BASELINE_FILE."
        echo "  Failing closed rather than silently passing with nothing to compare"
        echo "  against. Run 'bash scripts/check_no_panics.sh generate-baseline' once,"
        echo "  review the result, and commit it."
        exit 1
    fi
    if [ "$REGRESSED" -ne 0 ]; then
        echo ""
        echo "RATCHET MODE — FAILING: at least one (dir, pattern) count exceeds its"
        echo "  committed baseline in $PANIC_BASELINE_FILE. The existing backlog is"
        echo "  not what failed this build; a NEW production panic!/unwrap()/expect()"
        echo "  site is. Fix it, or if it is an intentionally reviewed addition,"
        echo "  regenerate the baseline deliberately (see the script header)."
        exit 1
    fi
    echo ""
    echo "RATCHET MODE — within baseline ($PANIC_BASELINE_FILE): no new production"
    echo "  panic!/unwrap()/expect() sites relative to the committed backlog."
    exit 0
fi

echo ""
echo "ADVISORY MODE — not failing CI."
echo "  Hard cutover (burn the backlog to zero) is still an open repo-owner"
echo "  decision (docs/EXECUTION_PLAN_2026-08-12.md Phase 2). The ratchet"
echo "  (baseline this count, gate on new violations only) is live in CI as of"
echo "  issue #89 — see 'ratchet' mode above, which is what ci.yml now runs."
exit 0
