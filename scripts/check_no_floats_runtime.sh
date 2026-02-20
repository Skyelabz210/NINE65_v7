#!/usr/bin/env bash
# check_no_floats_runtime.sh — Quality gate: no floating-point in production code
#
# Scans Rust source for float literals, f32/f64 types, and float operations.
# Exempts:
#   - Test code (#[cfg(test)] blocks)
#   - compiler.rs (has explicit #![allow(clippy::float_arithmetic)] exemption)
#   - comprehensive_benchmarks.rs (offline benchmark reporting)
#   - bin/ directory (benchmark/demo binaries, not library code)
#   - Comments and doc strings
#
# Exit 0 if clean, exit 1 if violations found.

set -euo pipefail

CRATE_DIR="crates/nine65/src"
VIOLATIONS=0

echo "=== No-Floats Quality Gate ==="
echo "Scanning: $CRATE_DIR"
echo ""

# Float patterns to detect
FLOAT_PATTERNS=(
    '\bf32\b'
    '\bf64\b'
    '[0-9]+\.[0-9]+[^."]'  # Float literals like 3.14 (exclude ranges ..)
    'as f32'
    'as f64'
    'f32::'
    'f64::'
)

for pattern in "${FLOAT_PATTERNS[@]}"; do
    matches=$(grep -rn "$pattern" "$CRATE_DIR" --include="*.rs" \
        --exclude="compiler.rs" \
        --exclude="comprehensive_benchmarks.rs" \
        --exclude-dir="bin" \
        2>/dev/null || true)

    if [ -z "$matches" ]; then
        echo "  [PASS] No '$pattern' found"
        continue
    fi

    # Filter: exclude test code and comments
    non_test_matches=""
    while IFS= read -r line; do
        file=$(echo "$line" | cut -d: -f1)
        lineno=$(echo "$line" | cut -d: -f2)
        content=$(echo "$line" | cut -d: -f3-)

        # Skip comments
        if echo "$content" | grep -qE '^\s*//'; then
            continue
        fi

        # Skip test modules
        in_test=$(head -n "$lineno" "$file" 2>/dev/null | grep -c '#\[cfg(test)\]' || true)
        if [ "$in_test" -gt 0 ]; then
            last_cfg_test_line=$(head -n "$lineno" "$file" | grep -n '#\[cfg(test)\]' | tail -1 | cut -d: -f1)
            if [ -n "$last_cfg_test_line" ]; then
                diff=$((lineno - last_cfg_test_line))
                if [ "$diff" -lt 2000 ]; then
                    continue
                fi
            fi
        fi

        non_test_matches="$non_test_matches
$line"
    done <<< "$matches"

    non_test_matches=$(echo "$non_test_matches" | sed '/^$/d')

    if [ -z "$non_test_matches" ]; then
        echo "  [PASS] '$pattern' — all occurrences in test/comment code"
    else
        count=$(echo "$non_test_matches" | wc -l)
        echo "  [FAIL] '$pattern' — $count float violations in production code:"
        echo "$non_test_matches" | head -5
        VIOLATIONS=$((VIOLATIONS + count))
    fi
done

echo ""
if [ "$VIOLATIONS" -gt 0 ]; then
    echo "RESULT: $VIOLATIONS float violations found"
    echo "Fix: Replace float literals with integer/rational equivalents"
    echo "     See CLAUDE.md 'Integer-Only Representations' table"
    exit 1
else
    echo "RESULT: No floating-point in production code"
    exit 0
fi
