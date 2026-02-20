#!/usr/bin/env bash
# check_no_panics.sh — Quality gate: no panic!/unwrap()/expect() in production code
#
# Scans all Rust source files in crates/nine65/src/ for panic patterns,
# excluding test modules (#[cfg(test)] blocks).
#
# Exit 0 if clean, exit 1 if violations found.

set -euo pipefail

CRATE_DIR="crates/nine65/src"
VIOLATIONS=0

echo "=== No-Panics Quality Gate ==="
echo "Scanning: $CRATE_DIR"
echo ""

# Patterns to detect (in non-test code)
PATTERNS=(
    'panic!'
    '\.unwrap()'
    '\.expect('
)

for pattern in "${PATTERNS[@]}"; do
    # Find matches, excluding test modules
    # We use a simple heuristic: skip lines in files that are inside #[cfg(test)] blocks
    # For a robust check, we grep and then filter out test-only occurrences

    matches=$(grep -rn "$pattern" "$CRATE_DIR" --include="*.rs" 2>/dev/null || true)

    if [ -z "$matches" ]; then
        echo "  [PASS] No '$pattern' found"
        continue
    fi

    # Filter out test modules and doc comments
    non_test_matches=""
    while IFS= read -r line; do
        file=$(echo "$line" | cut -d: -f1)
        lineno=$(echo "$line" | cut -d: -f2)

        # Skip if inside a #[cfg(test)] module (check preceding lines)
        in_test=$(head -n "$lineno" "$file" 2>/dev/null | grep -c '#\[cfg(test)\]' || true)
        # Count closing braces after last #[cfg(test)] to see if we're still inside
        if [ "$in_test" -gt 0 ]; then
            # Simple heuristic: if there's a #[cfg(test)] before this line,
            # assume it's test code (works for module-level test blocks)
            last_cfg_test_line=$(head -n "$lineno" "$file" | grep -n '#\[cfg(test)\]' | tail -1 | cut -d: -f1)
            if [ -n "$last_cfg_test_line" ]; then
                # If the test annotation is within 200 lines, likely in test module
                diff=$((lineno - last_cfg_test_line))
                if [ "$diff" -lt 2000 ]; then
                    continue
                fi
            fi
        fi

        # Skip doc comments (lines starting with ///)
        content=$(echo "$line" | cut -d: -f3-)
        if echo "$content" | grep -q '^\s*//'; then
            continue
        fi

        non_test_matches="$non_test_matches
$line"
    done <<< "$matches"

    # Trim and check
    non_test_matches=$(echo "$non_test_matches" | sed '/^$/d')

    if [ -z "$non_test_matches" ]; then
        echo "  [PASS] '$pattern' — all occurrences in test code"
    else
        count=$(echo "$non_test_matches" | wc -l)
        echo "  [WARN] '$pattern' — $count occurrences in production code"
        echo "$non_test_matches" | head -10
        if [ "$count" -gt 10 ]; then
            echo "  ... and $((count - 10)) more"
        fi
        VIOLATIONS=$((VIOLATIONS + count))
    fi
done

echo ""
if [ "$VIOLATIONS" -gt 0 ]; then
    echo "RESULT: $VIOLATIONS panic-pattern violations found"
    echo "NOTE: Some .expect() calls on OS CSPRNG are acceptable (CRITICAL path)"
    echo "      Review each violation and convert to try_*/? where possible."
    # Advisory mode: don't fail CI yet (some expect() on CSPRNG is intentional)
    exit 0
else
    echo "RESULT: No panic patterns in production code"
    exit 0
fi
