#!/usr/bin/env bash
# regression_scan.sh — Comprehensive CI regression gate for NINE65 v6
#
# This script performs multiple quality checks:
#   1. Verifies crates/nine65/src exists (fails loudly if missing)
#   2. Counts #[test] annotations across the codebase
#   3. Scans for float contamination (f32/f64) in runtime code
#   4. Checks for panic patterns in release code
#
# Exit 1 if:
#   - crates/nine65/src doesn't exist
#   - Test count < 1000
#   - Float violations found in production code
#   - Panic violations found in production code
#
# Exit 0 only if all checks pass.

set -euo pipefail

# Get the script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

CRATE_DIR="$PROJECT_ROOT/crates/nine65/src"
MIN_TEST_COUNT=1000
TOTAL_VIOLATIONS=0

echo "=============================================="
echo "  NINE65 v6 Regression Scan"
echo "=============================================="
echo ""
echo "Project Root: $PROJECT_ROOT"
echo "Target Dir:   $CRATE_DIR"
echo ""

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

# Find all Rust files and count test annotations
TEST_COUNT=0
FILES_SCANNED=0

while IFS= read -r -d '' file; do
    FILES_SCANNED=$((FILES_SCANNED + 1))
    count=$(grep -c '#\[test\]' "$file" 2>/dev/null || true)
    # Ensure count is a valid number
    if [[ "$count" =~ ^[0-9]+$ ]]; then
        TEST_COUNT=$((TEST_COUNT + count))
    fi
done < <(find "$CRATE_DIR" -name "*.rs" -type f -print0 2>/dev/null)

echo "  Files scanned: $FILES_SCANNED"
echo "  Total #[test] annotations found: $TEST_COUNT"
echo "  Minimum required: $MIN_TEST_COUNT"

if [ "$TEST_COUNT" -lt "$MIN_TEST_COUNT" ]; then
    echo "  [FAIL] Test count ($TEST_COUNT) is below minimum ($MIN_TEST_COUNT)"
    TOTAL_VIOLATIONS=$((TOTAL_VIOLATIONS + 1))
else
    echo "  [PASS] Test count meets minimum requirement"
fi
echo ""

# ============================================================
# CHECK 2: Float contamination scan (f32/f64 in runtime code)
# ============================================================
echo "=== Check 2: Float Contamination Scan ==="

FLOAT_VIOLATIONS=0

# Float patterns to detect
FLOAT_PATTERNS=(
    '\bf32\b'
    '\bf64\b'
)

for pattern in "${FLOAT_PATTERNS[@]}"; do
    # Find all matches in runtime code
    matches=$(grep -rn "$pattern" "$CRATE_DIR" --include="*.rs" 2>/dev/null || true)

    if [ -z "$matches" ]; then
        echo "  [PASS] No '$pattern' found"
        continue
    fi

    # Filter: exclude test code and comments
    while IFS= read -r line; do
        file=$(echo "$line" | cut -d: -f1)
        lineno=$(echo "$line" | cut -d: -f2)
        content=$(echo "$line" | cut -d: -f3-)

        # Skip comments (lines starting with //)
        if echo "$content" | grep -qE '^\s*//'; then
            continue
        fi

        # Skip doc comments (lines starting with ///)
        if echo "$content" | grep -qE '^\s*///'; then
            continue
        fi

        # Skip if inside a #[cfg(test)] module
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

        # This is a real violation
        echo "  [FAIL] Float violation: $line"
        FLOAT_VIOLATIONS=$((FLOAT_VIOLATIONS + 1))
    done <<< "$matches"
done

if [ "$FLOAT_VIOLATIONS" -eq 0 ]; then
    echo "  [PASS] No float contamination in production code"
else
    echo "  [FAIL] Found $FLOAT_VIOLATIONS float violations in production code"
    TOTAL_VIOLATIONS=$((TOTAL_VIOLATIONS + 1))
fi
echo ""

# ============================================================
# CHECK 3: Panic patterns in release code
# ============================================================
echo "=== Check 3: Panic Pattern Scan ==="

PANIC_VIOLATIONS=0

# Patterns to detect
PANIC_PATTERNS=(
    'panic!'
    '\.unwrap()'
    '\.expect('
)

for pattern in "${PANIC_PATTERNS[@]}"; do
    matches=$(grep -rn "$pattern" "$CRATE_DIR" --include="*.rs" 2>/dev/null || true)

    if [ -z "$matches" ]; then
        echo "  [PASS] No '$pattern' found"
        continue
    fi

    # Filter out test modules and comments
    while IFS= read -r line; do
        file=$(echo "$line" | cut -d: -f1)
        lineno=$(echo "$line" | cut -d: -f2)
        content=$(echo "$line" | cut -d: -f3-)

        # Skip comments
        if echo "$content" | grep -qE '^\s*//'; then
            continue
        fi

        # Skip doc comments
        if echo "$content" | grep -qE '^\s*///'; then
            continue
        fi

        # Skip if inside a #[cfg(test)] module
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

        # This is a real violation
        echo "  [FAIL] Panic pattern: $line"
        PANIC_VIOLATIONS=$((PANIC_VIOLATIONS + 1))
    done <<< "$matches"
done

if [ "$PANIC_VIOLATIONS" -eq 0 ]; then
    echo "  [PASS] No panic patterns in production code"
else
    echo "  [FAIL] Found $PANIC_VIOLATIONS panic pattern violations in production code"
    TOTAL_VIOLATIONS=$((TOTAL_VIOLATIONS + 1))
fi
echo ""

# ============================================================
# FINAL SUMMARY
# ============================================================
echo "=============================================="
echo "  REGRESSION SCAN SUMMARY"
echo "=============================================="
echo ""
echo "Files scanned:        $FILES_SCANNED"
echo "Test count:           $TEST_COUNT (minimum: $MIN_TEST_COUNT)"
echo "Float violations:     $FLOAT_VIOLATIONS"
echo "Panic violations:     $PANIC_VIOLATIONS"
echo "Total check failures: $TOTAL_VIOLATIONS"
echo ""

if [ "$TOTAL_VIOLATIONS" -gt 0 ] || [ "$TEST_COUNT" -lt "$MIN_TEST_COUNT" ]; then
    echo "RESULT: REGRESSION SCAN FAILED"
    echo ""
    if [ "$TEST_COUNT" -lt "$MIN_TEST_COUNT" ]; then
        echo "  - Test count ($TEST_COUNT) below minimum ($MIN_TEST_COUNT)"
    fi
    if [ "$FLOAT_VIOLATIONS" -gt 0 ]; then
        echo "  - Float contamination detected ($FLOAT_VIOLATIONS violations)"
    fi
    if [ "$PANIC_VIOLATIONS" -gt 0 ]; then
        echo "  - Panic patterns detected ($PANIC_VIOLATIONS violations)"
    fi
    echo ""
    echo "Fix violations before merging."
    exit 1
else
    echo "RESULT: REGRESSION SCAN PASSED"
    echo ""
    echo "All quality gates satisfied:"
    echo "  [OK] Source directory verified"
    echo "  [OK] Test coverage adequate ($TEST_COUNT tests)"
    echo "  [OK] No float contamination"
    echo "  [OK] No panic patterns in release code"
    exit 0
fi
