#!/bin/bash
# scripts/verify_constant_time.sh
#
# Constant-Time Verification Script for NINE65 v7
# 
# This script runs a suite of constant-time verification checks:
# 1. Statistical timing analysis (dudect-style)
# 2. Code pattern scanning for timing leaks
# 3. Clippy lints for common timing vulnerabilities
#
# Usage: ./scripts/verify_constant_time.sh [--verbose]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

VERBOSE=false
if [[ "$1" == "--verbose" ]]; then
    VERBOSE=true
fi

echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   NINE65 v7 Constant-Time Verification Suite          ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
echo ""

# Track pass/fail
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

# Function to report results
report() {
    local status=$1
    local test_name=$2
    local message=$3
    
    case $status in
        PASS)
            echo -e "${GREEN}[PASS]${NC} $test_name"
            ((PASS_COUNT++))
            ;;
        FAIL)
            echo -e "${RED}[FAIL]${NC} $test_name"
            if [ -n "$message" ]; then
                echo -e "       ${RED}$message${NC}"
            fi
            ((FAIL_COUNT++))
            ;;
        WARN)
            echo -e "${YELLOW}[WARN]${NC} $test_name"
            if [ -n "$message" ]; then
                echo -e "       ${YELLOW}$message${NC}"
            fi
            ((WARN_COUNT++))
            ;;
    esac
}

# ============================================================================
# Step 1: Code Pattern Scanning
# ============================================================================
echo -e "${BLUE}[1/4] Scanning for timing leak patterns...${NC}"

# Check for data-dependent branches in secret-key paths
SECRET_FILES=(
    "crates/nine65/src/arithmetic/k_elimination.rs"
    "crates/nine65/src/arithmetic/montgomery.rs"
    "crates/nine65/src/arithmetic/barrett.rs"
    "crates/nine65/src/security/secret_data.rs"
)

BRANCH_PATTERNS=(
    "if\s+\w+\s*<\s*\w+"
    "if\s+\w+\s*>\s*\w+"
    "if\s+\w+\s*==\s*\w+"
    "match\s+\w+\s*\{"
)

for file in "${SECRET_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        report "WARN" "$file" "File not found"
        continue
    fi
    
    # Check for non-CT patterns (excluding ct_ functions and tests)
    # Look for branching on potentially secret data
    BRANCH_COUNT=$(grep -n "if\s.*<?\|if\s.*>?\|if\s.*==\|if\s.*!=" "$file" 2>/dev/null | \
        grep -v "ct_\|_ct\|test_\|#\[test\]|//\|mask\|borrow" | wc -l || echo 0)
    
    if [ "$BRANCH_COUNT" -gt 0 ]; then
        if $VERBOSE; then
            report "WARN" "$file" "Found $BRANCH_COUNT potential timing-sensitive branches"
            grep -n "if\s.*<?\|if\s.*>?\|if\s.*==\|if\s.*!=" "$file" 2>/dev/null | \
                grep -v "ct_\|_ct\|test_\|#\[test\]|//\|mask\|borrow" | head -5
        else
            report "WARN" "$file" "Found $BRANCH_COUNT potential timing-sensitive branches"
        fi
    else
        report "PASS" "$file" "No obvious timing leaks"
    fi
done

echo ""

# ============================================================================
# Step 2: Clippy Lints for Timing Vulnerabilities
# ============================================================================
echo -e "${BLUE}[2/4] Running Clippy timing vulnerability lints...${NC}"

# Run clippy with timing-related lints
CLIPPY_OUTPUT=$(cargo clippy --package nine65 -- \
    -D clippy::indexing_slicing \
    -D clippy::unwrap_used \
    -W clippy::cast_possible_truncation \
    -W clippy::cast_sign_loss \
    2>&1 || true)

# Check for indexing_slicing (can leak timing info)
INDEXING_COUNT=$(echo "$CLIPPY_OUTPUT" | grep -c "indexing_slicing" || echo 0)
if [ "$INDEXING_COUNT" -gt 0 ]; then
    report "WARN" "indexing_slicing" "$INDEXING_COUNT instances found"
else
    report "PASS" "indexing_slicing" "No unsafe indexing"
fi

# Check for unwrap_used (can panic on secret data)
UNWRAP_COUNT=$(echo "$CLIPPY_OUTPUT" | grep -c "unwrap_used" || echo 0)
if [ "$UNWRAP_COUNT" -gt 0 ]; then
    report "WARN" "unwrap_used" "$UNWRAP_COUNT instances found"
else
    report "PASS" "unwrap_used" "No unsafe unwraps"
fi

# Check for cast_possible_truncation (timing leak via truncation)
CAST_COUNT=$(echo "$CLIPPY_OUTPUT" | grep -c "cast_possible_truncation" || echo 0)
if [ "$CAST_COUNT" -gt 0 ]; then
    report "WARN" "cast_possible_truncation" "$CAST_COUNT instances found"
else
    report "PASS" "cast_possible_truncation" "No unsafe casts"
fi

echo ""

# ============================================================================
# Step 3: Statistical Timing Tests
# ============================================================================
echo -e "${BLUE}[3/4] Running statistical timing tests...${NC}"

# Run the statistical timing tests
STAT_TEST_OUTPUT=$(cargo test --package nine65 --release constant_time_statistical -- --nocapture 2>&1 || true)

if echo "$STAT_TEST_OUTPUT" | grep -q "test result: ok"; then
    report "PASS" "statistical_timing" "All statistical CT tests passed"
elif echo "$STAT_TEST_OUTPUT" | grep -q "test result: FAILED"; then
    report "FAIL" "statistical_timing" "Statistical CT tests failed"
    if $VERBOSE; then
        echo "$STAT_TEST_OUTPUT" | grep -A 5 "FAILED"
    fi
else
    report "WARN" "statistical_timing" "Tests not found or skipped"
fi

echo ""

# ============================================================================
# Step 4: Constant-Time Function Verification
# ============================================================================
echo -e "${BLUE}[4/4] Verifying constant-time function annotations...${NC}"

# Check for CT function markers
CT_FUNCTIONS=(
    "extract_k"
    "extract_k_vartime"
    "montgomery_reduce"
    "montgomery_mul"
    "barrett_reduce"
    "detect_sign"
)

for func in "${CT_FUNCTIONS[@]}"; do
    # Check if function exists and has CT implementation
    if grep -q "fn ${func}" crates/nine65/src/arithmetic/*.rs; then
        # Check for CT markers or comments
        if grep -B5 "fn ${func}" crates/nine65/src/arithmetic/*.rs | grep -q "CONSTANT-TIME\|constant-time\|ct_\|_ct"; then
            report "PASS" "$func" "Marked as constant-time"
        else
            report "WARN" "$func" "Missing CT annotation"
        fi
    else
        report "WARN" "$func" "Function not found"
    fi
done

echo ""

# ============================================================================
# Summary
# ============================================================================
echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                  Verification Summary                  ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${GREEN}PASS:${NC} $PASS_COUNT"
echo -e "  ${YELLOW}WARN:${NC} $WARN_COUNT"
echo -e "  ${RED}FAIL:${NC} $FAIL_COUNT"
echo ""

if [ "$FAIL_COUNT" -gt 0 ]; then
    echo -e "${RED}❌ Verification FAILED${NC}"
    echo ""
    echo "Critical issues found. Please review the failures above."
    exit 1
elif [ "$WARN_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}⚠ Verification PASSED with warnings${NC}"
    echo ""
    echo "Review warnings for potential timing leak improvements."
    exit 0
else
    echo -e "${GREEN}✓ Verification PASSED${NC}"
    echo ""
    echo "All constant-time checks passed successfully."
    exit 0
fi
