#!/usr/bin/env bash
#
# exact_transcendentals quality gate
# Run before every commit. Exit code 0 = all gates pass.
#
# Gates:
#   1. Float scan     — zero f32/f64 in production code (outside #[cfg(test)])
#   2. Debug build    — cargo build succeeds
#   3. Release build  — cargo build --release succeeds (catches LTO issues)
#   4. no_std build   — cargo build --no-default-features succeeds
#   5. Test suite     — cargo test (all tests pass, debug)
#   6. Release tests  — cargo test --release (identical results under optimization)
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
TOTAL=6

gate() {
    local name="$1"
    shift
    printf "  %-24s" "$name"
    if output=$("$@" 2>&1); then
        printf "${GREEN}PASS${NC}\n"
        PASS=$((PASS + 1))
    else
        printf "${RED}FAIL${NC}\n"
        echo "$output" | tail -20
        FAIL=$((FAIL + 1))
    fi
}

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║   exact_transcendentals quality gate             ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# Gate 1: Float scan — most critical, runs first
gate "Float scan" python3 "$PROJECT_DIR/scripts/check_no_floats.py"

# Gate 2: Debug build
gate "Debug build" cargo build

# Gate 3: Release build (LTO)
gate "Release build" cargo build --release

# Gate 4: no_std compatibility
gate "no_std build" cargo build --no-default-features

# Gate 5: Test suite (debug)
gate "Tests (debug)" cargo test

# Gate 6: Test suite (release)
gate "Tests (release)" cargo test --release

echo ""
echo "────────────────────────────────────────────────────"
if [ "$FAIL" -eq 0 ]; then
    printf "  Result: ${GREEN}ALL $TOTAL GATES PASS${NC}\n"
    echo "────────────────────────────────────────────────────"
    echo ""
    exit 0
else
    printf "  Result: ${RED}$FAIL/$TOTAL GATES FAILED${NC}\n"
    echo "────────────────────────────────────────────────────"
    echo ""
    exit 1
fi
