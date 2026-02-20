#!/bin/bash
#
# MANA FHE Benchmark - Sandboxed Execution Script
#
# This script runs the benchmark in a completely isolated environment.
# Security features:
#   - No network access (--network=none)
#   - Read-only filesystem (--read-only)
#   - All Linux capabilities dropped (--cap-drop=ALL)
#   - No new privileges (--security-opt=no-new-privileges)
#   - Isolated PID namespace (--pid=private via container)
#   - Resource limits applied
#
# Usage:
#   ./run_sandboxed.sh          # Run with Docker
#   ./run_sandboxed.sh --native # Run natively with firejail (if available)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SCRIPT_DIR/mana_fhe_benchmark"
EXPECTED_SHA256="61a3e1110324297a512da84270f4d73544d96fbdb80dc6bea0dbf94c5a54c5dd"

echo "=============================================="
echo "  MANA FHE Benchmark - Sandboxed Execution"
echo "=============================================="
echo ""

# Verify checksum first
echo "[1/3] Verifying binary integrity..."
ACTUAL_SHA256=$(sha256sum "$BINARY" | cut -d' ' -f1)

if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
    echo "ERROR: Checksum mismatch!"
    echo "  Expected: $EXPECTED_SHA256"
    echo "  Got:      $ACTUAL_SHA256"
    echo ""
    echo "Binary may have been tampered with. Aborting."
    exit 1
fi
echo "  Checksum verified: OK"
echo ""

# Check for Docker or Firejail
if [ "$1" == "--native" ]; then
    # Native execution with firejail
    if command -v firejail &> /dev/null; then
        echo "[2/3] Running with Firejail sandbox..."
        echo ""
        echo "Security restrictions:"
        echo "  - No network access"
        echo "  - Private /tmp and /dev"
        echo "  - Read-only home directory"
        echo "  - Seccomp syscall filter"
        echo ""
        echo "[3/3] Benchmark output:"
        echo "----------------------------------------------"
        firejail --quiet \
            --net=none \
            --private-tmp \
            --private-dev \
            --read-only=~ \
            --seccomp \
            --noroot \
            --caps.drop=all \
            "$BINARY"
    else
        echo "ERROR: Firejail not installed."
        echo "Install with: sudo apt install firejail"
        echo "Or run without --native to use Docker."
        exit 1
    fi
else
    # Docker execution (default)
    if command -v docker &> /dev/null; then
        echo "[2/3] Building Docker sandbox..."

        # Build container
        docker build -t mana-benchmark "$SCRIPT_DIR" > /dev/null 2>&1

        echo "  Container built successfully"
        echo ""
        echo "Security restrictions:"
        echo "  - No network access (--network=none)"
        echo "  - Read-only filesystem (--read-only)"
        echo "  - All capabilities dropped (--cap-drop=ALL)"
        echo "  - No privilege escalation (--security-opt=no-new-privileges)"
        echo "  - Memory limit: 512MB"
        echo "  - CPU limit: 2 cores"
        echo ""
        echo "[3/3] Benchmark output:"
        echo "----------------------------------------------"

        docker run --rm \
            --network=none \
            --read-only \
            --cap-drop=ALL \
            --security-opt=no-new-privileges \
            --memory=512m \
            --cpus=2 \
            --pids-limit=50 \
            mana-benchmark
    else
        echo "ERROR: Docker not installed."
        echo ""
        echo "Options:"
        echo "  1. Install Docker: https://docs.docker.com/get-docker/"
        echo "  2. Install Firejail and run: ./run_sandboxed.sh --native"
        echo "  3. Run directly (not recommended): ./mana_fhe_benchmark"
        exit 1
    fi
fi

echo "----------------------------------------------"
echo ""
echo "Benchmark complete. Results shown above."
echo ""
echo "To submit results: founder@hackfate.us"
