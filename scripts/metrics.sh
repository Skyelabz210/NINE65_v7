#!/usr/bin/env bash
set -euo pipefail

echo "commit: $(git rev-parse HEAD)"
echo "rustc:  $(rustc -V)"
echo "cargo:  $(cargo -V)"

echo ""
echo "--- running tests (workspace) ---"
cargo test --release --workspace --exclude nine65-python --exclude nine65-wasm

echo ""
echo "--- counting tests (approx) ---"
grep -R --include='*.rs' '#\[test\]' crates | wc -l | awk '{print "unit_tests_marked: "$1}'
