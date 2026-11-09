#!/usr/bin/env bash
# Local workspace suite plus the explicitly opted-in coefficient/slot research
# target. Production builds retain their parameter/RNG gates; toy tests link
# allow_insecure only in the development test profile. No matching tests are
# removed. Both stages run and a failure from either makes this script fail.
# Extra arguments are forwarded to both cargo invocations.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

echo "=== Local workspace tests (development profile) ==="
result=0
cargo test --locked --workspace --verbose \
  --config profile.test.package.nine65.opt-level=2 \
  --exclude nine65-python --exclude nine65-wasm \
  --no-fail-fast \
  "$@" || result=$?

# Toy rings require the research feature in the linked library. Keep the entire
# target in the local suite even though production/release discovery excludes it.
echo "=== Coefficient/slot research integration ==="
cargo test --locked -p nine65 --test coefficient_slot_gate \
  --features allow_insecure --config profile.test.package.nine65.opt-level=2 \
  --no-fail-fast "$@" || result=$?
exit "$result"
