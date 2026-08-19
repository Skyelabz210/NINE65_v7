#!/usr/bin/env bash
# Build and start the FHE service with sensible defaults.
# Override with env vars: FHE_SERVICE_HOST, FHE_SERVICE_PORT, FHE_MAX_SESSIONS, etc.
#
# Always builds from source rather than shipping a prebuilt binary in the
# repo: a committed binary can't be reviewed the way source can, and it goes
# stale silently (nothing forces it to track the code it was built from).
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$DIR/../.." && pwd)"
cargo build --release -p fhe-service --manifest-path "$REPO_ROOT/Cargo.toml"
exec "$REPO_ROOT/target/release/fhe-service"
