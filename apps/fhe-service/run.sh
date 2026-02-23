#!/usr/bin/env bash
# Start the FHE service with sensible defaults.
# Override with env vars: FHE_SERVICE_HOST, FHE_SERVICE_PORT, FHE_MAX_SESSIONS, etc.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$DIR/fhe-service"
