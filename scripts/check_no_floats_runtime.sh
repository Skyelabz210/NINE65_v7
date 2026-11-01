#!/usr/bin/env bash
# Runtime-only float gate. The Python scanner uses balanced test-item extents,
# not a line-distance heuristic. Benchmark/test float policy has its own gate.
set -euo pipefail
exec python3 "$(dirname "${BASH_SOURCE[0]}")/check_no_floats_runtime.py" "$@"
