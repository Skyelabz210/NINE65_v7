#!/usr/bin/env bash
# Source-level constant-time verification for NINE65.
#
# This script fails closed on source-invariant regressions. It does not claim
# compiler, cache, timing, speculative-execution, power, or EM closure.

set -euo pipefail

VERBOSE=0
if [[ "${1:-}" == "--verbose" ]]; then
  VERBOSE=1
elif [[ -n "${1:-}" ]]; then
  echo "usage: $0 [--verbose]" >&2
  exit 64
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

required_files=(
  "crates/nine65/src/arithmetic/ntt_fft.rs"
  "crates/nine65/src/arithmetic/montgomery.rs"
  "crates/nine65/src/arithmetic/persistent_montgomery.rs"
  "crates/nine65/src/arithmetic/k_elimination.rs"
  "crates/nine65/src/security/secret_data.rs"
  "scripts/check_ct_ntt_source.py"
  "docs/CT_NTT_AUDIT_2026-07-13.md"
  "docs/SIDE_CHANNEL_THREAT_MODEL.md"
)

for path in "${required_files[@]}"; do
  if [[ ! -f "$path" ]]; then
    echo "FAIL missing required CT artifact: $path" >&2
    exit 1
  fi
done

echo "[1/5] NTT and Montgomery source invariants"
python3 scripts/check_ct_ntt_source.py

echo "[2/5] Explicit public-only variable-time boundaries"
grep -Fq "Variable-time exponentiation for public setup values only" \
  crates/nine65/src/arithmetic/montgomery.rs
grep -Fq "Variable-time setup operation over public parameters only" \
  crates/nine65/src/arithmetic/ntt_fft.rs
grep -Fq "Variable-time setup helper over public values" \
  crates/nine65/src/arithmetic/ntt_fft.rs

echo "[3/5] CLASS-F / CLASS-R separation"
grep -Fq "CLASS-F NTT modulus must be prime" \
  crates/nine65/src/arithmetic/ntt_fft.rs
grep -Fq "this layer is CLASS-R" \
  crates/nine65/src/arithmetic/persistent_montgomery.rs
grep -Fq "odd_composite_class_r_modulus_is_supported" \
  crates/nine65/src/arithmetic/persistent_montgomery.rs
grep -Fq "odd_composite_class_r_modulus_is_supported" \
  crates/nine65/src/arithmetic/montgomery.rs

echo "[4/5] Claim boundary and residual-risk language"
grep -Fq "compiler/disassembly and hardware evidence pending" \
  docs/SIDE_CHANNEL_THREAT_MODEL.md
grep -Fq "does not establish a universal constant-time claim" \
  docs/CT_NTT_AUDIT_2026-07-13.md
grep -Fq "compiler_disassembly_verified\": False" \
  scripts/check_ct_ntt_source.py
grep -Fq "empirical_timing_verified\": False" \
  scripts/check_ct_ntt_source.py
grep -Fq "cache_line_alignment_verified\": False" \
  scripts/check_ct_ntt_source.py

echo "[5/5] High-risk source pattern checks"
if grep -nE 'if[[:space:]]+sum[[:space:]]*>=[[:space:]]*self\.(q|m)' \
    crates/nine65/src/arithmetic/ntt_fft.rs \
    crates/nine65/src/arithmetic/montgomery.rs \
    crates/nine65/src/arithmetic/persistent_montgomery.rs; then
  echo "FAIL branchy modular-add pattern returned" >&2
  exit 1
fi

if grep -nE 'if[[:space:]]+(a|left|x)[[:space:]]*>=[[:space:]]*(b|right|y)' \
    crates/nine65/src/arithmetic/ntt_fft.rs \
    crates/nine65/src/arithmetic/montgomery.rs \
    crates/nine65/src/arithmetic/persistent_montgomery.rs; then
  echo "FAIL branchy modular-subtract pattern returned" >&2
  exit 1
fi

if grep -nE 'if[[:space:]]+(a|value|x)[[:space:]]*==[[:space:]]*0' \
    crates/nine65/src/arithmetic/ntt_fft.rs \
    crates/nine65/src/arithmetic/montgomery.rs; then
  echo "FAIL branchy secret-value zero check returned in CT core" >&2
  exit 1
fi

if [[ "$VERBOSE" -eq 1 ]]; then
  echo "Residual gates intentionally OPEN:"
  echo "  - compiler IR/disassembly review"
  echo "  - cache-line/alignment and address-trace evidence"
  echo "  - fixed-vs-random target timing diagnostics"
  echo "  - speculative execution, scheduler, SMT, power, and EM analysis"
fi

echo "PASS source-level CT invariants; target-specific closure remains open"
