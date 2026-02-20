#!/usr/bin/env bash
set -euo pipefail

readme="README.md"
registry="docs/CLAIM_REGISTRY.csv"
errors=0

artifact_for() {
  local claim_id="$1"
  awk -F',' -v id="${claim_id}" '$1 == id { print $4 }' "${registry}"
}

require_file() {
  local path="$1"
  if [[ ! -f "${path}" ]]; then
    echo "ERROR: missing file: ${path}"
    errors=$((errors + 1))
  fi
}

compare_value() {
  local label="$1"
  local readme_val="$2"
  local artifact_val="$3"
  if [[ "${readme_val}" != "${artifact_val}" ]]; then
    echo "ERROR: claim drift for ${label}: README=${readme_val}, artifact=${artifact_val}"
    errors=$((errors + 1))
  fi
}

require_non_empty() {
  local label="$1"
  local val="$2"
  if [[ -z "${val}" ]]; then
    echo "ERROR: missing parsed value for ${label}"
    errors=$((errors + 1))
  fi
}

round2() {
  local val="$1"
  awk -v x="${val}" 'BEGIN { printf "%.2f", x + 0.0 }'
}

perf_doc=$(artifact_for "readme.fhe_ops_secure_128_192")
depth_doc=$(artifact_for "readme.depth50_symmetric_secure")
security_doc=$(artifact_for "readme.lwe_estimator_secure_configs")

require_file "${readme}"
require_file "${registry}"
require_file "${perf_doc}"
require_file "${depth_doc}"
require_file "${security_doc}"

if [[ "${errors}" -gt 0 ]]; then
  echo "stale claim check failed (${errors} precondition error(s))"
  exit 1
fi

# README claim values (source of public claims)
readme_enc_128=$(awk -F'|' '$2 ~ /^[[:space:]]*Encrypt[[:space:]]*$/ {v=$3; gsub(/[[:space:]m,s]/, "", v); print v; exit}' "${readme}")
readme_add_128=$(awk -F'|' '$2 ~ /^[[:space:]]*Add[[:space:]]*$/ {v=$3; gsub(/[[:space:]m,s]/, "", v); print v; exit}' "${readme}")
readme_mul_128=$(awk -F'|' '$2 ~ /^[[:space:]]*Mul[[:space:]]*$/ {v=$3; gsub(/[[:space:]m,s]/, "", v); print v; exit}' "${readme}")
readme_dec_128=$(awk -F'|' '$2 ~ /^[[:space:]]*Decrypt[[:space:]]*$/ {v=$3; gsub(/[[:space:]m,s]/, "", v); print v; exit}' "${readme}")

readme_enc_192=$(awk -F'|' '$2 ~ /^[[:space:]]*Encrypt[[:space:]]*$/ {v=$4; gsub(/[[:space:]m,s]/, "", v); print v; exit}' "${readme}")
readme_add_192=$(awk -F'|' '$2 ~ /^[[:space:]]*Add[[:space:]]*$/ {v=$4; gsub(/[[:space:]m,s]/, "", v); print v; exit}' "${readme}")
readme_mul_192=$(awk -F'|' '$2 ~ /^[[:space:]]*Mul[[:space:]]*$/ {v=$4; gsub(/[[:space:]m,s]/, "", v); print v; exit}' "${readme}")
readme_dec_192=$(awk -F'|' '$2 ~ /^[[:space:]]*Decrypt[[:space:]]*$/ {v=$4; gsub(/[[:space:]m,s]/, "", v); print v; exit}' "${readme}")

readme_depth_128=$(awk -F'|' '$2 ~ /^[[:space:]]*secure_128[[:space:]]*$/ {v=$4; gsub(/[[:space:]s]/, "", v); print v; exit}' "${readme}")
readme_depth_192=$(awk -F'|' '$2 ~ /^[[:space:]]*secure_192[[:space:]]*$/ {v=$4; gsub(/[[:space:]s]/, "", v); print v; exit}' "${readme}")

readme_sec_128=$(awk -F'|' '$2 ~ /secure_128/ {v=$5; gsub(/[[:space:]]/, "", v); print v; exit}' "${readme}")
readme_sec_192=$(awk -F'|' '$2 ~ /secure_192/ {v=$5; gsub(/[[:space:]]/, "", v); print v; exit}' "${readme}")
readme_sec_256=$(awk -F'|' '$2 ~ /secure_256/ {v=$5; gsub(/[[:space:]]/, "", v); print v; exit}' "${readme}")

# Artifact values: secure_128 block in performance baseline
perf_block_128="${TMPDIR:-/tmp}/claim_drift_perf_128.$$"
perf_block_192="${TMPDIR:-/tmp}/claim_drift_perf_192.$$"
depth_block_128="${TMPDIR:-/tmp}/claim_drift_depth_128.$$"
depth_block_192="${TMPDIR:-/tmp}/claim_drift_depth_192.$$"
trap 'rm -f "${perf_block_128}" "${perf_block_192}" "${depth_block_128}" "${depth_block_192}"' EXIT

awk '/### Secure Config FHE Ops \(secure_128\)/, /### Secure Config FHE Ops \(secure_192\)/' "${perf_doc}" > "${perf_block_128}"
awk '/### Secure Config FHE Ops \(secure_192\)/, /### Symmetric Max Depth \(secure_128\)/' "${perf_doc}" > "${perf_block_192}"
awk '/### Symmetric Max Depth \(secure_128\)/, /### Symmetric Max Depth \(secure_192\)/' "${depth_doc}" > "${depth_block_128}"
awk 'f{print} /### Symmetric Max Depth \(secure_192\)/{f=1; print}' "${depth_doc}" > "${depth_block_192}"

artifact_enc_128=$(grep -m1 "FHE_ENCRYPT" "${perf_block_128}" | grep -Eo '[0-9]+\.[0-9]+' | tail -n1)
artifact_add_128=$(grep -m1 "FHE_ADD" "${perf_block_128}" | grep -Eo '[0-9]+\.[0-9]+' | tail -n1)
artifact_mul_128=$(grep -m1 "FHE_MUL" "${perf_block_128}" | grep -Eo '[0-9]+\.[0-9]+' | tail -n1)
artifact_dec_128=$(grep -m1 "FHE_DECRYPT" "${perf_block_128}" | grep -Eo '[0-9]+\.[0-9]+' | tail -n1)

artifact_enc_192=$(grep -m1 "FHE_ENCRYPT" "${perf_block_192}" | grep -Eo '[0-9]+\.[0-9]+' | tail -n1)
artifact_add_192=$(grep -m1 "FHE_ADD" "${perf_block_192}" | grep -Eo '[0-9]+\.[0-9]+' | tail -n1)
artifact_mul_192=$(grep -m1 "FHE_MUL" "${perf_block_192}" | grep -Eo '[0-9]+\.[0-9]+' | tail -n1)
artifact_dec_192=$(grep -m1 "FHE_DECRYPT" "${perf_block_192}" | grep -Eo '[0-9]+\.[0-9]+' | tail -n1)

artifact_depth_128=$(round2 "$(grep -m1 "Total time:" "${depth_block_128}" | grep -Eo '[0-9]+\.[0-9]+')")
artifact_depth_192=$(round2 "$(grep -m1 "Total time:" "${depth_block_192}" | grep -Eo '[0-9]+\.[0-9]+')")

artifact_sec_128=$(awk -F'|' '$2 ~ /^[[:space:]]*secure_128[[:space:]]*$/ {v=$5; gsub(/[[:space:]]/, "", v); print v; exit}' "${security_doc}")
artifact_sec_192=$(awk -F'|' '$2 ~ /^[[:space:]]*secure_192[[:space:]]*$/ {v=$5; gsub(/[[:space:]]/, "", v); print v; exit}' "${security_doc}")
artifact_sec_256=$(awk -F'|' '$2 ~ /^[[:space:]]*secure_256[[:space:]]*$/ {v=$5; gsub(/[[:space:]]/, "", v); print v; exit}' "${security_doc}")

require_non_empty "readme_enc_128" "${readme_enc_128}"
require_non_empty "readme_add_128" "${readme_add_128}"
require_non_empty "readme_mul_128" "${readme_mul_128}"
require_non_empty "readme_dec_128" "${readme_dec_128}"
require_non_empty "readme_enc_192" "${readme_enc_192}"
require_non_empty "readme_add_192" "${readme_add_192}"
require_non_empty "readme_mul_192" "${readme_mul_192}"
require_non_empty "readme_dec_192" "${readme_dec_192}"
require_non_empty "readme_depth_128" "${readme_depth_128}"
require_non_empty "readme_depth_192" "${readme_depth_192}"
require_non_empty "readme_sec_128" "${readme_sec_128}"
require_non_empty "readme_sec_192" "${readme_sec_192}"
require_non_empty "readme_sec_256" "${readme_sec_256}"

require_non_empty "artifact_enc_128" "${artifact_enc_128}"
require_non_empty "artifact_add_128" "${artifact_add_128}"
require_non_empty "artifact_mul_128" "${artifact_mul_128}"
require_non_empty "artifact_dec_128" "${artifact_dec_128}"
require_non_empty "artifact_enc_192" "${artifact_enc_192}"
require_non_empty "artifact_add_192" "${artifact_add_192}"
require_non_empty "artifact_mul_192" "${artifact_mul_192}"
require_non_empty "artifact_dec_192" "${artifact_dec_192}"
require_non_empty "artifact_depth_128" "${artifact_depth_128}"
require_non_empty "artifact_depth_192" "${artifact_depth_192}"
require_non_empty "artifact_sec_128" "${artifact_sec_128}"
require_non_empty "artifact_sec_192" "${artifact_sec_192}"
require_non_empty "artifact_sec_256" "${artifact_sec_256}"

if [[ "${errors}" -gt 0 ]]; then
  echo "stale claim check failed (${errors} parse issue(s))"
  exit 1
fi

compare_value "encrypt secure_128" "${readme_enc_128}" "${artifact_enc_128}"
compare_value "add secure_128" "${readme_add_128}" "${artifact_add_128}"
compare_value "mul secure_128" "${readme_mul_128}" "${artifact_mul_128}"
compare_value "decrypt secure_128" "${readme_dec_128}" "${artifact_dec_128}"

compare_value "encrypt secure_192" "${readme_enc_192}" "${artifact_enc_192}"
compare_value "add secure_192" "${readme_add_192}" "${artifact_add_192}"
compare_value "mul secure_192" "${readme_mul_192}" "${artifact_mul_192}"
compare_value "decrypt secure_192" "${readme_dec_192}" "${artifact_dec_192}"

compare_value "depth total secure_128" "${readme_depth_128}" "${artifact_depth_128}"
compare_value "depth total secure_192" "${readme_depth_192}" "${artifact_depth_192}"

compare_value "security rop secure_128" "${readme_sec_128}" "${artifact_sec_128}"
compare_value "security rop secure_192" "${readme_sec_192}" "${artifact_sec_192}"
compare_value "security rop secure_256" "${readme_sec_256}" "${artifact_sec_256}"

if [[ "${errors}" -gt 0 ]]; then
  echo "stale claim check failed (${errors} drift issue(s))"
  exit 1
fi

echo "Stale claim check passed."
