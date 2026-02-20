#!/usr/bin/env bash
set -euo pipefail

registry="docs/CLAIM_REGISTRY.csv"
policy="docs/BENCHMARK_PROFILE_POLICY.md"

if [[ ! -f "${registry}" ]]; then
  echo "ERROR: missing ${registry}"
  exit 1
fi

if [[ ! -f "${policy}" ]]; then
  echo "ERROR: missing ${policy}"
  exit 1
fi

declare -A seen_ids
errors=0
line_no=0

while IFS=',' read -r claim_id visibility profile_class artifact_path; do
  line_no=$((line_no + 1))

  # Skip header
  if [[ "${line_no}" -eq 1 ]]; then
    continue
  fi

  if [[ -z "${claim_id}" || -z "${visibility}" || -z "${profile_class}" || -z "${artifact_path}" ]]; then
    echo "ERROR: malformed row ${line_no} in ${registry}"
    errors=$((errors + 1))
    continue
  fi

  if [[ -n "${seen_ids[${claim_id}]:-}" ]]; then
    echo "ERROR: duplicate claim_id '${claim_id}' in ${registry}"
    errors=$((errors + 1))
  fi
  seen_ids["${claim_id}"]=1

  if [[ "${visibility}" != "public" && "${visibility}" != "internal" ]]; then
    echo "ERROR: invalid visibility '${visibility}' for '${claim_id}'"
    errors=$((errors + 1))
  fi

  if [[ "${profile_class}" != "secure" && "${profile_class}" != "exploratory" ]]; then
    echo "ERROR: invalid profile_class '${profile_class}' for '${claim_id}'"
    errors=$((errors + 1))
  fi

  if [[ "${visibility}" == "public" && "${profile_class}" != "secure" ]]; then
    echo "ERROR: public claim '${claim_id}' must use secure profile_class"
    errors=$((errors + 1))
  fi

  if [[ ! -f "${artifact_path}" ]]; then
    echo "ERROR: artifact path missing for '${claim_id}': ${artifact_path}"
    errors=$((errors + 1))
  fi
done < "${registry}"

if ! rg -q "docs/BENCHMARK_PROFILE_POLICY.md" README.md; then
  echo "ERROR: README.md must reference docs/BENCHMARK_PROFILE_POLICY.md"
  errors=$((errors + 1))
fi

if ! rg -q "docs/CLAIM_REGISTRY.csv" README.md; then
  echo "ERROR: README.md must reference docs/CLAIM_REGISTRY.csv"
  errors=$((errors + 1))
fi

if [[ "${errors}" -gt 0 ]]; then
  echo "Claim registry check failed with ${errors} error(s)."
  exit 1
fi

echo "Claim registry check passed."
