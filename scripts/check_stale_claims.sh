#!/usr/bin/env bash
# check_stale_claims.sh — Quality gate: the claim registry describes reality.
#
# HISTORY / WHY THIS WAS REWRITTEN (2026-08-12, Execution Plan Phase 2):
#   The previous version hardcoded three claim IDs that were formally retired
#   on 2026-07-13 (see docs/CLAIM_RETIREMENTS_2026-07-13.md) and removed from
#   docs/CLAIM_REGISTRY.csv. `artifact_for()` therefore returned the empty
#   string for all three and the script exited 1 on EVERY push and PR (it runs
#   in ci.yml tier T1 "Static Analysis & Proofs"). It also parsed a README
#   benchmark table (Encrypt/Add/Mul/Decrypt rows, depth rows, estimator rows)
#   that no longer exists in README.md.
#
#   The retired IDs are deliberately NOT spelled out in this file: check 3
#   below fails any file outside the retirement records that names one, and
#   this gate must not be the thing it is trying to catch.
#
#   Nothing about that old logic could ever pass again, so it carried no signal.
#   This version derives everything it checks from files that exist today, and
#   hardcodes no claim IDs at all.
#
# WHAT THIS GATE ENFORCES
#   1. Preconditions: README.md, docs/CLAIM_REGISTRY.csv and at least one
#      docs/CLAIM_RETIREMENTS_*.md are present, and the registry header matches
#      the expected schema.
#   2. Retired claim IDs (parsed out of every docs/CLAIM_RETIREMENTS_*.md) do
#      NOT reappear as active rows in docs/CLAIM_REGISTRY.csv.
#   3. Retired claim IDs are not cited anywhere else in the tree as if they
#      were live evidence — docs, scripts and workflows included. This is the
#      exact failure mode that broke this script: a gate went on referencing
#      IDs the registry had dropped. The retirement documents themselves are
#      the only place a retired ID may appear.
#   4. Every ACTIVE registry row points at an artifact that exists and is
#      non-empty. (scripts/check_claim_registry.sh validates the row *schema*
#      and artifact existence; this adds the "not an empty stub" check and is
#      deliberately redundant on existence so either gate alone catches a
#      dangling artifact.)
#
# Structural/schema validation of the registry rows lives in
# scripts/check_claim_registry.sh — this script is about staleness only.
#
# Exit 0 if the registry is truthful, exit 1 otherwise.

set -euo pipefail

readme="README.md"
registry="docs/CLAIM_REGISTRY.csv"
expected_header="claim_id,visibility,profile_class,artifact_path"
errors=0

fail() {
  echo "ERROR: $*"
  errors=$((errors + 1))
}

require_file() {
  local path="$1"
  if [[ ! -f "${path}" ]]; then
    fail "missing file: ${path}"
  fi
}

echo "=== Stale Claim Gate ==="
echo "Registry: ${registry}"
echo ""

# ---------------------------------------------------------------------------
# 1. Preconditions
# ---------------------------------------------------------------------------
require_file "${readme}"
require_file "${registry}"

retirement_docs=()
while IFS= read -r doc; do
  retirement_docs+=("${doc}")
done < <(find docs -maxdepth 1 -name 'CLAIM_RETIREMENTS_*.md' -type f | sort)

if [[ "${#retirement_docs[@]}" -eq 0 ]]; then
  fail "no docs/CLAIM_RETIREMENTS_*.md found — retirements must stay on record"
fi

if [[ "${errors}" -gt 0 ]]; then
  echo ""
  echo "RESULT: stale claim check FAILED (${errors} precondition error(s))"
  exit 1
fi

echo "Retirement records: ${retirement_docs[*]}"
echo ""

header=$(head -n1 "${registry}")
if [[ "${header}" != "${expected_header}" ]]; then
  fail "registry header changed: expected '${expected_header}', got '${header}'"
fi

# ---------------------------------------------------------------------------
# 2. Collect active and retired claim IDs
# ---------------------------------------------------------------------------
active_ids=()
while IFS= read -r id; do
  [[ -z "${id}" ]] && continue
  active_ids+=("${id}")
done < <(tail -n +2 "${registry}" | cut -d',' -f1)

if [[ "${#active_ids[@]}" -eq 0 ]]; then
  fail "docs/CLAIM_REGISTRY.csv has no claim rows"
fi

# Retired IDs are the backtick-quoted identifier in the FIRST column of the
# retirement tables: "| `some.claim_id` | reason | replacement |". Only column
# one is read — the third column names the *replacement* claim, which is
# normally an active registry row and must not be treated as retired.
retired_ids=()
while IFS= read -r id; do
  [[ -z "${id}" ]] && continue
  retired_ids+=("${id}")
done < <(awk -F'|' '/^\|/ {
             gsub(/[` ]/, "", $2)
             if ($2 ~ /^[a-z0-9_]+\.[a-z0-9_]+$/) { print $2 }
           }' "${retirement_docs[@]}" | sort -u)

if [[ "${#retired_ids[@]}" -eq 0 ]]; then
  fail "parsed zero retired IDs from ${retirement_docs[*]} — parser or format drifted"
fi

echo "=== Check 1: registry inventory ==="
echo "  Active claims:  ${#active_ids[@]}"
echo "  Retired claims: ${#retired_ids[@]}"
echo ""

# ---------------------------------------------------------------------------
# 3. Retired IDs must not be active
# ---------------------------------------------------------------------------
echo "=== Check 2: retired claims stay retired ==="
readmitted=0
for retired in "${retired_ids[@]}"; do
  for active in "${active_ids[@]}"; do
    if [[ "${retired}" == "${active}" ]]; then
      fail "retired claim '${retired}' is active again in ${registry}"
      readmitted=$((readmitted + 1))
    fi
  done
done
if [[ "${readmitted}" -eq 0 ]]; then
  echo "  [PASS] no retired ID reappears in the active registry"
fi
echo ""

# ---------------------------------------------------------------------------
# 4. Retired IDs must not be cited as live evidence elsewhere
# ---------------------------------------------------------------------------
echo "=== Check 3: no live references to retired claims ==="
stale_refs=0
for retired in "${retired_ids[@]}"; do
  # Search the tracked tree, excluding the retirement records (which must keep
  # naming the IDs) and the registry itself (covered by check 2).
  # NOTE: every option must precede `--`; anything after `--` is an operand,
  # which is how the --exclude flags were silently ignored during development.
  hits=$(grep -rIl --fixed-strings \
           --exclude-dir=.git \
           --exclude-dir=target \
           --exclude-dir=node_modules \
           --exclude-dir=__pycache__ \
           --exclude='CLAIM_RETIREMENTS_*.md' \
           --exclude='CLAIM_REGISTRY.csv' \
           -- "${retired}" . 2>/dev/null || true)
  if [[ -n "${hits}" ]]; then
    while IFS= read -r hit; do
      [[ -z "${hit}" ]] && continue
      fail "retired claim '${retired}' still referenced in ${hit#./}"
      stale_refs=$((stale_refs + 1))
    done <<< "${hits}"
  fi
done
if [[ "${stale_refs}" -eq 0 ]]; then
  echo "  [PASS] retired IDs appear only in the retirement records"
fi
echo ""

# ---------------------------------------------------------------------------
# 5. Active claims must have real, non-empty artifacts
# ---------------------------------------------------------------------------
echo "=== Check 4: active claim artifacts are real ==="
bad_artifacts=0
while IFS=',' read -r claim_id visibility profile_class artifact_path; do
  [[ "${claim_id}" == "claim_id" ]] && continue
  [[ -z "${claim_id}" ]] && continue
  if [[ -z "${artifact_path}" ]]; then
    fail "claim '${claim_id}' has no artifact_path"
    bad_artifacts=$((bad_artifacts + 1))
    continue
  fi
  if [[ ! -f "${artifact_path}" ]]; then
    fail "claim '${claim_id}' points at missing artifact: ${artifact_path}"
    bad_artifacts=$((bad_artifacts + 1))
    continue
  fi
  if [[ ! -s "${artifact_path}" ]]; then
    fail "claim '${claim_id}' points at an empty artifact: ${artifact_path}"
    bad_artifacts=$((bad_artifacts + 1))
  fi
done < "${registry}"
if [[ "${bad_artifacts}" -eq 0 ]]; then
  echo "  [PASS] all ${#active_ids[@]} active claims resolve to non-empty artifacts"
fi
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
if [[ "${errors}" -gt 0 ]]; then
  echo "RESULT: stale claim check FAILED (${errors} error(s))"
  exit 1
fi

echo "RESULT: stale claim check PASSED"
echo "  ${#active_ids[@]} active claims, ${#retired_ids[@]} retired claims, no stale references."
exit 0
