#!/usr/bin/env bash
set -euo pipefail

date_tag=$(date -u +%Y-%m-%d)
timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
out_md="docs/PERFORMANCE_BASELINE_${date_tag}.md"
out_json="docs/PERFORMANCE_BASELINE_${date_tag}.json"
criterion_json="docs/PERFORMANCE_BASELINE_${date_tag}_criterion.json"
tmp_dir=$(mktemp -d)

cleanup() {
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

mkdir -p docs

run_cmd() {
  local title="$1"
  local cmd="$2"
  local logfile="$3"

  {
    echo
    echo "### ${title}"
    echo
    echo "Command:"
    echo "\`\`\`"
    echo "${cmd}"
    echo "\`\`\`"
    echo
    echo "Output:"
    echo "\`\`\`"
  } >> "${out_md}"

  bash -lc "${cmd}" > "${logfile}" 2>&1
  cat "${logfile}" >> "${out_md}"

  {
    echo "\`\`\`"
    echo
  } >> "${out_md}"
}

extract_ms_from_log() {
  local logfile="$1"
  local label="$2"
  grep -m1 "${label}" "${logfile}" | grep -Eo '[0-9]+\.[0-9]+' | tail -n1
}

extract_depth_total_seconds() {
  local logfile="$1"
  grep -m1 "Total time:" "${logfile}" | grep -Eo '[0-9]+\.[0-9]+'
}

round2() {
  local val="$1"
  awk -v x="${val}" 'BEGIN { printf "%.2f", x + 0.0 }'
}

criterion_log="${tmp_dir}/criterion_timing.log"
secure128_log="${tmp_dir}/secure_128.log"
secure192_log="${tmp_dir}/secure_192.log"
depth128_log="${tmp_dir}/depth_128.log"
depth192_log="${tmp_dir}/depth_192.log"

{
  echo "# Performance Baseline (${date_tag})"
  echo
  echo "Results are hardware- and config-dependent; re-run on your target hardware and"
  echo "record updated baselines when publishing."
  echo
  echo "## Environment"
  echo "- Timestamp (UTC): ${timestamp_utc}"
  echo "- OS: $(uname -a)"
  echo "- CPU: $(lscpu | grep -m1 'Model name' | sed 's/^Model name:[[:space:]]*//')"
  echo "- Rust: $(rustc --version)"
  echo "- Cargo: $(cargo --version)"
  echo "- Commit: $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  echo "- Benchmark profile class: secure (claim-grade)"
  echo
  echo "## Commands"
} > "${out_md}"

run_cmd \
  "Criterion Timing Bench (K-Elimination + Core Arithmetic)" \
  "cargo bench -p nine65 --bench timing --features benchmarks -- --noplot --save-baseline perf_${date_tag}" \
  "${criterion_log}"

python3 scripts/extract_criterion_summary.py --criterion-root target/criterion --out "${criterion_json}"

# Guardrail for B-2: reject zero-time artifacts from machine-readable Criterion output.
python3 - "${criterion_json}" << 'PY'
import json
import sys
path = sys.argv[1]
data = json.load(open(path, "r", encoding="utf-8"))
bad = [b["benchmark_id"] for b in data.get("benchmarks", []) if b.get("median_ns", 0.0) <= 0.0]
if bad:
    print("ERROR: criterion zero-time artifacts detected:", ", ".join(bad))
    raise SystemExit(1)
print("Criterion zero-time scan passed.")
PY

run_cmd \
  "Secure Config FHE Ops (secure_128)" \
  "cargo test -p nine65 --lib --release --features shadow-entropy ops::gso_fhe::arithmetic_benchmarks::benchmark_fhe_ops_secure_128 -- --nocapture" \
  "${secure128_log}"

run_cmd \
  "Secure Config FHE Ops (secure_192)" \
  "cargo test -p nine65 --lib --release --features shadow-entropy ops::gso_fhe::arithmetic_benchmarks::benchmark_fhe_ops_secure_192 -- --nocapture" \
  "${secure192_log}"

run_cmd \
  "Symmetric Max Depth (secure_128)" \
  "cargo test -p nine65 --lib --release ops::gso_fhe::depth_benchmarks::benchmark_symmetric_max_depth_secure_128 -- --nocapture" \
  "${depth128_log}"

run_cmd \
  "Symmetric Max Depth (secure_192)" \
  "cargo test -p nine65 --lib --release ops::gso_fhe::depth_benchmarks::benchmark_symmetric_max_depth_secure_192 -- --nocapture" \
  "${depth192_log}"

enc128=$(extract_ms_from_log "${secure128_log}" "FHE_ENCRYPT")
add128=$(extract_ms_from_log "${secure128_log}" "FHE_ADD")
mul128=$(extract_ms_from_log "${secure128_log}" "FHE_MUL")
dec128=$(extract_ms_from_log "${secure128_log}" "FHE_DECRYPT")

enc192=$(extract_ms_from_log "${secure192_log}" "FHE_ENCRYPT")
add192=$(extract_ms_from_log "${secure192_log}" "FHE_ADD")
mul192=$(extract_ms_from_log "${secure192_log}" "FHE_MUL")
dec192=$(extract_ms_from_log "${secure192_log}" "FHE_DECRYPT")

depth_total_128=$(extract_depth_total_seconds "${depth128_log}")
depth_total_192=$(extract_depth_total_seconds "${depth192_log}")

{
  echo "## Claim-Grade Summary"
  echo
  echo "| Operation | secure_128 (ms) | secure_192 (ms) |"
  echo "|---|---:|---:|"
  echo "| Encrypt | ${enc128} | ${enc192} |"
  echo "| Add | ${add128} | ${add192} |"
  echo "| Mul | ${mul128} | ${mul192} |"
  echo "| Decrypt | ${dec128} | ${dec192} |"
  echo
  echo "| Depth benchmark | secure_128 total (s) | secure_192 total (s) |"
  echo "|---|---:|---:|"
  echo "| symmetric depth-50 | $(round2 "${depth_total_128}") | $(round2 "${depth_total_192}") |"
  echo
  echo "## Criterion Artifacts"
  echo
  echo "- Machine-readable summary: \`${criterion_json}\`"
  echo "- Raw Criterion tree: \`target/criterion/\`"
  echo
  echo "The criterion summary above is now the source for K-Elimination micro-op timings"
  echo "to avoid timer-resolution artifacts (e.g., historical 0 ns rows)."
} >> "${out_md}"

cat > "${out_json}" <<EOF
{
  "generated_at_utc": "${timestamp_utc}",
  "profile_class": "secure",
  "source_files": {
    "markdown_report": "${out_md}",
    "criterion_summary": "${criterion_json}"
  },
  "fhe_ops_ms": {
    "secure_128": {
      "encrypt": ${enc128},
      "add": ${add128},
      "mul": ${mul128},
      "decrypt": ${dec128}
    },
    "secure_192": {
      "encrypt": ${enc192},
      "add": ${add192},
      "mul": ${mul192},
      "decrypt": ${dec192}
    }
  },
  "depth_total_seconds": {
    "secure_128": $(round2 "${depth_total_128}"),
    "secure_192": $(round2 "${depth_total_192}")
  }
}
EOF

echo "Wrote ${out_md}"
echo "Wrote ${out_json}"
echo "Wrote ${criterion_json}"
