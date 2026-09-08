#!/usr/bin/env bash
# archive_criterion_run.sh — Archive raw Criterion benchmark output per run.
#
# Problem (issue #77): Criterion writes detailed HTML/JSON reports to
# target/criterion/ by default, and every `cargo bench` invocation silently
# overwrites the previous run's data in place. There is no record of what a
# given commit actually measured once the next benchmark run happens. That is
# exactly how the "152.13 ms" figure in CLAUDE.md/README.md went stale and
# unverifiable (see README.md "Why these replaced the previous figures") —
# nothing preserved the raw output the number was supposedly measured from.
#
# This script does not replace scripts/generate_performance_baseline.sh (which
# extracts and commits a small, citable JSON/Markdown summary under docs/ for
# release-grade baselines). It is the lightweight layer underneath: a
# zero-config way to snapshot the FULL raw target/criterion/ tree — HTML
# reports, per-benchmark estimates.json, sample data, everything Criterion
# wrote — into a timestamped, commit-pinned directory under bench-archive/
# (gitignored; these are large, regenerable build artifacts, not source) so
# that a run's raw evidence survives the next `cargo bench` invocation.
#
# Usage:
#   cargo bench -p nine65 --bench timing --features benchmarks
#   scripts/archive_criterion_run.sh [label]
#
#   [label]  Optional short tag appended to the archive directory name, e.g.
#            "before-rescale-change" / "after-rescale-change". Alphanumeric,
#            '-' and '_' only.
#
# Environment variables:
#   CRITERION_ROOT     Path to Criterion's output root
#                       (default: "${CARGO_TARGET_DIR:-target}/criterion", matching
#                       cargo's own resolution -- so this also works out of the box
#                       when CARGO_TARGET_DIR points somewhere shared, per CLAUDE.md)
#   BENCH_ARCHIVE_DIR  Destination root (default: bench-archive)
#
# Output:
#   <BENCH_ARCHIVE_DIR>/<UTC-timestamp>_<commit>[-dirty][_<label>]/
#     MANIFEST.md              - timestamp, commit, dirty flag, branch, host, toolchain
#     criterion/                - verbatim copy of target/criterion/
#     criterion_summary.json    - scripts/extract_criterion_summary.py output
#
# Exit codes:
#   0 - archived successfully
#   1 - bad usage
#   2 - target/criterion missing/empty, or archive dir already exists

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

label="${1:-}"
if [[ -n "${label}" && ! "${label}" =~ ^[A-Za-z0-9_-]+$ ]]; then
  echo "ERROR: label must be alphanumeric plus '-'/'_' only, got: ${label}" >&2
  exit 1
fi

criterion_root="${CRITERION_ROOT:-${CARGO_TARGET_DIR:-target}/criterion}"
archive_root="${BENCH_ARCHIVE_DIR:-bench-archive}"

if [[ ! -d "${criterion_root}" ]] || [[ -z "$(find "${criterion_root}" -name 'estimates.json' -print -quit 2>/dev/null)" ]]; then
  echo "ERROR: no Criterion output found under '${criterion_root}'." >&2
  echo "Run a benchmark first, e.g.:" >&2
  echo "  cargo bench -p nine65 --bench timing --features benchmarks" >&2
  exit 2
fi

timestamp_utc="$(date -u +%Y%m%dT%H%M%SZ)"
commit_full="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
commit_short="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"

dirty_suffix=""
dirty_flag="no"
if ! git diff --quiet --ignore-submodules HEAD -- 2>/dev/null; then
  dirty_suffix="-dirty"
  dirty_flag="yes"
fi

archive_name="${timestamp_utc}_${commit_short}${dirty_suffix}"
if [[ -n "${label}" ]]; then
  archive_name="${archive_name}_${label}"
fi
archive_dir="${archive_root}/${archive_name}"

if [[ -e "${archive_dir}" ]]; then
  echo "ERROR: archive directory already exists: ${archive_dir}" >&2
  echo "(two runs landed in the same UTC second — re-run, or pass a distinct label)" >&2
  exit 2
fi

mkdir -p "${archive_dir}"
cp -R "${criterion_root}" "${archive_dir}/criterion"

summary_json="${archive_dir}/criterion_summary.json"
if command -v python3 >/dev/null 2>&1; then
  python3 "${SCRIPT_DIR}/extract_criterion_summary.py" \
    --criterion-root "${criterion_root}" \
    --out "${summary_json}" || echo "WARNING: extract_criterion_summary.py failed; raw copy still archived." >&2
else
  echo "WARNING: python3 not found; skipping criterion_summary.json (raw copy still archived)." >&2
fi

bench_count="$(find "${criterion_root}" -name 'estimates.json' -path '*/new/*' | wc -l | tr -d '[:space:]')"

{
  echo "# Criterion Run Archive"
  echo
  echo "- Timestamp (UTC): ${timestamp_utc}"
  echo "- Commit: ${commit_full}"
  echo "- Branch: ${branch}"
  echo "- Working tree dirty at archive time: ${dirty_flag}"
  echo "- OS: $(uname -a)"
  if command -v lscpu >/dev/null 2>&1; then
    echo "- CPU: $(lscpu | grep -m1 'Model name' | sed 's/^Model name:[[:space:]]*//')"
  fi
  echo "- Rust: $(rustc --version 2>/dev/null || echo unknown)"
  echo "- Cargo: $(cargo --version 2>/dev/null || echo unknown)"
  echo "- Benchmark IDs archived: ${bench_count}"
  echo "- Source: \`${criterion_root}\` (copied verbatim into \`criterion/\`)"
  echo "- Machine-readable summary: \`criterion_summary.json\` (via scripts/extract_criterion_summary.py)"
  echo
  if [[ "${dirty_flag}" == "yes" ]]; then
    echo "**Warning:** the working tree had uncommitted changes when this run was"
    echo "archived. The commit hash above does not fully pin what was measured —"
    echo "treat these numbers as exploratory, not claim-grade."
    echo
  fi
  echo "Regenerate the small, citable release baseline (committed under docs/)"
  echo "with \`scripts/generate_performance_baseline.sh\` instead of citing this"
  echo "archive directly in README/CLAUDE.md; this archive is the raw evidence"
  echo "behind that baseline, kept so a disputed number can be traced back to"
  echo "what was actually measured."
} > "${archive_dir}/MANIFEST.md"

echo "Archived Criterion output to: ${archive_dir}"
echo "  ${archive_dir}/MANIFEST.md"
echo "  ${archive_dir}/criterion/           (raw HTML + JSON, ${bench_count} benchmark IDs)"
if [[ -f "${summary_json}" ]]; then
  echo "  ${archive_dir}/criterion_summary.json"
fi
