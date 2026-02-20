#!/usr/bin/env bash
#
# generate_summary_json.sh - Generate summary.json for V6 proof artifacts
#
# Usage:
#   ./generate_summary_json.sh [OPTIONS]
#
# Options:
#   --rust-tests <json>      Rust test results JSON (from cargo test --message-format=json)
#   --python-tests <json>    Python test results JSON (from pytest --json-report)
#   --regression-dir <path>  Directory to scan for regression tests (default: ./security_proofs)
#   --output <path>          Output path for summary.json (default: ./summary.json)
#   --claim-registry <path>  Path to claim registry file (default: ./QA/claim_registry.json)
#   --help                   Show this help message
#
# Environment Variables:
#   RUST_TESTS_JSON          Alternative to --rust-tests
#   PYTHON_TESTS_JSON        Alternative to --python-tests
#   REGRESSION_DIR           Alternative to --regression-dir
#   OUTPUT_PATH              Alternative to --output
#   CLAIM_REGISTRY_PATH      Alternative to --claim-registry
#
# Exit Codes:
#   0 - Success
#   1 - Invalid arguments
#   2 - Git operations failed
#   3 - JSON generation failed
#

set -euo pipefail

# Script directory for relative path resolution
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Default values
RUST_TESTS_JSON=""
PYTHON_TESTS_JSON=""
REGRESSION_DIR="${PROJECT_ROOT}/security_proofs"
OUTPUT_PATH="${PROJECT_ROOT}/summary.json"
CLAIM_REGISTRY_PATH="${PROJECT_ROOT}/QA/claim_registry.json"

# Color codes for output (disabled in CI)
if [[ -t 1 ]] && [[ -z "${CI:-}" ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    NC=''
fi

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

# Show help
show_help() {
    head -30 "$0" | tail -25 | sed 's/^# \?//'
    exit 0
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --rust-tests)
                RUST_TESTS_JSON="$2"
                shift 2
                ;;
            --python-tests)
                PYTHON_TESTS_JSON="$2"
                shift 2
                ;;
            --regression-dir)
                REGRESSION_DIR="$2"
                shift 2
                ;;
            --output)
                OUTPUT_PATH="$2"
                shift 2
                ;;
            --claim-registry)
                CLAIM_REGISTRY_PATH="$2"
                shift 2
                ;;
            --help|-h)
                show_help
                ;;
            *)
                log_error "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done

    # Apply environment variable overrides
    RUST_TESTS_JSON="${RUST_TESTS_JSON:-${RUST_TESTS_JSON:-}}"
    PYTHON_TESTS_JSON="${PYTHON_TESTS_JSON:-${PYTHON_TESTS_JSON:-}}"
    REGRESSION_DIR="${REGRESSION_DIR:-${REGRESSION_DIR:-}}"
    OUTPUT_PATH="${OUTPUT_PATH:-${OUTPUT_PATH:-}}"
    CLAIM_REGISTRY_PATH="${CLAIM_REGISTRY_PATH:-${CLAIM_REGISTRY_PATH:-}}"
}

# Get git information
get_git_info() {
    local commit_sha branch dirty_status

    # Get commit SHA
    if ! commit_sha="$(git -C "${PROJECT_ROOT}" rev-parse HEAD 2>/dev/null)"; then
        log_warn "Could not determine git commit SHA"
        commit_sha="unknown"
    fi

    # Get branch name
    if ! branch="$(git -C "${PROJECT_ROOT}" rev-parse --abbrev-ref HEAD 2>/dev/null)"; then
        log_warn "Could not determine git branch"
        branch="unknown"
    fi

    # Check if working tree is dirty
    if git -C "${PROJECT_ROOT}" diff-index --quiet HEAD -- 2>/dev/null; then
        dirty_status="false"
    else
        dirty_status="true"
    fi

    echo "{\"commit_sha\":\"${commit_sha}\",\"branch\":\"${branch}\",\"dirty\":${dirty_status}}"
}

# Parse Rust test results
parse_rust_tests() {
    local json_input="$1"
    local passed=0
    local failed=0
    local ignored=0
    local total=0

    if [[ -z "${json_input}" ]] || [[ ! -f "${json_input}" ]]; then
        echo "{\"passed\":0,\"failed\":0,\"ignored\":0,\"total\":0}"
        return
    fi

    # Parse cargo test JSON output
    # Count test events (ok, failed, ignored)
    if command -v jq &>/dev/null; then
        # Use jq to count matching events directly
        passed=$(jq -r 'select(.type == "test" and .event == "ok") | .event' "${json_input}" 2>/dev/null | wc -l | tr -d '[:space:]')
        failed=$(jq -r 'select(.type == "test" and .event == "failed") | .event' "${json_input}" 2>/dev/null | wc -l | tr -d '[:space:]')
        ignored=$(jq -r 'select(.type == "test" and .event == "ignored") | .event' "${json_input}" 2>/dev/null | wc -l | tr -d '[:space:]')
        total=$((passed + failed + ignored))
    else
        # Fallback: grep-based counting
        passed=$(grep -c '"event": *"ok"' "${json_input}" 2>/dev/null || echo 0)
        failed=$(grep -c '"event": *"failed"' "${json_input}" 2>/dev/null || echo 0)
        ignored=$(grep -c '"event": *"ignored"' "${json_input}" 2>/dev/null || echo 0)
        total=$((passed + failed + ignored))
    fi

    echo "{\"passed\":${passed},\"failed\":${failed},\"ignored\":${ignored},\"total\":${total}}"
}

# Parse Python test results
parse_python_tests() {
    local json_input="$1"
    local passed=0
    local failed=0
    local skipped=0
    local total=0

    if [[ -z "${json_input}" ]] || [[ ! -f "${json_input}" ]]; then
        echo "{\"passed\":0,\"failed\":0,\"skipped\":0,\"total\":0}"
        return
    fi

    if command -v jq &>/dev/null; then
        # Parse pytest JSON report
        passed=$(jq -r '.tests | map(select(.outcome == "passed")) | length' "${json_input}" 2>/dev/null || echo 0)
        failed=$(jq -r '.tests | map(select(.outcome == "failed" or .outcome == "error")) | length' "${json_input}" 2>/dev/null || echo 0)
        skipped=$(jq -r '.tests | map(select(.outcome == "skipped")) | length' "${json_input}" 2>/dev/null || echo 0)
        total=$((passed + failed + skipped))
    else
        # Fallback: grep-based counting
        passed=$(grep -c '"outcome": *"passed"' "${json_input}" 2>/dev/null || echo 0)
        failed=$(grep -c '"outcome": *"failed"' "${json_input}" 2>/dev/null || echo 0)
        skipped=$(grep -c '"outcome": *"skipped"' "${json_input}" 2>/dev/null || echo 0)
        total=$((passed + failed + skipped))
    fi

    echo "{\"passed\":${passed},\"failed\":${failed},\"skipped\":${skipped},\"total\":${total}}"
}

# Scan regression directories
scan_regression() {
    local scan_dir="$1"
    local dirs_scanned=0
    local test_count=0
    local violations=0

    if [[ ! -d "${scan_dir}" ]]; then
        echo "{\"dirs_scanned\":0,\"test_count\":0,\"violations\":0}"
        return
    fi

    # Count directories scanned (trim whitespace)
    dirs_scanned=$(find "${scan_dir}" -type d 2>/dev/null | wc -l | tr -d '[:space:]')

    # Count test files (trim whitespace)
    test_count=$(find "${scan_dir}" -type f \( -name "*.rs" -o -name "*.py" -o -name "*.sh" \) 2>/dev/null | wc -l | tr -d '[:space:]')

    # Count potential violations (TODO, FIXME, HACK, XXX markers)
    # Use grep -o to count occurrences, then count lines
    violations=$(grep -r -o -E "(TODO|FIXME|HACK|XXX)" "${scan_dir}" --include="*.rs" --include="*.py" --include="*.sh" 2>/dev/null | wc -l | tr -d '[:space:]')
    # Handle case where grep returns nothing
    if [[ -z "${violations}" ]] || [[ "${violations}" == "" ]]; then
        violations=0
    fi

    echo "{\"dirs_scanned\":${dirs_scanned},\"test_count\":${test_count},\"violations\":${violations}}"
}

# Verify claims from registry
verify_claims() {
    local registry_path="$1"
    local claims_verified="true"
    local proofs_valid="true"
    local invariants_hold="true"
    local performance_met="true"
    local security_properties="true"

    if [[ ! -f "${registry_path}" ]]; then
        log_warn "Claim registry not found: ${registry_path}" >&2
        echo "{\"claims_verified\":false,\"proofs_valid\":false,\"invariants_hold\":false,\"performance_met\":false,\"security_properties\":false}"
        return
    fi

    # Check claim registry for verification status
    if command -v jq &>/dev/null; then
        # Check if all claims are marked as verified
        local unverified
        unverified=$(jq -r '.claims // [] | map(select(.verified == false or .verified == null)) | length' "${registry_path}" 2>/dev/null || echo 0)
        if [[ "${unverified}" -gt 0 ]]; then
            claims_verified="false"
        fi

        # Check proof status
        local invalid_proofs
        invalid_proofs=$(jq -r '.claims // [] | map(select(.proof_status == "invalid" or .proof_status == "pending")) | length' "${registry_path}" 2>/dev/null || echo 0)
        if [[ "${invalid_proofs}" -gt 0 ]]; then
            proofs_valid="false"
        fi

        # Check invariants
        local failed_invariants
        failed_invariants=$(jq -r '.claims // [] | map(select(.invariant_status == "failed")) | length' "${registry_path}" 2>/dev/null || echo 0)
        if [[ "${failed_invariants}" -gt 0 ]]; then
            invariants_hold="false"
        fi

        # Check performance benchmarks
        local perf_missed
        perf_missed=$(jq -r '.claims // [] | map(select(.performance_met == false)) | length' "${registry_path}" 2>/dev/null || echo 0)
        if [[ "${perf_missed}" -gt 0 ]]; then
            performance_met="false"
        fi

        # Check security properties
        local sec_violations
        sec_violations=$(jq -r '.claims // [] | map(select(.security_verified == false)) | length' "${registry_path}" 2>/dev/null || echo 0)
        if [[ "${sec_violations}" -gt 0 ]]; then
            security_properties="false"
        fi
    fi

    echo "{\"claims_verified\":${claims_verified},\"proofs_valid\":${proofs_valid},\"invariants_hold\":${invariants_hold},\"performance_met\":${performance_met},\"security_properties\":${security_properties}}"
}

# Determine overall verdict
determine_verdict() {
    local rust_tests="$1"
    local python_tests="$2"
    local regression="$3"
    local claims="$4"

    local verdict="PASS"

    # Check for test failures
    if command -v jq &>/dev/null; then
        local rust_failed python_failed regress_violations
        rust_failed=$(echo "${rust_tests}" | jq -r '.failed // 0' 2>/dev/null || echo 0)
        python_failed=$(echo "${python_tests}" | jq -r '.failed // 0' 2>/dev/null || echo 0)
        regress_violations=$(echo "${regression}" | jq -r '.violations // 0' 2>/dev/null || echo 0)

        if [[ "${rust_failed}" -gt 0 ]] || [[ "${python_failed}" -gt 0 ]]; then
            verdict="FAIL"
        fi

        # Check claim verification
        local claims_ok
        claims_ok=$(echo "${claims}" | jq -r 'if (.claims_verified and .proofs_valid and .invariants_hold) then "true" else "false" end' 2>/dev/null || echo "false")
        if [[ "${claims_ok}" != "true" ]]; then
            verdict="FAIL"
        fi
    else
        # Fallback: simple string matching
        if echo "${rust_tests}" | grep -q '"failed":[1-9]'; then
            verdict="FAIL"
        fi
        if echo "${python_tests}" | grep -q '"failed":[1-9]'; then
            verdict="FAIL"
        fi
    fi

    echo "${verdict}"
}

# Generate ISO 8601 timestamp
get_timestamp() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}

# Escape string for JSON
json_escape() {
    local str="$1"
    # Basic JSON escaping
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/\\r}"
    str="${str//$'\t'/\\t}"
    echo "${str}"
}

# Main function
main() {
    parse_args "$@"

    log_info "Generating V6 proof artifacts summary..."
    log_info "Project root: ${PROJECT_ROOT}"
    log_info "Output path: ${OUTPUT_PATH}"

    # Ensure output directory exists
    local output_dir
    output_dir="$(dirname "${OUTPUT_PATH}")"
    if [[ ! -d "${output_dir}" ]]; then
        log_info "Creating output directory: ${output_dir}"
        mkdir -p "${output_dir}"
    fi

    # Gather all information
    log_info "Collecting git information..."
    local git_info
    git_info="$(get_git_info)"

    log_info "Parsing Rust test results..."
    local rust_tests
    rust_tests="$(parse_rust_tests "${RUST_TESTS_JSON}")"

    log_info "Parsing Python test results..."
    local python_tests
    python_tests="$(parse_python_tests "${PYTHON_TESTS_JSON}")"

    log_info "Scanning regression directories..."
    local regression
    regression="$(scan_regression "${REGRESSION_DIR}")"

    log_info "Verifying claims..."
    local claims
    claims="$(verify_claims "${CLAIM_REGISTRY_PATH}")"

    log_info "Determining verdict..."
    local verdict
    verdict="$(determine_verdict "${rust_tests}" "${python_tests}" "${regression}" "${claims}")"

    # Generate timestamp
    local timestamp
    timestamp="$(get_timestamp)"

    # Build JSON output
    log_info "Generating summary.json..."

    cat > "${OUTPUT_PATH}" << EOF
{
  "schema_version": "1.0",
  "generated_at": "${timestamp}",
  "git": ${git_info},
  "test_summary": {
    "rust": ${rust_tests},
    "python": ${python_tests}
  },
  "regression_scan": ${regression},
  "claim_verification": ${claims},
  "verdict": "${verdict}"
}
EOF

    # Validate JSON if jq is available
    if command -v jq &>/dev/null; then
        if jq empty "${OUTPUT_PATH}" 2>/dev/null; then
            log_info "JSON validation: PASSED"
        else
            log_error "JSON validation: FAILED"
            exit 3
        fi
    fi

    # Pretty-print if jq is available
    if command -v jq &>/dev/null; then
        local temp_file
        temp_file="$(mktemp)"
        jq '.' "${OUTPUT_PATH}" > "${temp_file}" && mv "${temp_file}" "${OUTPUT_PATH}"
    fi

    log_info "Summary generated successfully: ${OUTPUT_PATH}"
    log_info "Verdict: ${verdict}"

    # Exit with appropriate code based on verdict
    if [[ "${verdict}" == "FAIL" ]]; then
        exit 1
    fi

    exit 0
}

# Run main function
main "$@"
