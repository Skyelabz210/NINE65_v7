#!/usr/bin/env bash
# cram_ct_gates.sh — DAG-walking gate runner for the CRAM-CT stack.
#
# See docs/CRAM_CT_GATE_DAG.md for the full DAG specification.
#
# Behaviour:
#   - Walks the DAG in topological order.
#   - Every hard-edge dependency must be PASS before its dependants run;
#     otherwise the dependants are reported as BLOCKED (not failed).
#   - Soft-edge dependants run regardless and are tagged WARN if upstream
#     failed.
#   - Final exit code: 0 iff every non-soft gate passed.
#
# Usage:
#   bash scripts/cram_ct_gates.sh                  # run every gate
#   bash scripts/cram_ct_gates.sh B0 T0 R0         # run only listed gates

set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# ─── DAG state ────────────────────────────────────────────────────────────
declare -A GATE_NAME
declare -A GATE_DEPS
declare -A GATE_CMD
declare -A GATE_SOFT          # 1 = soft (failure does not block downstream)
declare -A GATE_STATUS        # PASS | FAIL | BLOCKED | WARN | SKIPPED
declare -A GATE_DURATION
declare -A GATE_NOTES

declare -a GATE_ORDER         # topological order (manually maintained)

register() {
    local id="$1" name="$2" deps="$3" soft="$4" cmd="$5"
    GATE_NAME[$id]="$name"
    GATE_DEPS[$id]="$deps"
    GATE_CMD[$id]="$cmd"
    GATE_SOFT[$id]="$soft"
    GATE_ORDER+=("$id")
}

# ─── Tier 0 — Build ───────────────────────────────────────────────────────
register B0 "debug build" "" 0 \
    "cargo build --workspace --exclude nine65-python --exclude nine65-wasm"
register B1 "release build" "" 0 \
    "cargo build --release --workspace --exclude nine65-python --exclude nine65-wasm"
register B2 "no_std build" "" 0 \
    "cargo build -p exact_transcendentals --no-default-features --release"
register B3 "arb-prec build" "" 0 \
    "cargo build -p exact_transcendentals --features arbitrary-precision --release"

# ─── Tier 1 — Quality ─────────────────────────────────────────────────────
register Q0 "float scan" "B0" 0 \
    "bash scripts/check_no_floats_runtime.sh"
register Q1 "no-panic scan (soft)" "B0" 1 \
    "bash scripts/check_no_panics.sh"

# ─── Tier 2 — Tests ───────────────────────────────────────────────────────
register T0 "exact_transcendentals base" "B1 Q0" 0 \
    "cargo test --release -p exact_transcendentals"
register T1 "exact_transcendentals arb-prec" "B3" 0 \
    "cargo test --release -p exact_transcendentals --features arbitrary-precision"
register T2 "nine65 lib" "B1 Q0" 0 \
    "cargo test --release -p nine65 --lib"
register T3 "cram_ct_wrap" "T2" 0 \
    "cargo test --release -p nine65 --lib cram_ct_wrap"
register T4 "workspace sweep" "B1" 0 \
    "cargo test --release --workspace --exclude nine65-python --exclude nine65-wasm"

# ─── Tier 3 — Spec coverage ───────────────────────────────────────────────
register C0 "phase 0 topology" "T0" 0 \
    "cargo test --release -p exact_transcendentals s8_chimera_v1"
register C1 "phase 1 projection" "T0" 0 \
    "cargo test --release -p exact_transcendentals lane_projector"
register C2 "phase 2 phase-locks" "T0" 0 \
    "cargo test --release -p exact_transcendentals -- lock_witness anchor_k_inverse"
register C3 "phase 3 ops" "T0" 0 \
    "cargo test --release -p exact_transcendentals -- cram_add cram_mul"
register C4 "phase 4 division lanes" "T0" 0 \
    "cargo test --release -p exact_transcendentals -- d1_ d2_ fpd_ router_"
register C5 "phase 5 bootstrap" "T0" 0 \
    "cargo test --release -p exact_transcendentals -- bootstrap_"
register C6 "nine65 wiring" "T3" 0 \
    "cargo test --release -p nine65 --lib cram_ct_wrap::tests"

# ─── Tier 4 — Report ──────────────────────────────────────────────────────
# R0 is special — synthesised at the end.

# ─── Runner ───────────────────────────────────────────────────────────────
run_gate() {
    local id="$1"
    local name="${GATE_NAME[$id]}"
    local deps="${GATE_DEPS[$id]}"
    local soft="${GATE_SOFT[$id]}"
    local cmd="${GATE_CMD[$id]}"

    # Filter: if a positional argument list was given, run only listed gates.
    if [ "$RUN_FILTER" != "" ] && ! [[ " $RUN_FILTER " == *" $id "* ]]; then
        GATE_STATUS[$id]="SKIPPED"
        GATE_DURATION[$id]="-"
        GATE_NOTES[$id]="not in filter"
        return
    fi

    # Check upstream.
    local blocker=""
    for d in $deps; do
        if [ "${GATE_STATUS[$d]:-MISSING}" = "FAIL" ]; then
            blocker="$d"
            break
        fi
    done
    if [ "$blocker" != "" ]; then
        if [ "$soft" = "1" ]; then
            GATE_STATUS[$id]="WARN"
            GATE_NOTES[$id]="upstream $blocker failed (soft)"
        else
            GATE_STATUS[$id]="BLOCKED"
            GATE_DURATION[$id]="-"
            GATE_NOTES[$id]="upstream $blocker failed"
            printf "  [BLOCK] %-3s %-40s upstream %s failed\n" "$id" "$name" "$blocker"
            return
        fi
    fi

    printf "  [RUN  ] %-3s %-40s ... " "$id" "$name"
    local t0=$(date +%s)
    if eval "$cmd" > "/tmp/cram_ct_gate_${id}.log" 2>&1; then
        local t1=$(date +%s)
        GATE_STATUS[$id]="PASS"
        GATE_DURATION[$id]="$((t1 - t0))s"
        GATE_NOTES[$id]=""
        printf "PASS (%ss)\n" "$((t1 - t0))"
    else
        local rc=$?
        local t1=$(date +%s)
        GATE_DURATION[$id]="$((t1 - t0))s"
        if [ "$soft" = "1" ]; then
            GATE_STATUS[$id]="WARN"
            GATE_NOTES[$id]="exit=$rc (soft)"
            printf "WARN (%ss, exit=%s)\n" "$((t1 - t0))" "$rc"
        else
            GATE_STATUS[$id]="FAIL"
            GATE_NOTES[$id]="exit=$rc — see /tmp/cram_ct_gate_${id}.log"
            printf "FAIL (%ss, exit=%s)\n" "$((t1 - t0))" "$rc"
        fi
    fi
}

# ─── Entrypoint ───────────────────────────────────────────────────────────
RUN_FILTER="$*"
echo "=============================================="
echo "  CRAM-CT Gate DAG"
if [ "$RUN_FILTER" != "" ]; then
    echo "  Filter: $RUN_FILTER"
fi
echo "=============================================="

for id in "${GATE_ORDER[@]}"; do
    run_gate "$id"
done

# Synthesise R0 — final report.
echo ""
echo "=============================================="
echo "  R0 — Summary"
echo "=============================================="
printf "%-3s  %-7s  %-9s  %s\n" "ID" "STATUS" "DURATION" "NOTES"
printf "%-3s  %-7s  %-9s  %s\n" "---" "------" "--------" "----"
fail_count=0
warn_count=0
for id in "${GATE_ORDER[@]}"; do
    status="${GATE_STATUS[$id]:-?}"
    duration="${GATE_DURATION[$id]:-?}"
    notes="${GATE_NOTES[$id]:-}"
    printf "%-3s  %-7s  %-9s  %s\n" "$id" "$status" "$duration" "$notes"
    if [ "$status" = "FAIL" ]; then fail_count=$((fail_count + 1)); fi
    if [ "$status" = "WARN" ]; then warn_count=$((warn_count + 1)); fi
done

echo ""
if [ "$fail_count" -eq 0 ]; then
    if [ "$warn_count" -eq 0 ]; then
        echo "ALL GATES GREEN."
        exit 0
    else
        echo "GREEN with $warn_count soft warning(s)."
        exit 0
    fi
else
    echo "GATE DAG FAILED: $fail_count hard failure(s), $warn_count soft warning(s)."
    exit 1
fi
