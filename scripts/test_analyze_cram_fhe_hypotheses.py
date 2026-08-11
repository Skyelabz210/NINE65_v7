#!/usr/bin/env python3
"""Synthetic tests for the CRAM/FHE evidence classifier."""

from __future__ import annotations

import pathlib

from analyze_cram_fhe_hypotheses import (
    CONTRADICTED,
    INCONCLUSIVE,
    SUPPORTED,
    analyze_addition_cost,
    analyze_budget_as_winding,
    analyze_constant_mul_step,
    analyze_key_material,
    analyze_off_by_one,
    analyze_refresh,
    trace_records,
)


def by_id(items: list[dict[str, object]]) -> dict[str, dict[str, object]]:
    return {str(item["claim_id"]): item for item in items}


def main() -> int:
    exploratory = {
        "schema": "nine65-cram-exploratory-probe-v1",
        "metadata": {
            "candidate_winding_is_verified": False,
            "noise_budget_is_accounting_model": True,
        },
        "trace": [
            {
                "step": 0,
                "operation": "add_ct",
                "accounting_cost_mb": 1000,
                "budget_before_mb": 20_000,
                "budget_after_mb": 19_000,
                "correct": True,
                "refreshed_pre": False,
                "refreshed_post": False,
            },
            {
                "step": 1,
                "operation": "mul_ct",
                "accounting_cost_mb": 5000,
                "budget_before_mb": 19_000,
                "budget_after_mb": 14_000,
                "correct": True,
                "refreshed_pre": False,
                "refreshed_post": False,
            },
            {
                "step": 2,
                "operation": "mul_ct",
                "accounting_cost_mb": 5000,
                "budget_before_mb": 14_000,
                "budget_after_mb": 9_000,
                "correct": False,
                "mismatch_delta_mod_t": 1,
                "refreshed_pre": False,
                "refreshed_post": False,
            },
        ],
    }
    comparative = {
        "schema": "nine65-comparative-probe-v1",
        "key_structure": {
            "relinearization_components": 12,
            "decomposition_base": 1024,
            "decomposition_digits": 12,
        },
        "ct_mul_depth": {"entries": []},
    }
    payloads = [
        (pathlib.Path("exploratory.json"), exploratory),
        (pathlib.Path("comparative.json"), comparative),
    ]
    traces = trace_records(payloads)
    refresh_claim, refresh_latency = analyze_refresh(traces)
    claims = by_id(
        [
            analyze_budget_as_winding(payloads),
            analyze_addition_cost(traces),
            analyze_constant_mul_step(traces),
            analyze_off_by_one(traces),
            analyze_key_material(payloads),
            refresh_claim,
            refresh_latency,
        ]
    )
    assert claims["H01"]["verdict"] == INCONCLUSIVE
    assert claims["H02"]["verdict"] == CONTRADICTED
    assert claims["H03"]["verdict"] == SUPPORTED
    assert claims["H04"]["verdict"] == SUPPORTED
    assert claims["H05"]["verdict"] == CONTRADICTED
    assert claims["H06"]["verdict"] == INCONCLUSIVE
    assert claims["H07"]["verdict"] == INCONCLUSIVE
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
