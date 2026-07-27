#!/usr/bin/env python3
"""Focused exact tests for the comparative ranking gate."""

from __future__ import annotations

from cram_compare_results import COMPATIBILITY_FIELDS, group_report


def record(implementation: str, failures: int) -> dict[str, object]:
    compatibility = {
        "scheme": "BFV-legacy-single-modulus",
        "plaintext_semantics": "scalar-mod-t",
        "target_security_bits": 0,
        "security_estimator": "comparison-only-parameter-shape",
        "n": 4096,
        "log_q_bits": 90,
        "plaintext_modulus": 65_537,
        "slots": 1,
        "refresh_kind": "none",
        "hardware_fingerprint": "same-machine",
        "threads": 1,
        "build_profile": "release",
        "sample_policy": "repeated-process integer average",
    }
    assert tuple(compatibility) == COMPATIBILITY_FIELDS
    return {
        "schema": "fhe-comparison-record-v1",
        "implementation": implementation,
        "version": "test",
        "operation": "mul_ct",
        "samples_ns": [10, 20, 30],
        "correctness": {"trials": 3, "failures": failures},
        "compatibility": compatibility,
        "provenance": {},
    }


def main() -> int:
    passing = group_report([record("left", 0), record("right", 0)])
    comparison = passing[0]["comparisons"][0]
    assert comparison["correctness_gate"] is True
    assert comparison["ranking_allowed"] is True
    assert comparison["left_over_right_median"] == {"numerator": 1, "denominator": 1}

    blocked = group_report([record("left", 0), record("right", 1)])
    comparison = blocked[0]["comparisons"][0]
    assert comparison["correctness_gate"] is False
    assert comparison["ranking_allowed"] is False
    assert comparison["left_over_right_median"] is None
    assert comparison["blocked_reason"]

    empty_trials = record("right", 0)
    empty_trials["correctness"] = {"trials": 0, "failures": 0}
    blocked = group_report([record("left", 0), empty_trials])
    comparison = blocked[0]["comparisons"][0]
    assert comparison["ranking_allowed"] is False
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
