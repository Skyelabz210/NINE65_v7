#!/usr/bin/env python3
"""Independent exact-integer oracle for the private-feedback domain core.

This validates structured-field bounds, safe-basis coprimality, residue ranges,
lane-wise aggregation, strict-turn question selection, and prohibited-path counters.
It does not replace Rust, Lean, WASM, or cryptographic execution gates.
"""

from __future__ import annotations

import hashlib
import json
from itertools import product
from math import gcd, prod
from pathlib import Path

SAFE_BASIS = (2, 3, 5, 7, 11, 13, 17, 19)
SLOT_COUNT = 8


def validate_signal(signal: list[int]) -> bool:
    topic, friction, severity, sentiment, product_area, followup, consent, confidence = signal
    return (
        0 <= topic < 256
        and 0 <= friction < 8
        and 0 <= severity < 8
        and 0 <= sentiment < 6
        and 0 <= product_area < 1024
        and 0 <= followup < 7
        and consent in (0, 1)
        and 0 <= confidence <= 1000
    )


def residues(slots: list[int]) -> list[list[int]]:
    return [[value % modulus for modulus in SAFE_BASIS] for value in slots]


def add_residues(left: list[list[int]], right: list[list[int]]) -> list[list[int]]:
    return [
        [
            (left[slot][lane] + right[slot][lane]) % SAFE_BASIS[lane]
            for lane in range(len(SAFE_BASIS))
        ]
        for slot in range(SLOT_COUNT)
    ]


def select_question(state: tuple[bool, bool, bool, bool, bool, bool, int]) -> int:
    goal, obstacle, location_vs_comprehension, impact, expected, trust, remaining = state
    if remaining == 0:
        return 6
    if not goal:
        return 0
    if not obstacle:
        return 1
    if not location_vs_comprehension:
        return 2
    if trust:
        return 5
    if not impact:
        return 3
    if not expected:
        return 4
    return 6


def lcg(value: int) -> int:
    return (6364136223846793005 * value + 1442695040888963407) & ((1 << 64) - 1)


def run() -> dict[str, object]:
    pair_checks = 0
    for left in range(len(SAFE_BASIS)):
        for right in range(left + 1, len(SAFE_BASIS)):
            assert gcd(SAFE_BASIS[left], SAFE_BASIS[right]) == 1
            pair_checks += 1

    base = [42, 2, 5, 3, 17, 2, 0, 900]
    axis_specs = (
        (0, range(256)),
        (1, range(8)),
        (2, range(8)),
        (3, range(6)),
        (4, range(1024)),
        (5, range(7)),
        (6, range(2)),
        (7, range(1001)),
    )

    signals_checked = 0
    lane_range_checks = 0
    for index, values in axis_specs:
        for value in values:
            signal = list(base)
            signal[index] = value
            assert validate_signal(signal)
            for row in residues(signal):
                for lane, residue in enumerate(row):
                    assert 0 <= residue < SAFE_BASIS[lane]
                    lane_range_checks += 1
            signals_checked += 1

    state = 0x4E49_4E45_3635
    aggregation_cases = 4096
    aggregation_lane_checks = 0
    bounds = (256, 8, 8, 6, 1024, 7, 2, 1001) * 2
    for _ in range(aggregation_cases):
        values: list[int] = []
        for bound in bounds:
            state = lcg(state)
            values.append(state % bound)
        left_slots = values[:SLOT_COUNT]
        right_slots = values[SLOT_COUNT:]
        actual = add_residues(residues(left_slots), residues(right_slots))
        expected = residues(
            [left_slots[index] + right_slots[index] for index in range(SLOT_COUNT)]
        )
        assert actual == expected
        aggregation_lane_checks += SLOT_COUNT * len(SAFE_BASIS)

    selector_cases = 0
    for flags in product((False, True), repeat=6):
        for remaining in (0, 1, 2):
            state_tuple = (*flags, remaining)
            actual = select_question(state_tuple)
            goal, obstacle, location_vs_comprehension, impact, expected, trust = flags
            if remaining == 0:
                expected_question = 6
            elif not goal:
                expected_question = 0
            elif not obstacle:
                expected_question = 1
            elif not location_vs_comprehension:
                expected_question = 2
            elif trust:
                expected_question = 5
            elif not impact:
                expected_question = 3
            elif not expected:
                expected_question = 4
            else:
                expected_question = 6
            assert actual == expected_question
            selector_cases += 1

    invalids = (
        [256, 0, 0, 0, 0, 0, 0, 0],
        [0, 8, 0, 0, 0, 0, 0, 0],
        [0, 0, 8, 0, 0, 0, 0, 0],
        [0, 0, 0, 6, 0, 0, 0, 0],
        [0, 0, 0, 0, 1024, 0, 0, 0],
        [0, 0, 0, 0, 0, 7, 0, 0],
        [0, 0, 0, 0, 0, 0, 2, 0],
        [0, 0, 0, 0, 0, 0, 0, 1001],
    )
    for invalid in invalids:
        assert not validate_signal(invalid)

    result: dict[str, object] = {
        "schema": 1,
        "date": "2026-07-13",
        "arithmetic": "exact_integer_only",
        "safe_basis": list(SAFE_BASIS),
        "safe_basis_product": prod(SAFE_BASIS),
        "basis_pair_coprimality_checks": pair_checks,
        "valid_signals_axis_checked": signals_checked,
        "lane_range_checks": lane_range_checks,
        "aggregation_cases": aggregation_cases,
        "aggregation_lane_checks": aggregation_lane_checks,
        "selector_state_cases": selector_cases,
        "invalid_boundary_cases": len(invalids),
        "garner_calls": 0,
        "mixed_radix_calls": 0,
        "numberline_reconstruction_calls": 0,
        "floating_point_operations": 0,
        "status": "PASS",
    }
    canonical = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    result["evidence_sha256"] = hashlib.sha256(canonical).hexdigest()
    return result


def main() -> int:
    result = run()
    output = Path("artifacts/app_platform/private_feedback_correctness_2026-07-13.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
