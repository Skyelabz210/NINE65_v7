#!/usr/bin/env python3
"""Independent arbitrary-integer fixtures for the secure_128 dual rescale test.

This is a test oracle, not a production reconstruction path. It computes the
signed integer X before reduction, rounds X/Delta exactly, then reports the
main and anchor residues of both the true quotient and its canonical mod-Q
representative. No floating point or cryptographic secret is used.
"""

import json
from math import prod


MAIN = [998244353, 985661441, 754974721, 469762049]
ANCHOR = [
    2013265921, 2281701377, 2483027969, 2885681153,
    3221225473, 3221422081, 3222306817,
]
T = 65537
Q = prod(MAIN)
DELTA = Q // T
K_MAGNITUDE = (1 << 145) + 12345


def round_away_zero(x: int, divisor: int) -> int:
    magnitude = (abs(x) + divisor // 2) // divisor
    return -magnitude if x < 0 else magnitude


def vector(name: str, k: int, v: int) -> dict:
    x = v + k * Q
    y = round_away_zero(x, DELTA)
    canonical = y % Q
    return {
        "name": name,
        "k": str(k),
        "v": str(v),
        "input_main": [x % p for p in MAIN],
        "input_anchor": [x % a for a in ANCHOR],
        "expected_main": [canonical % p for p in MAIN],
        "canonical_output_anchor": [canonical % a for a in ANCHOR],
        "true_quotient_anchor": [y % a for a in ANCHOR],
    }


if __name__ == "__main__":
    assert K_MAGNITUDE < prod(ANCHOR) // 2
    assert DELTA * T + Q % T == Q
    cases = [
        vector("positive_large_k_zero_v", K_MAGNITUDE, 0),
        vector("negative_large_k_upper_v", -K_MAGNITUDE, Q - 1),
    ]
    assert all(
        case["canonical_output_anchor"] != case["true_quotient_anchor"]
        for case in cases
    )
    print(json.dumps({"schema": "nine65-large-phase-oracle-v1", "q": str(Q),
                      "delta": str(DELTA), "main": MAIN, "anchor": ANCHOR,
                      "cases": cases}, indent=2))
