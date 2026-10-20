#!/usr/bin/env python3
"""Independent clear/public-bound model for atomic encrypted-tray updates.

This models planning/rollback; Rust separately executes the encrypted path.
"""

import hashlib
import itertools
import json
import math
from pathlib import Path

N, T, ETA = 8192, 65537, 3
WORK = (998244353, 985661441, 754974721, 469762049)
BOOT = (1811939329, 2113929217, 2130706433, 1107296257, 1711276033)
ROOT = (2, 3, 5, 7, 11, 13, 17, 19)
WIDE = ((77, 221), (1, 6, 10, 8, 27, 121, 385, 4199, 6, 65537))
COMPACT = ((6, 10, 15, 21), (1, 8, 9, 11, 22, 6))
Q, QB = math.prod(WORK), math.prod(BOOT)
HALF = QB // T // 2
SWITCH = N * ETA * 1023 * sum((p.bit_length() + 9) // 10 for p in BOOT)
INPUT = N * (ETA * (2 * N + 1) + 8) + (N - 1) * SWITCH


def nearest(s, q):
    return (s + q // 2) // q


def phase(s):
    return s % 2, (s // 2) % 11


def multiply(a, b):
    exponent = max(0, a.bit_length() + b.bit_length()
                   + (N * T).bit_length() - (QB.bit_length() - 1))
    quadratic = 2 ** exponent
    assert quadratic >= (N * T * a * b + QB - 1) // QB
    return ((a + b) * (N * T * (N // 2 + 1) + (T - 1) // 2)
            + quadratic + (N * N + N + 2) // 2 + SWITCH)


class Refusal(Exception):
    pass


def plan(rows, coefficient, layouts):
    proposed = {}
    products = 0
    for s, error in rows.items():
        for trit in (-1, 0, 1):
            operand = coefficient * trit
            out = s + operand
            bound = INPUT if error is None else multiply(error, INPUT)
            products += error is not None
            if bound >= HALF:
                raise Refusal("selector multiply")
            proposed[out] = proposed.get(out, 0) + bound
            if proposed[out] >= HALF or len(proposed) > 27:
                raise Refusal("merged selector/capacity")
            bl, ul = phase(s)
            br, ur = phase(operand)
            bo, uo = phase(out)
            assert bo == (bl + br) % 2
            assert uo == (ul + ur + (bl + br) // 2) % 11
    carry = sum(abs(nearest(s, Q)) * e for s, e in proposed.items())
    root_bounds = {str(p): sum((s % p) * e for s, e in proposed.items()) for p in ROOT}
    phase_bound = sum(((s // 2) % 11) * e for s, e in proposed.items())
    if max((carry, phase_bound, *root_bounds.values())) >= HALF:
        raise Refusal("root/carry/phase")
    view_bounds = {}
    for layout in layouts:
        period = math.lcm(*layout)
        assert period > 0
        for m in layout:
            if not 1 <= m <= T:
                raise Refusal("encoding")
            error = sum((s % m) * e for s, e in proposed.items())
            if error >= HALF:
                raise Refusal(f"view {m}: {error.bit_length()} bits")
            view_bounds[str(m)] = error
    return proposed, {"selector_products": products, "rows": len(proposed),
                      "carry_error_bits": carry.bit_length(),
                      "phase_error_bits": phase_bound.bit_length(),
                      "largest_view_error_bits": max(view_bounds.values()).bit_length(),
                      "view_error_bounds": view_bounds,
                      "layout_periods": [math.lcm(*m) for m in layouts]}


def run():
    schedules = []
    for sign in (-1, 1):
        h = Q // 2
        rows = {sign * h: None}
        committed_products = 0
        prefixes = []
        for step, coefficient in enumerate((sign * h, -sign * h, sign * h), 1):
            source = dict(rows)
            old_work = committed_products
            refusal = None
            try:
                proposed, certificate = plan(rows, coefficient, WIDE)
                assert step < 3
                layouts = WIDE
            except Refusal as error:
                assert step == 3
                refusal = str(error)
                assert rows == source and committed_products == old_work
                layouts = COMPACT
                proposed, certificate = plan(rows, coefficient, layouts)
            rows = proposed
            committed_products += certificate["selector_products"]
            prefixes.append({"step": step, "wide_refusal": refusal, **certificate})
        assert committed_products == 24
        assert [p["rows"] for p in prefixes] == [3, 5, 7]
        before_fourth = dict(rows)
        try:
            plan(rows, h, COMPACT)
        except Refusal as error:
            assert str(error) == "selector multiply"
            assert rows == before_fourth and committed_products == 24
        else:
            raise AssertionError("fourth update must not be admitted")
        schedules.append({"sign": sign, "prefixes": prefixes,
                          "committed_selector_products": committed_products,
                          "rejected_proposals_execute_products": 0,
                          "fourth_update_refused": True})

    # Independent exact oracle across every three-trit assignment and both
    # public sign schedules. Equal plaintext on step three does not justify
    # restoring an old input-history/error certificate.
    cases = 0
    h = Q // 2
    for sign in (-1, 1):
        coefficients = (sign * h, -sign * h, sign * h)
        for trits in itertools.product((-1, 0, 1), repeat=3):
            exact = sign * h
            g, k = exact, 0
            for coefficient, trit in zip(coefficients, trits):
                operand = coefficient * trit
                increment = nearest(g + operand, Q)
                g, k = g + operand - Q * increment, k + increment
                exact += operand
                assert k == nearest(exact, Q)
                for layout in WIDE + COMPACT:
                    for m in layout:
                        assert (g % m + k % m * (Q % m)) % m == exact % m
                assert phase(exact) == (exact % 2, ((exact % 11 - exact % 2) * 6) % 11)
            cases += 1
    assert cases == 54
    assert [s["prefixes"][2]["carry_error_bits"] for s in schedules] == [129, 129]
    repo = Path(__file__).resolve().parent.parent
    sources = ("scripts/safe_basis_tray_transition_probe.py",
               "crates/nine65/src/ops/safe_basis_composition_tests.rs",
               "crates/nine65/src/ops/safe_basis_sister_tray_tests.rs", "Cargo.lock")
    return {"schema": "nine65-atomic-tray-transition-v1",
            "baseline": "3198cff3bfb932c90441c27f41d85bb2f0babd8c",
            "source_sha256": {p: hashlib.sha256((repo / p).read_bytes()).hexdigest() for p in sources},
            "safe_basis_roots": 1, "wide_layouts": WIDE, "compact_layouts": COMPACT,
            "half_scale_bits": HALF.bit_length(), "public_schedules": schedules,
            "clear_three_trit_cases": cases, "native_encrypted_execution": "separate Rust probe",
            "scope": "atomic bounded state/tray planning; not full refresh or authenticated production provenance",
            "error_bounds_reset_by_reconfiguration": False, "public_refresh_admitted": False}


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
