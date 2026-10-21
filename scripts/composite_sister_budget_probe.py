#!/usr/bin/env python3
"""Independent exact-integer composite sister-view budget probe.

Clear support integers below are an ORACLE ONLY. The native evaluator projects
from public (remainder,winding) support rows and encrypted selectors; it neither
reconstructs nor decrypts the selected value. No ciphertext modulus changes.
"""

import argparse
from functools import cache
import hashlib
import json
import math
from pathlib import Path
import re

from safe_basis_tray_transition_probe import COMPACT, HALF, Q, T, plan, Refusal


@cache
def composite(m):
    return m >= 4 and any(m % d == 0 for d in range(2, math.isqrt(m) + 1))


def projection_bound(rows, modulus):
    return sum((s % modulus) * max(error or 0, 1) for s, error in rows.items())


def choose(rows, lower, upper, cap, half=HALF, encoding=T):
    if lower < 4 or lower > upper or upper > encoding or not 0 <= cap < half:
        raise ValueError("invalid composite-view budget")
    for m in range(upper, lower - 1, -1):
        if not composite(m) or len({s % m for s in rows}) != len(rows):
            continue
        bound = projection_bound(rows, m)
        if bound <= cap:
            return m, bound
    raise Refusal("no composite preserves support within budget")


def run(native_log=None):
    # First derive small-domain expectations by direct enumeration of the
    # requested feasible set, not by duplicating the descending selection.
    cases = 0
    for left in range(-8, 9):
        for right in range(left + 1, 10):
            rows = {left: 2, right: 3}
            for cap in (0, 1, 3, 8, 19, 39):
                feasible = {m: 2 * (left % m) + 3 * (right % m)
                            for m in range(4, 17)
                            if any(m % d == 0 for d in range(2, m))
                            and left % m != right % m
                            and 2 * (left % m) + 3 * (right % m) <= cap}
                if feasible:
                    m, bound = choose(rows, 4, 16, cap, half=40, encoding=17)
                    assert m == max(feasible) and bound == feasible[m]
                else:
                    try:
                        choose(rows, 4, 16, cap, half=40, encoding=17)
                    except Refusal:
                        pass
                    else:
                        raise AssertionError("infeasible view accepted")
                cases += 1
    assert cases == 918
    assert choose({1: 1, 11: 1}, 4, 12, 4) == (9, 3)
    assert projection_bound({1: 1, 11: 1}, 6) > projection_bound({1: 1, 11: 1}, 9)
    for args in ((3, 12, 4), (12, 4, 4), (4, T + 1, 4), (4, 12, HALF), (4, 12, -1)):
        try:
            choose({1: 1, 11: 1}, *args)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid request accepted")

    selections = []
    expected = {-1: (315, 194, 158, 78, 45), 1: (300, 206, 123, 93, 65)}
    for sign in (-1, 1):
        h = Q // 2
        rows = {sign * h: None}
        for coefficient in (sign * h, -sign * h, sign * h):
            rows, _ = plan(rows, coefficient, COMPACT)
        before = dict(rows)
        assert len(rows) == 7
        for divisor, expected_m in zip((2, 3, 4, 5, 8), expected[sign]):
            cap = HALF // divisor
            m, bound = choose(rows, 35, T, cap)
            assert m == expected_m
            assert choose(rows, m, m, bound) == (m, bound)
            try:
                choose(rows, m, m, bound - 1)
            except Refusal:
                pass
            else:
                raise AssertionError("one-unit budget violation accepted")
            # Prove maximality over the entire requested interval, with no
            # modulus-monotonicity or bit-length-only admission shortcut.
            assert all(not composite(other)
                       or len({s % other for s in rows}) < len(rows)
                       or projection_bound(rows, other) > cap
                       for other in range(m + 1, T + 1))
            selections.append({"sign": sign, "cap_divisor": divisor,
                               "modulus": m, "error_bound": str(bound),
                               "cap": str(cap), "distinct_support": len(rows),
                               "view_period": m})
        try:
            choose(rows, 35, T, HALF // 16)
        except Refusal:
            pass
        else:
            raise AssertionError("minimum modulus silently weakened")
        assert rows == before  # neither the source nor its bounds were reset
        try:
            plan(rows, h, COMPACT)
        except Refusal as error:
            assert str(error) == "selector multiply"
        else:
            raise AssertionError("view sizing fabricated a fourth multiplication level")

    matched = 0
    if native_log is not None:
        log = native_log.read_text()
        pattern = (r"composite tray: sign=(-?1), cap=half/(\d+), modulus=(\d+), "
                   r"error_bits=(\d+), distinct_support=(\d+), bound_hex=([0-9a-f]{128})")
        actual = {}
        for sign, divisor, modulus, bits, distinct, bound_hex in re.findall(pattern, log):
            key = (int(sign), int(divisor))
            assert key not in actual
            bound = int(bound_hex, 16)
            assert bound.bit_length() == int(bits)
            actual[key] = (int(modulus), bound, int(distinct))
        for row in selections:
            assert actual.pop((row["sign"], row["cap_divisor"])) == (
                row["modulus"], int(row["error_bound"]), row["distinct_support"])
            matched += 1
        assert not actual and matched == 10
        assert re.search(r"test result: ok\. [1-9]\d* passed; 0 failed; 0 ignored", log)

    repo = Path(__file__).resolve().parent.parent
    sources = ["scripts/composite_sister_budget_probe.py",
               "scripts/safe_basis_tray_transition_probe.py",
               "crates/nine65/src/ops/safe_basis_sister_tray_tests.rs",
               "crates/nine65/src/ops/safe_basis_composition_tests.rs", "Cargo.lock"]
    return {"schema": "nine65-composite-sister-budget-v1", "clear_budget_cases": cases,
            "source_sha256": {p: hashlib.sha256((repo / p).read_bytes()).hexdigest() for p in sources},
            "selected_composites": selections, "native_bound_cross_checks": matched,
            "minimum_modulus": 35, "maximum_modulus": T,
            "all_support_states_distinguished": True, "exact_budget_boundary_checked": True,
            "safe_basis_roots": 1, "ciphertext_modulus_changed": False,
            "source_error_reset": False, "fourth_update_refused": True,
            "native_public_refresh_admitted": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-log", type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.native_log), indent=2))
