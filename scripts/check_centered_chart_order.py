#!/usr/bin/env python3
"""Exhaust the centered-chart order and occupancy claims on the S6 window.

This is an exact, clear-integer verifier. The loop knows S only as a test
oracle: it produces the input chart g and an authentic independent S mod R.
Recovery then uses only those inputs, Q, R, and the declared interval.
Neither g nor the independent anchor is extracted from encrypted data here.
This script constructs no FHE comparison, encrypted maximum, or carry circuit.

For P = Q*R = 30030 the window is [-15015, 15014]. The Q-chart is
[lo, lo+Q), lo = -(Q//2), and S = g + Q*K. Lexicographic order means K
first and g second. Occupancy runs below encode every sheet count exactly;
the pair-tie probability is for two independent uniform choices in the window.
"""

import argparse
from collections import Counter
from fractions import Fraction
from itertools import combinations
import json
from math import gcd, prod
from pathlib import Path


S6 = (2, 3, 5, 7, 11, 13)
P = prod(S6)
LOWER = -(P // 2)
UPPER = P // 2 - 1


def ceil_div(numerator, denominator):
    return -((-numerator) // denominator)


def recover_sheet(g, anchor_residue, q, r, inverse_q):
    """Recover the unique interval-admitted K from authentic chart/anchor data."""
    k_mod_r = ((anchor_residue - g) * inverse_q) % r
    first = ceil_div(LOWER - g, q)
    last = (UPPER - g) // q
    assert last - first + 1 == r
    recovered = first + (k_mod_r - first) % r
    assert first <= recovered <= last
    return recovered


def occupancy_runs(counts):
    """Lossless run encoding: each integer K from first through last has count."""
    items = sorted(counts.items())
    runs = []
    for sheet, count in items:
        if runs and sheet == runs[-1]["last"] + 1 and count == runs[-1]["count"]:
            runs[-1]["last"] = sheet
        else:
            runs.append({"first": sheet, "last": sheet, "count": count})
    return runs


def check_split(main_primes):
    q = prod(main_primes)
    r = P // q
    assert q > 1 and r > 1 and gcd(q, r) == 1
    inverse_q = pow(q, -1, r)
    lo = -(q // 2)
    previous_pair = None
    counts = Counter()
    comparisons = 0
    for source in range(LOWER, UPPER + 1):
        chart = ((source - lo) % q) + lo
        sheet = (source - chart) // q
        assert lo <= chart < lo + q
        assert chart + q * sheet == source
        pair = (sheet, chart)
        if previous_pair is not None:
            assert previous_pair < pair
            comparisons += 1
        previous_pair = pair
        counts[sheet] += 1

        # Source is a test oracle, not an input to recover_sheet.
        recovered = recover_sheet(chart, source % r, q, r, inverse_q)
        assert recovered == sheet

    assert sum(counts.values()) == P
    raw_pair_ties = sum(count * count for count in counts.values())
    probability = Fraction(raw_pair_ties, P * P)
    if q % 2 == 0:
        expected = Counter({sheet: q for sheet in range(-(r // 2), r // 2 + 1)})
        assert counts == expected
        assert probability == Fraction(1, r)
        formula_numerator = r * q * q
    else:
        half_r = r // 2
        expected = Counter({sheet: q for sheet in range(-half_r + 1, half_r)})
        expected[-half_r] = (q + 1) // 2
        expected[half_r] = (q - 1) // 2
        assert counts == expected
        formula_numerator = (
            (r - 1) * q * q + ((q + 1) // 2) ** 2 + ((q - 1) // 2) ** 2
        )
    assert raw_pair_ties == formula_numerator
    assert probability == Fraction(formula_numerator, (q * r) ** 2)
    return {
        "Q": q,
        "R": r,
        "main_primes": list(main_primes),
        "states_checked": P,
        "adjacent_order_checks": comparisons,
        "bounded_sheet_recoveries": P,
        "sheet_occupancy_runs": occupancy_runs(counts),
        "pair_tie_numerator": raw_pair_ties,
        "pair_tie_denominator": P * P,
        "pair_tie_probability": str(probability),
        "occupancy_formula": "uniform" if q % 2 == 0 else "two_partial_end_sheets",
    }


def check_published_rows(results):
    by_q = {row["Q"]: row for row in results}
    published = [
        (15015, 2, Fraction(169087669, 450900450)),
        (10010, 3, Fraction(1, 3)),
        (6006, 5, Fraction(1, 5)),
        (5005, 6, Fraction(22962523, 150300150)),
        (210, 143, Fraction(1, 143)),
        (143, 210, Fraction(4284124009, 901800900000)),
    ]
    checked = []
    for q, r, supplied in published:
        actual = by_q[q]
        assert actual["R"] == r
        computed = Fraction(actual["pair_tie_numerator"], actual["pair_tie_denominator"])
        matches = supplied == computed
        if q == 143:
            # Preserve the corrected arithmetic, rather than the supplied typo.
            assert actual["sheet_occupancy_runs"] == [
                {"first": -105, "last": -105, "count": 72},
                {"first": -104, "last": 104, "count": 143},
                {"first": 105, "last": 105, "count": 71},
            ]
            assert computed == Fraction(4284066, 901800900)
            assert not matches
        else:
            assert matches
        checked.append({
            "Q": q,
            "R": r,
            "supplied": str(supplied),
            "computed": str(computed),
            "matches": matches,
            "supplied_minus_computed": str(supplied - computed),
        })
    return checked


def verify():
    results = [
        check_split(primes)
        for size in range(1, len(S6))
        for primes in combinations(S6, size)
    ]
    assert len(results) == 62
    rows = check_published_rows(results)
    summary = {
        "splits_checked": len(results),
        "states_checked": sum(row["states_checked"] for row in results),
        "adjacent_order_checks": sum(row["adjacent_order_checks"] for row in results),
        "bounded_sheet_recoveries": sum(row["bounded_sheet_recoveries"] for row in results),
        "published_rows_checked": len(rows),
        "published_row_corrections": [row for row in rows if not row["matches"]],
    }
    return {
        "summary": summary,
        "basis": list(S6),
        "window": {"lower_inclusive": LOWER, "upper_inclusive": UPPER},
        "scope": "Finite clear arithmetic with preexisting authentic chart and anchor inputs; no encrypted extraction or FHE ordering construction.",
        "splits": results,
        "published_rows": rows,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Write the complete exact JSON report here.")
    arguments = parser.parse_args()
    if not __debug__:
        parser.error("This verifier requires assertions; run Python without -O or -OO.")
    report = verify()
    if arguments.output is not None:
        arguments.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report["summary"], indent=2))
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
