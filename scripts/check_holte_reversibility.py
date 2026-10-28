#!/usr/bin/env python3
"""Exact independent checks for HOLTE_REVERSIBILITY.md; standard library only.

Driving digits are iid uniform. Carry states need not be iid. The finite
checks below support the written induction; they are not a formal proof.
Run from any directory: python3 scripts/check_holte_reversibility.py
"""

from fractions import Fraction
from math import comb, factorial
import json


def require(condition, message):
    # Preserve checks when the interpreter is run with -O.
    if not condition:
        raise AssertionError(message)


def sum_counts(n, base):
    """DP convolution of n independent digits, without binomial formulas."""
    counts = [1]
    for _ in range(n):
        next_counts = []
        window = 0
        for total in range(len(counts) + base - 1):
            if total < len(counts):
                window += counts[total]
            if 0 <= total - base < len(counts):
                window -= counts[total - base]
            next_counts.append(window)
        counts = next_counts
    return counts


def transition_counts(n, base):
    counts = sum_counts(n, base)
    matrix = [[0] * n for _ in range(n)]
    for carry in range(n):
        for total, count in enumerate(counts):
            matrix[carry][(carry + total) // base] += count
    return matrix


def eulerian(n):
    row = [1]
    for size in range(2, n + 1):
        row = [
            (j + 1) * (row[j] if j < len(row) else 0)
            + (size - j) * (row[j - 1] if j > 0 else 0)
            for j in range(size)
        ]
    return row


def corner_counts(n, base):
    return (
        comb(2 * base + n - 1, n) - (n + 1) * comb(base + n - 1, n),
        comb(base + n - 2, n),
    )


def gap(n, base):
    t01, t10 = corner_counts(n, base)
    return t01 - (2**n - n - 1) * t10


def factored_gap(n, base):
    common = base * (base - 1) * (base + 1)
    numerator, denominator = {
        4: (common, 6),
        5: (common * (base + 2), 4),
        6: (common * (base + 2) * (23 * base + 64), 120),
        7: (common * (base + 2) * (base + 3) * (3 * base + 10), 30),
        8: (common * (base + 2) * (base + 3) * (67 * base**2 + 512 * base + 990), 1680),
    }[n]
    require(numerator % denominator == 0, f"factored count integrality n={n},M={base}")
    return -(numerator // denominator)


def newton_coefficients(values):
    coefficients = []
    while values:
        coefficients.append(values[0])
        values = [b - a for a, b in zip(values, values[1:])]
    return coefficients


def low_arity_matrix(n, base):
    if n == 1:
        return [[Fraction(1)]]
    if n == 2:
        return [
            [Fraction(base + 1, 2 * base), Fraction(base - 1, 2 * base)],
            [Fraction(base - 1, 2 * base), Fraction(base + 1, 2 * base)],
        ]
    b2 = base * base
    numerators = [
        [b2 + 3 * base + 2, 4 * b2 - 4, b2 - 3 * base + 2],
        [b2 - 1, 4 * b2 + 2, b2 - 1],
        [b2 - 3 * base + 2, 4 * b2 - 4, b2 + 3 * base + 2],
    ]
    return [[Fraction(v, 6 * b2) for v in row] for row in numerators]


def check_dp_grid():
    cases = 0
    defects = {}
    for n in range(1, 13):
        for base in (*range(2, 13), 36):
            matrix = transition_counts(n, base)
            total = base**n
            weights = eulerian(n)
            require(sum(weights) == factorial(n), f"Eulerian mass n={n}")
            for i, row in enumerate(matrix):
                require(sum(row) == total, f"row mass n={n},M={base},i={i}")
            for j in range(n):
                require(
                    sum(weights[i] * matrix[i][j] for i in range(n)) == weights[j] * total,
                    f"stationarity n={n},M={base},j={j}",
                )
            worst = max(
                abs(weights[i] * matrix[i][j] - weights[j] * matrix[j][i])
                for i in range(n) for j in range(n)
            )
            require((worst == 0) == (n <= 3), f"reversibility n={n},M={base}")
            defects[n, base] = Fraction(worst, factorial(n) * total)
            if n <= 3:
                expected = low_arity_matrix(n, base)
                require(
                    [[Fraction(v, total) for v in row] for row in matrix] == expected,
                    f"explicit low-arity matrix n={n},M={base}",
                )
            if n >= 2:
                require((matrix[0][1], matrix[1][0]) == corner_counts(n, base), f"corner identity n={n},M={base}")
                require(weights[1] == 2**n - n - 1, f"Eulerian corner n={n}")
            cases += 1
    require(cases == 144, "DP grid must retain all 144 cases")
    require(defects[4, 2] == Fraction(1, 384), "published n4,M2 defect")
    require(defects[5, 10] == Fraction(99, 400_000), "published n5,M10 defect")
    # A stationary reversible carry process can still be correlated.
    require(Fraction(transition_counts(2, 36)[0][0], 36**2) != Fraction(1, 2), "iid carries are not required by iid digits")
    return cases


def check_bigint_formulas():
    cases = 0
    bases = (*range(2, 65), 127, 256, 65_536)
    for n in range(2, 31):
        for base in bases:
            value = gap(n, base)
            require(value == 0 if n <= 3 else value < 0, f"corner sign n={n},M={base}")
            if 4 <= n <= 8:
                require(value == factored_gap(n, base), f"factored table n={n},M={base}")
            if n == 4:
                require(value == -comb(base + 1, 3), "n4 closed form")
            if n == 5:
                require(value == -6 * comb(base + 2, 4), "n5 closed form")
            if n >= 3:
                g = -value
                b = comb(base + n - 2, n)
                require(
                    (n + 1) * -gap(n + 1, base)
                    == (2 * base + n) * g + (n - 2) * (2**n - n - 1) * b,
                    f"polynomial recurrence n={n},M={base}",
                )
                t = base - 1
                r = Fraction(comb(2 * base + n - 1, n), b)
                h = 2**n + Fraction(n * (n + 1), t)
                factor = 2 - Fraction(n - 2, t + n)
                h_next = 2 ** (n + 1) + Fraction((n + 1) * (n + 2), t)
                require(h_next - h * factor == Fraction((n - 2) * (2**n - n - 1), t + n), f"ratio slack n={n},M={base}")
                require(r <= h and (r == h) == (n == 3), f"ratio bound n={n},M={base}")
            cases += 1
    require(cases == 1914, "bigint grid must retain all 1914 cases")
    return cases


def check_newton_coefficients():
    rows = {}
    for n in range(4, 31):
        coefficients = newton_coefficients([-gap(n, base) for base in range(2, n + 3)])
        require(coefficients[-1] == 0, f"degree cancellation n={n}")
        require(all(c > 0 for c in coefficients[:-1]), f"Newton coefficient positivity n={n}")
        for base in (37, 100, 65_536):
            u = base - 2
            evaluated = sum(c * comb(u, j) for j, c in enumerate(coefficients) if j <= u)
            require(evaluated == -gap(n, base), f"Newton evaluation n={n},M={base}")
        rows[n] = coefficients[:-1]
    require(len(rows) == 27, "Newton grid must retain all 27 arities")
    return rows


def check_centered_chart():
    cases = 0
    for q in range(2, 13):
        start = -(q // 2)
        pairs = [(k, g) for k in range(-3, 4) for g in range(start, start + q)]
        values = [g + k * q for k, g in pairs]
        require(all(a < b for a, b in zip(values, values[1:])), f"centered lexicographic order Q={q}")
        for (k, g), value in zip(pairs, values):
            require((value - start) // q == k, f"centered winding Q={q}")
            require(value - k * q == g, f"centered digit Q={q}")
        cases += len(pairs)
    # Outside a common width-Q chart, lexicographic order can fail.
    require((0, 20) < (1, 0) and 20 > 10, "wide-chart negative control")
    require(cases == 539, "centered grid must retain all 539 states")
    return cases


def main():
    dp_cases = check_dp_grid()
    formula_cases = check_bigint_formulas()
    newton = check_newton_coefficients()
    chart_cases = check_centered_chart()
    bases = (2, 3, 4, 5, 10, 36)
    expected = {
        4: [-1, -4, -10, -20, -165, -7770],
        5: [-6, -30, -90, -210, -2970, -442890],
        6: [-22, -133, -468, -1253, -29106, -13168596],
        7: [-64, -456, -1848, -5600, -205920, -271757304],
        8: [-163, -1341, -6165, -20900, -1177605, -4369748877],
    }
    actual = {n: [gap(n, base) for base in bases] for n in expected}
    require(actual == expected, "n4..8 exact corner table")
    print(json.dumps({
        "status": "pass",
        "dp_grid_cases": dp_cases,
        "bigint_formula_cases": formula_cases,
        "newton_arities_checked": [4, 30],
        "newton_coefficients_n4_to_n8": {n: newton[n] for n in range(4, 9)},
        "gap_table_bases": bases,
        "gap_table_n4_to_n8": actual,
        "centered_chart_states": chart_cases,
        "driving_digits": "iid uniform",
        "iid_carry_output_required": False,
        "proof_scope": "finite checks; see written all-arity induction",
    }, indent=2))


if __name__ == "__main__":
    main()
