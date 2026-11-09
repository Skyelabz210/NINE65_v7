#!/usr/bin/env python3
"""Diagnose the November 9 Safe Basis slow-fixture budgets using exact integers.

This is a source-pinned public planning model, not encrypted execution, a new
noise proof, security admission, or evidence that a failing Rust test passes.
Archived probe outputs and their historical source hashes remain unchanged.
"""

from dataclasses import dataclass
import hashlib
from itertools import product
import json
from pathlib import Path

from safe_basis_pair_probe import BOOT, ETA, N, Q, ROOT, T
from safe_basis_three_pair_probe import cube_differences, pair_rows, table_for
from safe_basis_triple_precharge_probe import block_rows, differences, raw

# Reviewed inputs and public planning/table implementations. Refuse silent
# reuse after source drift; update these only after checking the model again.
PINNED_SOURCE_SHA256 = {
    "crates/exact_transcendentals/src/chimera.rs": "90796cb939f799bb77c16caf07016969a01b53981676855b76c0ce2a2c42a08e",
    "crates/nine65/src/ops/exact_mul.rs": "228d23cc8c86eeba566f8d53ced1cc3f7f86445c6bcc4e5828e30df338ea9d2a",
    "crates/nine65/src/ops/safe_basis_composition_tests.rs": "587beb5b665088a416c599ed08c04d49f489d7ee0ff818f23a4838f3cf31ec14",
    "crates/nine65/src/ops/safe_basis_pair_tests.rs": "556768a693eb5b57f8d2155163e371f0cfa4ec6168bebbec8c1899f55f45664f",
    "crates/nine65/src/ops/safe_basis_precharge_tests.rs": "229d94a64276287156276e304d2061e5198498c1d7de03405ec9d77ecb302d1a",
    "crates/nine65/src/ops/safe_basis_sister_tray_tests.rs": "89a541ee1c8f67fadc37a352ee1596873447df5156627a7f3565d64e779f49b6",
    "crates/nine65/src/ops/safe_basis_terminal_tests.rs": "e0fbb4f769d40136658fd00f02f563efe0d696c9d7f3f985f0bd337b11149c8f",
    "crates/nine65/src/ops/safe_basis_triple_precharge_tests.rs": "b4c5c30a434a99b31dfc617b5c35e7c8cb4594e829e5c572b4f44a1c2063e1d9",
    "crates/nine65/src/params/secure_configs.rs": "38e01b8dc2fd05aaa0bb08f8ddeb7d14f46704e7010ead1761d6e34d7ed05c41",
    "scripts/safe_basis_pair_probe.py": "79e8ec7e0161187c26f86eb241aab31ae2049b2c772a888069a5bcd28e56a26d",
    "scripts/safe_basis_three_pair_probe.py": "486c7f43546f467370c60e230597bcc4828d3744f4fe43dd9cca4e7ee842511c",
    "scripts/safe_basis_triple_precharge_probe.py": "09b53ca1ec502ce505b1624b4f426edd6285cac65c4eb64a257afd57868f9841"
}


@dataclass(frozen=True)
class Budget:
    margin: int = 16

    @property
    def qb(self):
        result = 1
        for prime in BOOT:
            result *= prime
        return result

    @property
    def half(self):
        return self.qb // T // 2

    @property
    def switch(self):
        return N * ETA * 1023 * sum((p.bit_length() + 9) // 10 for p in BOOT)

    @property
    def projected(self):
        return self.margin * (N * (ETA * (2 * N + 1) + 8) + (N - 1) * self.switch)

    def multiply(self, left, right):
        np = N * T
        exponent = max(0, left.bit_length() + right.bit_length()
                       + np.bit_length() - (self.qb.bit_length() - 1))
        quadratic = (1 << exponent) if left and right else 0
        return ((left + right) * (np * (N // 2 + 1) + (T - 1) // 2)
                + quadratic + (N * N + N + 2) // 2 + self.switch)

    def observation(self, bound, stage, **context):
        return {"stage": stage, "bound": bound, "bound_bits": bound.bit_length(),
                "threshold": self.half, "threshold_bits": self.half.bit_length(),
                "exact_admitted": bound < self.half,
                "bit_length_admitted": bound.bit_length() < self.half.bit_length(),
                **context}


def checked_sources(root):
    actual = {path: hashlib.sha256((root / path).read_bytes()).hexdigest()
              for path in PINNED_SOURCE_SHA256}
    changed = [path for path in actual if actual[path] != PINNED_SOURCE_SHA256[path]]
    if changed:
        raise ValueError("review model after source drift: " + ", ".join(changed))
    return actual


def projection(rows, value):
    return sum(max(error, 1) * abs(value(total)) for total, error in rows.items())


def pair(budget, terms, initial=0):
    rows = {}
    for left, right in product((-1, 0, 1), repeat=2):
        total = initial + terms[0] * left + terms[1] * right
        rows[total] = rows.get(total, 0) + budget.projected
    return rows


def compose(budget, left, right):
    """Preserve Rust insertion and refusal order, including merged-row checks."""
    rows = {}
    for a, ea in left.items():
        for b, eb in right.items():
            error = budget.multiply(ea, eb) if ea is not None else eb
            if error >= budget.half:
                return None, budget.observation(error, "selector multiply")
            total = a + b
            rows[total] = rows.get(total, 0) + error
            if len(rows) > 27:
                raise ValueError("fixture exceeded the Rust state capacity")
            if rows[total] >= budget.half:
                return None, budget.observation(rows[total], "merged selector")
    outputs = [("carry projection", projection(rows, lambda s: (s + Q // 2) // Q), {})]
    outputs += [("Safe Basis projection", projection(rows, lambda s, p=p: s % p),
                 {"modulus": p}) for p in ROOT]
    for stage, bound, context in outputs:
        if bound >= budget.half:
            return None, budget.observation(bound, stage, **context)
    return rows, None


def pair_failure(budget):
    h = Q // 2
    four, refusal = compose(budget, pair(budget, (h, -h), h), pair(budget, (h, h)))
    if refusal:
        return refusal
    _, refusal = compose(budget, four, pair(budget, (h, h)))
    return refusal


def cube_bound(budget, diff):
    base, a, b, c, ab, ac, bc, abc = diff
    pair_error = budget.multiply(budget.projected, budget.projected)
    triple_error = budget.multiply(pair_error, budget.projected)
    if max(pair_error, triple_error) >= budget.half:
        raise ValueError("three-pair intermediate product no longer admitted")
    return (abs(base) + budget.projected * sum(abs(x) for axis in (a, b, c) for x in axis)
            + pair_error * sum(abs(x) for surface in (ab, ac, bc) for row in surface for x in row)
            + triple_error * sum(abs(x) for surface in abc for row in surface for x in row))


def terminal_carry(budget):
    h = Q // 2
    states = [pair_rows((h - 1, h - 3)), pair_rows((h - 9, h - 27)),
              pair_rows((h - 81, h - 243))]
    diff = cube_differences(table_for(states, h, 1, Q))
    return budget.observation(cube_bound(budget, diff), "three-pair terminal output")


def triple_square(budget):
    h = Q // 2
    weights = (h - 1, h - 3, h - 9, h - 27, h - 81, h - 243)
    states = [block_rows(weights[:3], Q), block_rows(weights[3:], Q)]
    table = [[(h + raw(a, Q) + raw(b, Q) + h) // Q for b in states[1]]
             for a in states[0]]
    base, a, b, mixed = differences(table)
    pair_error = budget.multiply(budget.projected, budget.projected)
    carry = (abs(base) + budget.projected * sum(abs(x) for axis in (a, b) for x in axis)
             + pair_error * sum(abs(x) for row in mixed for x in row))
    remainder = budget.qb % T
    affine = (N * (ETA * (2 * N + 1) * N * (T // 2)
                   + (N + 1) * remainder + (remainder + 1) // 2)
              + (N - 1) * budget.switch)
    refreshed = affine + carry
    return budget.observation(budget.multiply(refreshed, refreshed), "selector multiply",
                              refreshed_bound=refreshed, refreshed_admitted=refreshed < budget.half)


def sister_failure(budget):
    # Positive-sign schedule reaches its third compact-layout proposal first.
    h = Q // 2
    rows = {h: None}
    for index, term in enumerate((h, -h, h), 1):
        rows, refusal = compose(budget, rows, {term * u: budget.projected for u in (-1, 0, 1)})
        if refusal:
            return {**refusal, "step": index}
        phase = projection(rows, lambda s: (s // 2) % 11)
        if phase >= budget.half:
            return budget.observation(phase, "2/11 phase", step=index)
        layouts = ((77, 221), (1, 6, 10, 8, 27, 121, 385, 4199, 6, 65537)) if index < 3 else (
            (6, 10, 15, 21), (1, 8, 9, 11, 22, 6))
        for layout in layouts:
            for modulus in layout:
                bound = projection(rows, lambda s: s % modulus)
                if bound >= budget.half:
                    return budget.observation(bound, "dependent sister view", step=index, modulus=modulus)
    return None


def report(root):
    sources = checked_sources(root)
    budget = Budget()
    return {"schema": "nine65-safe-basis-current-bound-diagnostic-v1",
            "scope": "public integer planning model; no encrypted execution",
            "source_sha256": sources,
            "trace_safety_margin": budget.margin, "projected_selector_bound": budget.projected,
            "half_threshold": budget.half,
            "pair_six_term": pair_failure(budget),
            "terminal_three_pair": terminal_carry(budget),
            "triple_following_square": triple_square(budget),
            "sister_third_step": sister_failure(budget),
            "native_tests_executed": 0, "production_refresh_admitted": False,
            "legacy_clockwork_gate_changed": False}


if __name__ == "__main__":
    print(json.dumps(report(Path(__file__).resolve().parents[1]), indent=2, sort_keys=True))
