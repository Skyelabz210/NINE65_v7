#!/usr/bin/env python3
"""Research-only Phase-1 carry transducer.

Wires three already-checked pieces into one candidate:

1. The displaced BFV quotient the legacy component switch drops.
2. The evaluator-side 49/2 sister-tray reconstruction of that integer.
3. The scale-locked return budget, which still refuses the next square.

No ciphertext is produced. ``public_phase1_soundness_gate`` is not relaxed.
"""

from scale_locked_carry_tray import plan as scale_plan
from paired_chart_k_elimination import (
    composite_sister_trays_signed_carry,
    report as chart_report,
)


P_INV_MOD_49 = 47


def round_ratio_nearest(numerator: int, denominator: int) -> int:
    """Match the Rust test helper: half away from zero via a positive division."""
    if denominator <= 0:
        raise ValueError("denominator must be positive")
    if numerator >= 0:
        return (numerator + denominator // 2) // denominator
    return -((-numerator + denominator // 2) // denominator)


def displaced_scalar(q: int, t: int, c0: int, c1: int, secret: int) -> dict:
    a0 = round_ratio_nearest(t * c0, q)
    a1 = round_ratio_nearest(t * c1, q)
    r0 = t * c0 - q * a0
    r1 = t * c1 - q * a1
    component = a0 + a1 * secret
    decoded = round_ratio_nearest(t * (c0 + c1 * secret), q)
    carry = round_ratio_nearest(r0 + r1 * secret, q)
    if decoded != component + carry:
        raise AssertionError("scalar displaced identity failed")
    return {
        "component": component,
        "decoded": decoded,
        "k": carry,
        "residues": (r0, r1),
        "already_centered": abs(c0) <= q // 2 and abs(c1) <= q // 2,
    }


def negacyclic(lhs: list[int], rhs: list[int]) -> list[int]:
    if len(lhs) != len(rhs):
        raise ValueError("negacyclic operands differ in length")
    n = len(lhs)
    out = [0] * n
    for i, a in enumerate(lhs):
        for j, b in enumerate(rhs):
            degree = i + j
            if degree < n:
                out[degree] += a * b
            else:
                out[degree - n] -= a * b
    return out


def displaced_polynomial(q: int, t: int, c0: list[int], c1: list[int], secret: list[int]) -> dict:
    a0 = [round_ratio_nearest(t * x, q) for x in c0]
    a1 = [round_ratio_nearest(t * x, q) for x in c1]
    r0 = [t * x - q * a for x, a in zip(c0, a0)]
    r1 = [t * x - q * a for x, a in zip(c1, a1)]
    phase = [x + y for x, y in zip(c0, negacyclic(c1, secret))]
    component = [x + y for x, y in zip(a0, negacyclic(a1, secret))]
    correction = [x + y for x, y in zip(r0, negacyclic(r1, secret))]
    decoded = [round_ratio_nearest(t * x, q) for x in phase]
    carry = [round_ratio_nearest(x, q) for x in correction]
    if decoded != [a + k for a, k in zip(component, carry)]:
        raise AssertionError("polynomial displaced identity failed")
    radius = len(c0) // 2
    return {
        "component": component,
        "decoded": decoded,
        "k": carry,
        "within_radius": all(abs(k) <= radius for k in carry),
    }


def affine_phase2_hits(q: int, t: int, c0: int, c1: int, secrets=(-1, 0, 1)) -> int:
    targets = [round_ratio_nearest(t * (c0 + c1 * s), q) % t for s in secrets]
    hits = 0
    for a0 in range(t):
        for a1 in range(t):
            if all((a0 + a1 * s) % t == target for s, target in zip(secrets, targets)):
                hits += 1
    return hits


def evaluator_signed_carry(y49: int, w49: int, y2: int, w2: int) -> tuple[int, int]:
    """Recover signed K from canonical public residues. No secret, no Z99.

    k49 = ((Y49 - w49) * 47) mod 49
    k2  = (Y2 - w2) mod 2
    c   = (k49 - k2) mod 2
    K   = k49 - 49*c
    """
    if not (0 <= y49 < 49 and 0 <= w49 < 49 and y2 in (0, 1) and w2 in (0, 1)):
        raise ValueError("sister residues are not canonical")
    k49 = ((y49 - w49) * P_INV_MOD_49) % 49
    k2 = (y2 - w2) % 2
    bit = (k49 - k2) % 2
    return k49 - 49 * bit, bit


def candidate() -> dict:
    scalar = displaced_scalar(17, 5, 1, 1, 1)
    if (scalar["decoded"], scalar["component"], scalar["k"]) != (1, 0, 1):
        raise AssertionError("pinned scalar counterexample moved")
    if not scalar["already_centered"]:
        raise AssertionError("counterexample was expected to already be centered")
    polynomial = displaced_polynomial(17, 5, [1, 0], [1, 1], [1, -1])
    if polynomial["decoded"] != [1, 0] or polynomial["k"] != [1, 0] or not polynomial["within_radius"]:
        raise AssertionError("pinned negacyclic counterexample moved")
    if affine_phase2_hits(17, 5, 1, 1) != 0:
        raise AssertionError("an affine Phase 2 unexpectedly realizes the scalar map")

    chart = chart_report()
    if chart["public_refresh_admitted"] or not chart["composite_sister_trays_49_2"]["all_signed_49_2_checks_pass"]:
        raise AssertionError("chart oracle no longer matches its own refusal")

    # Oracle supplies residues; the evaluator function is the only consumer.
    checked = 0
    for z99 in (-15941, -384, -53, 0, 1, 278, 15834):
        sister = composite_sister_trays_signed_carry(z99)
        got, bit = evaluator_signed_carry(
            sister["y_mod_49"], sister["w_mod_49"], sister["y_mod_2"], sister["w_mod_2"]
        )
        if got != sister["k_signed"] or bit != sister["sign_correction_bit"]:
            raise AssertionError(f"evaluator carry diverged at Z99={z99}")
        checked += 1

    budgets = []
    for scale in (121, 5632):
        row = scale_plan(scale)
        cycle = row["return_cycle"]
        if row["public_refresh_admitted"] or cycle["following_dense_square_decodes"]:
            raise AssertionError(f"scale {scale} no longer refuses the following square")
        if not row["same_phase_output_decodes"] or not cycle["returned_decodes"]:
            raise AssertionError(f"scale {scale} lost the carry re-decode")
        budgets.append({
            "scale": scale,
            "residual": row["strict_residual_bound"],
            "return_bits": cycle["returned_v_bits"],
            "square_bits": cycle["following_dense_square_v_bits"],
            "square_decodes": False,
        })

    return {
        "scope": (
            "clear transducer: BFV missing carry, evaluator 49/2 reconstruction, "
            "and the scale-locked square refusal"
        ),
        "scalar_counterexample": {"q": 17, "t": 5, "component": 0, "decoded": 1, "k": 1},
        "negacyclic_k": polynomial["k"],
        "affine_phase2_hits": 0,
        "evaluator_boundary_points": checked,
        "chart_envelope_admitted_by_existing_oracle": chart["composite_sister_trays_49_2"]["source_correlated_checks"],
        "scale_lock": budgets,
        "dense_ciphertext_producer": False,
        "production_gate_relaxed": False,
        "public_refresh_admitted": False,
    }


if __name__ == "__main__":
    import json

    print(json.dumps(candidate(), indent=2))
