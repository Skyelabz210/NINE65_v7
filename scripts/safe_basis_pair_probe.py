#!/usr/bin/env python3
"""Independent clear pair-precharge oracle and exact public noise budgets.

No encrypted execution or security-estimator claim. The nine alternatives are
prepared independently of the later residual coefficients, by the key holder.
"""

import hashlib
import itertools
import json
import math
from pathlib import Path

ROOT = (2, 3, 5, 7, 11, 13, 17, 19)
TRAYS = (6, 10, 15, 21, 1, 8, 9, 11, 22, 6)
WORK = (998244353, 985661441, 754974721, 469762049)
BOOT = (1811939329, 2113929217, 2130706433, 1107296257, 1711276033)
N, T, ETA = 8192, 65537, 3
Q, QB = math.prod(WORK), math.prod(BOOT)
H = Q // 2
HALF = QB // T // 2
SWITCH = N * ETA * 1023 * sum((p.bit_length() + 9) // 10 for p in BOOT)
PROJECTED = N * (ETA * (2 * N + 1) + 8) + (N - 1) * SWITCH


def nearest(x, q=Q):
    return (x + q // 2) // q


def multiply(a, b):
    exponent = max(0, a.bit_length() + b.bit_length()
                   + (N * T).bit_length() - (QB.bit_length() - 1))
    quadratic = 1 << exponent
    assert quadratic >= (N * T * a * b + QB - 1) // QB
    return ((a + b) * (N * T * (N // 2 + 1) + (T - 1) // 2)
            + quadratic + (N * N + N + 2) // 2 + SWITCH)


def pair(terms, initial=0):
    # CLEAR oracle keys are possible sums, never a proposed encrypted API.
    rows = {}
    for u, v in itertools.product((-1, 0, 1), repeat=2):
        s = initial + terms[0] * u + terms[1] * v
        rows[s] = rows.get(s, 0) + PROJECTED
    return rows


def combine(left, right):
    rows = {}
    first_refusal = None
    for a, ea in left.items():
        for b, eb in right.items():
            error = multiply(ea, eb)
            if error >= HALF and first_refusal is None:
                first_refusal = ("selector multiply", error)
            rows[a + b] = rows.get(a + b, 0) + error
    if first_refusal is None:
        if len(rows) > 27:
            first_refusal = ("state capacity", len(rows))
        elif max(rows.values()) >= HALF:
            first_refusal = ("merged selector", max(rows.values()))
        else:
            outputs = [("carry", sum(abs(nearest(s)) * e for s, e in rows.items()))]
            outputs += [(f"root {p}", sum(s % p * e for s, e in rows.items())) for p in ROOT]
            first_refusal = next(((name, e) for name, e in outputs if e >= HALF), None)
    return rows, first_refusal


def bounds(rows):
    carry = sum(abs(nearest(s)) * e for s, e in rows.items())
    roots = {str(p): sum(s % p * e for s, e in rows.items()) for p in ROOT}
    trays = {str(p): sum(s % p * e for s, e in rows.items()) for p in TRAYS}
    phase = sum((s // 2) % 11 * e for s, e in rows.items())
    return {"rows": len(rows), "carry_bound": carry, "carry_bits": carry.bit_length(),
            "root_bounds": roots, "max_root_bits": max(roots.values()).bit_length(),
            "phase_bound": phase, "tray_bounds": trays,
            "complete_frame_admitted": max(carry, phase, *roots.values(), *trays.values()) < HALF}


def check_identity(q, initial, terms, trits):
    blocks = [initial + terms[0] * trits[0] + terms[1] * trits[1]]
    blocks += [sum(a * u for a, u in zip(terms[j:j+2], trits[j:j+2]))
               for j in range(2, len(terms), 2)]
    g, k = 0, 0
    for block in blocks:
        kb = nearest(block, q)
        gb = block - q * kb
        crossing = nearest(g + gb, q)
        g, k = g + gb - q * crossing, k + kb + crossing
    total = initial + sum(a * u for a, u in zip(terms, trits))
    assert k == nearest(total, q) and g + q * k == total
    for p in ROOT + TRAYS:
        assert (g % p + (k % p) * (q % p)) % p == total % p
    # Each block transports the parity crossing into j11, including negatives.
    parity, phase = 0, 0
    for block in blocks:
        raw = parity + block % 2
        phase = (phase + (block // 2) % 11 + raw // 2) % 11
        parity = raw % 2
    assert (parity, phase) == (total % 2, (total // 2) % 11)


def run():
    pair_cases = 0
    for q in (5, 17, 31):
        h = q // 2
        for initial, a, b in itertools.product((-h, 0, h), range(-h, h+1), range(-h, h+1)):
            for trits in itertools.product((-1, 0, 1), repeat=2):
                check_identity(q, initial, (a, b), trits)
                pair_cases += 1
    assert pair_cases == 34425
    native_cases = 0
    profiles = []
    for sign in (1, -1):
        terms = (sign*H, -sign*H, sign*H, sign*H, sign*H, sign*H, sign*H, sign*H)
        blocks = [pair(terms[:2], sign*H)] + [pair(terms[j:j+2]) for j in (2, 4, 6)]
        four, refusal = combine(blocks[0], blocks[1])
        assert refusal is None
        six, refusal = combine(four, blocks[2])
        assert refusal is None
        right_four, refusal = combine(blocks[2], blocks[3])
        assert refusal is None
        eight, refusal = combine(four, right_four)
        assert refusal is not None and refusal[0].startswith("root ")
        _, sequential_refusal = combine(six, blocks[3])
        assert sequential_refusal is not None and sequential_refusal[0] == "selector multiply"
        for count, rows in ((4, four), (6, six), (8, eight)):
            for trits in itertools.product((-1, 0, 1), repeat=count):
                check_identity(Q, sign*H, terms[:count], trits)
                assert sign*H + sum(a*u for a, u in zip(terms[:count], trits)) in rows
                native_cases += 1
        b4, b6, b8 = bounds(four), bounds(six), bounds(eight)
        assert b4["complete_frame_admitted"] and b6["complete_frame_admitted"]
        assert not b8["complete_frame_admitted"]
        # Same affine/extraction budget as native refresh_coefficient_at.
        rem = QB % T
        affine = N * (ETA * (2*N+1) * N * (T//2) + (N+1)*rem + (rem+1)//2) + (N-1)*SWITCH
        fresh = affine + b4["carry_bound"]
        square = multiply(fresh, fresh)
        assert square < HALF
        source = (1, -1, -1, 1)
        residual_sum = sign*H + sum(a*u for a, u in zip(terms[:4], source))
        assert residual_sum == sign*3*H
        assert abs(residual_sum - Q*nearest(residual_sum)) == H-1
        profiles.append({"sign": sign, "four_terms": b4, "six_terms": b6,
                         "eight_terms": b8,
                         "eight_first_refusal": {"stage": refusal[0], "error_bits": refusal[1].bit_length()},
                         "sequential_next_refusal": {"stage": sequential_refusal[0],
                                                     "error_bits": sequential_refusal[1].bit_length()},
                         "four_term_refresh": {"bound": fresh, "bits": fresh.bit_length(),
                                               "square_bound": square, "square_bits": square.bit_length(),
                                               "source_grid_distance": H-1}})
    assert native_cases == 14742
    # Unstructured coefficients retain exponential support despite pair input.
    arbitrary = [pair((1, 3)), pair((9, 27))]
    rows, refusal = combine(*arbitrary)
    assert len(rows) == 81 and refusal == ("state capacity", 81)
    ct_bytes = 2 * len(BOOT) * N * 8
    # Optimistic *single* selector depth ignores merging/projection. This
    # general pair representation still needs 12 product levels for N terms.
    depth, e = 0, PROJECTED
    levels = []
    while e < HALF:
        levels.append({"product_levels": depth, "error_bits": e.bit_length(), "admitted": True})
        e, depth = multiply(e, e), depth + 1
    levels.append({"product_levels": depth, "error_bits": e.bit_length(), "admitted": False})
    repo = Path(__file__).resolve().parent.parent
    paths = ("scripts/safe_basis_pair_probe.py",
             "crates/nine65/src/ops/safe_basis_pair_tests.rs",
             "crates/nine65/src/ops/safe_basis_composition_tests.rs",
             "crates/nine65/src/ops/safe_basis_precharge_tests.rs",
             "crates/nine65/src/ops/exact_mul.rs", "Cargo.lock")
    return {"schema": "nine65-pair-precharge-v1",
            "baseline": "b0adf341b1c099f45db48785f19d091ce548b213",
            "source_sha256": {p: hashlib.sha256((repo/p).read_bytes()).hexdigest() for p in paths},
            "clear_pair_assignments": pair_cases, "clear_native_composition_assignments": native_cases,
            "half_bound": HALF, "half_bits": HALF.bit_length(), "profiles": profiles,
            "packed_precharge_bytes": 9*ct_bytes, "single_trit_precharge_bytes": 3*ct_bytes,
            "shared_evaluation_key_bytes": 14 * 20 * ct_bytes,
            "full_pair_tree_product_levels": (N//2).bit_length()-1,
            "optimistic_selector_levels": levels,
            "arbitrary_four_term_support": len(rows), "configured_state_limit": 27,
            "safe_basis_roots": 1, "production_refresh_admitted": False}


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
