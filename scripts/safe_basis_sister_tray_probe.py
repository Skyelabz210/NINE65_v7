#!/usr/bin/env python3
"""Exact reference: one S8 root and arbitrary dependent 2/11 sister views.

Clear algebra/public bounds only. Native encrypted execution is separate.
"""

import hashlib
import json
import math
from pathlib import Path

ROOT = (2, 3, 5, 7, 11, 13, 17, 19)
TARGETS = (1, 6, 10, 8, 27, 121, 77, 221, 385, 4199, 6, 65537)
WORK = (998244353, 985661441, 754974721, 469762049)
BOOT = (1811939329, 2113929217, 2130706433, 1107296257, 1711276033)
N, T, ETA = 8192, 65537, 3
Q = math.prod(WORK)


def row(x, q):
    k = (x + q // 2) // q
    return x - q * k, k


def view(g, k, q, m):
    return (g % m + k % m * (q % m)) % m


def phase(g, k, q):
    b = view(g, k, q, 2)
    a = view(g, k, q, 11)
    return b, ((a - b) * 6) % 11


def transition(x, y, q):
    gl, kl = row(x, q)
    gr, kr = row(y, q)
    crossing = (gl + gr + q // 2) // q
    g, k = gl + gr - q * crossing, kl + kr + crossing
    bl, ul = phase(gl, kl, q)
    br, ur = phase(gr, kr, q)
    b, u = phase(g, k, q)
    assert b == (bl + br) % 2
    assert u == (ul + ur + (bl + br) // 2) % 11
    assert u == ((x + y) // 2) % 11
    assert view(g, k, q, 11) == (b + 2 * u) % 11
    for m in TARGETS:
        assert view(g, k, q, m) == (x + y) % m


def public_bounds(sign):
    qb = math.prod(BOOT)
    half = qb // T // 2
    digits = sum((p.bit_length() + 9) // 10 for p in BOOT)
    switch = N * ETA * 1023 * digits
    projected = N * (ETA * (2 * N + 1) + 8) + (N - 1) * switch

    def multiply(a, b):
        exponent = max(0, a.bit_length() + b.bit_length()
                       + (N * T).bit_length() - (qb.bit_length() - 1))
        quadratic = 2 ** exponent
        assert quadratic >= (N * T * a * b + qb - 1) // qb
        return ((a + b) * (N * T * (N // 2 + 1) + (T - 1) // 2)
                + quadratic + (N * N + N + 2) // 2 + switch)

    def combine(left, right):
        output = {}
        for x, a in left.items():
            for y, b in right.items():
                error = b if a is None else a if b is None else multiply(a, b)
                output[x + y] = output.get(x + y, 0) + error
        return output

    def leaf(coefficient):
        return {coefficient * trit: projected for trit in (-1, 0, 1)}

    def certificate(rows, m):
        # Each ciphertext is a canonical m residue represented under common T.
        return sum((s % m) * error for s, error in rows.items())

    h = Q // 2
    left = combine({sign * h: None}, leaf(sign * h))
    left = combine(left, leaf(-sign * h))
    bounds = {str(m): certificate(left, m) for m in set(TARGETS + ROOT)}
    phase_bound = sum(((s // 2) % 11) * error for s, error in left.items())
    assert max((*bounds.values(), phase_bound)) < half
    right = combine(leaf(sign * h), leaf(sign * h))
    balanced = combine(left, right)
    small_bound = certificate(balanced, 6)
    large_bound = certificate(balanced, 4199)
    assert small_bound < half <= large_bound
    return {"sign": sign, "two_term_rows": len(left), "view_error_bounds": bounds,
            "phase_211_error_bound": phase_bound, "half_scale_bits": half.bit_length(),
            "balanced_four_rows": len(balanced),
            "balanced_four_view_6_bits": small_bound.bit_length(),
            "balanced_four_view_4199_bits": large_bound.bit_length(),
            "mixed_tray_refused_before_evaluation": True}


def run():
    transitions = 0
    for q in (5, 17, 31):
        for x in range(-64, 65):
            for y in range(-64, 65):
                transition(x, y, q)
                transitions += 1
    h = Q // 2
    points = (-2 * Q, -Q, -h, -1, 0, 1, h, Q, 2 * Q)
    for x in points:
        for y in points:
            transition(x, y, Q)
            transitions += 1
    native = 0
    for k in range(-N // 2, N // 2 + 1):
        for g in (-h, 0, h):
            s = g + k * Q  # Oracle only: native S may occupy 132 bits.
            b, u = phase(g, k, Q)
            assert b == s % 2 and u == (s // 2) % 11
            for m in TARGETS + ROOT:
                assert view(g, k, Q, m) == s % m
            native += 1
    assert transitions == 50004 and native == 24579
    assert math.lcm(6, 10, 6, 1) == 30 < 6 * 10
    assert math.lcm(11, 121, 121, 1) == 121
    assert phase(*row(0, Q), Q) == phase(*row(22, Q), Q)
    assert 0 % 5 != 22 % 5  # Two snapshots do not authorize source rebinding.
    assert (1 + 1) // 2 != 1 // 2 + 1 // 2  # Binary crossing is essential.
    repo = Path(__file__).resolve().parent.parent
    sources = ("scripts/safe_basis_sister_tray_probe.py",
               "crates/nine65/src/ops/safe_basis_sister_tray_tests.rs",
               "crates/nine65/src/ops/safe_basis_composition_tests.rs",
               "crates/nine65/src/ops/safe_basis_precharge_tests.rs",
               "crates/exact_transcendentals/src/chimera.rs",
               "crates/exact_transcendentals/src/cram_ct.rs", "Cargo.lock")
    return {"schema": "nine65-one-root-sister-trays-v1",
            "baseline": "128cbc16655c5f038dbc20502f74531d60895217",
            "source_sha256": {p: hashlib.sha256((repo / p).read_bytes()).hexdigest() for p in sources},
            "safe_basis_root_count": 1, "root_moduli": ROOT,
            "dependent_tray_count": 2, "arbitrary_target_moduli": TARGETS,
            "catalogue_views": {"shadow_bridge": 77, "boundary_saturation": 221},
            "phase_quantity": "j=floor(S/2) mod 11, with S=(S mod 2)+2*j modulo 22",
            "checks": {"additive_phase_transitions": transitions,
                       "native_full_carry_range_views": native,
                       "negative_controls": 4},
            "public_bounds": [public_bounds(sign) for sign in (-1, 1)],
            "encoding": "integer view under existing main-Q BFV t=65537; no free plaintext conversion",
            "limits": ["bounded research source-state capability; not cryptographic provenance",
                       "2/11 transition tested for the additive reference quantity, not the full operator fabric",
                       "dependent views add no multiplication depth or fresh noise budget",
                       "general full secret-sum circuit remains unadmitted"],
            "public_refresh_admitted": False}


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
