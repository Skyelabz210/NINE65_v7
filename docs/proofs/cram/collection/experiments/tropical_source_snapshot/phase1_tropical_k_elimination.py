#!/usr/bin/env python3
"""Exact oracle connecting BFV component rounding to tropical K-Elimination.

This checks the Phase 1 carry identity on bounded full-polynomial examples.
It supplies the secret only to this clear oracle: it does not implement the
same-source encrypted producer for S mod A and g mod A, and cannot admit
public refresh.
"""

from __future__ import annotations

import random


Q_SOURCE = 5_000_003
PLAINTEXT = 65_537
N = 32
LOW_TRAY = 1 << 15
ADJACENT_TRAY = LOW_TRAY + 1
PHASE_TRAY = PLAINTEXT
CARRY_BOUND = N // 2
SEED = 0x5048_4153_454B


def nearest(value: int, denominator: int) -> int:
    """Nearest integer with ties rounded toward positive infinity."""
    return (2 * value + denominator) // (2 * denominator)


def negacyclic(left: list[int], right: list[int]) -> list[int]:
    if len(left) != len(right):
        raise ValueError("polynomial degree mismatch")
    n = len(left)
    result = [0] * n
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            degree = i + j
            sign = 1 if degree < n else -1
            result[degree % n] += sign * a * b
    return result


def center(value: int, modulus: int) -> int:
    residue = value % modulus
    return residue - modulus if residue > modulus // 2 else residue


def eliminate_carry(source_residue: int, centered_residue: int, tray: int) -> int:
    """Recover K from S=Q*K+g, given same-source residues modulo tray."""
    inverse = pow(Q_SOURCE, -1, tray)
    residue = ((source_residue - centered_residue) * inverse) % tray
    return residue - tray if residue > tray // 2 else residue


def one_polynomial_case(
    c0: list[int], c1: list[int], secret: list[int]
) -> tuple[int, int]:
    if not (len(c0) == len(c1) == len(secret) == N):
        raise ValueError("polynomial degree mismatch")
    if any(not 0 <= value < Q_SOURCE for value in c0 + c1):
        raise ValueError("component is outside the canonical Q interval")
    if any(value not in (-1, 0, 1) for value in secret):
        raise ValueError("secret is not ternary")

    def component_round(poly: list[int]) -> tuple[list[int], list[int]]:
        rounded = [nearest(value * PLAINTEXT, Q_SOURCE) for value in poly]
        residual = [
            value * PLAINTEXT - Q_SOURCE * quotient
            for value, quotient in zip(poly, rounded)
        ]
        assert all(2 * abs(value) <= Q_SOURCE for value in residual)
        return rounded, residual

    a0, r0 = component_round(c0)
    a1, r1 = component_round(c1)

    # The secret-dependent displacement left by independently switching c0,c1.
    s = [a + b for a, b in zip(r0, negacyclic(r1, secret))]
    carry = [nearest(value, Q_SOURCE) for value in s]
    centered_s = [value - Q_SOURCE * k for value, k in zip(s, carry)]
    assert all(2 * abs(value) <= Q_SOURCE for value in centered_s)
    assert all(abs(value) <= CARRY_BOUND for value in carry)

    # Directly compare the two switches. Round the combined Q-phase, and
    # compare it to the independently rounded components under the same key.
    c1_secret = negacyclic(c1, secret)
    component_phase = [
        (x + y) % PLAINTEXT
        for x, y in zip(a0, negacyclic(a1, secret))
    ]
    combined_switch = [
        nearest(center(x + y, Q_SOURCE) * PLAINTEXT, Q_SOURCE) % PLAINTEXT
        for x, y in zip(c0, c1_secret)
    ]
    assert all(
        (component + k) % PLAINTEXT == combined
        for component, k, combined in zip(component_phase, carry, combined_switch)
    )

    # One Safe-Basis low tray and one arbitrary phase-locked tray both recover
    # the signed hidden carry from the exact same S,g pair.
    for tray in (LOW_TRAY, ADJACENT_TRAY, PHASE_TRAY):
        assert tray > 2 * CARRY_BOUND
        for source, centered, expected in zip(s, centered_s, carry):
            assert eliminate_carry(source % tray, centered % tray, tray) == expected

    return max(map(abs, carry)), sum(value != 0 for value in carry)


def _boundary_components() -> list[int]:
    values = {0, 1, Q_SOURCE // 2, Q_SOURCE - 2, Q_SOURCE - 1}
    for quotient in (0, 1, PLAINTEXT // 2, PLAINTEXT - 2, PLAINTEXT - 1):
        boundary = ((2 * quotient + 1) * Q_SOURCE) // (2 * PLAINTEXT)
        values.update(max(0, min(Q_SOURCE - 1, boundary + offset)) for offset in (-1, 0, 1))
    return sorted(values)


def run() -> dict:
    if Q_SOURCE % 2 == 0 or PLAINTEXT % 2 == 0:
        raise AssertionError("this oracle expects odd source and plaintext moduli")
    for tray in (LOW_TRAY, ADJACENT_TRAY, PHASE_TRAY):
        if Q_SOURCE % tray == 0:
            raise AssertionError("K-Elimination tray is not coprime to source Q")

    rng = random.Random(SEED)
    secrets = [
        [1] * N,
        [-1] * N,
        [1 if i % 2 == 0 else -1 for i in range(N)],
        [1 if i == 5 else -1 if i == 23 else 0 for i in range(N)],
        [rng.choice((-1, 0, 1)) for _ in range(N)],
    ]
    cases = 0
    max_abs_carry = 0
    nonzero_carries = 0
    boundary = _boundary_components()
    for secret_index, secret in enumerate(secrets):
        for trial in range(8):
            c0 = [rng.randrange(Q_SOURCE) for _ in range(N)]
            c1 = [rng.randrange(Q_SOURCE) for _ in range(N)]
            if trial == 0:
                for i, value in enumerate(boundary):
                    c0[i] = value
                    c1[N - 1 - i] = Q_SOURCE - 1 - value
            observed, nonzero = one_polynomial_case(c0, c1, secret)
            max_abs_carry = max(max_abs_carry, observed)
            nonzero_carries += nonzero
            cases += 1

    # The full N/2 signed corridor, including centered-cell endpoints, is
    # checked independently of which carries the deterministic samples hit.
    half_q = Q_SOURCE // 2
    g_values = (-half_q, -half_q + 1, 0, half_q - 1, half_q)
    corridor_checks = 0
    for carry in range(-CARRY_BOUND, CARRY_BOUND + 1):
        for g in g_values:
            source = Q_SOURCE * carry + g
            assert nearest(source, Q_SOURCE) == carry
            for tray in (LOW_TRAY, ADJACENT_TRAY, PHASE_TRAY):
                assert eliminate_carry(source % tray, g % tray, tray) == carry
                corridor_checks += 1

    return {
        "schema": "nine65-phase1-tropical-k-elimination-v1",
        "scope": "clear full-polynomial identity oracle; no encrypted producer or refresh admission",
        "source_q": Q_SOURCE,
        "plaintext_modulus": PLAINTEXT,
        "ring_degree": N,
        "carry_bound": CARRY_BOUND,
        "safe_basis_tray": LOW_TRAY,
        "adjacent_sister_tray": ADJACENT_TRAY,
        "phase_locked_tray": PHASE_TRAY,
        "polynomial_cases": cases,
        "coefficient_cases": cases * N,
        "maximum_observed_abs_carry": max_abs_carry,
        "nonzero_carries": nonzero_carries,
        "full_signed_corridor_residue_checks": corridor_checks,
        "component_switch_difference_equals_tropical_carry": True,
        "all_three_trays_recover_signed_carry": True,
        "same_source_encrypted_pair_produced": False,
        "public_refresh_admitted": False,
    }


if __name__ == "__main__":
    import json

    print(json.dumps(run(), indent=2))
