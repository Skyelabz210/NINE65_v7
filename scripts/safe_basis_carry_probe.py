#!/usr/bin/env python3
"""Exact certificates for aligned-frame and local ternary carry experiments.

Fractional phase arithmetic is a clear oracle. Rust separately tests actual
encrypted evaluation. No full refresh or full secret-sum circuit is admitted.
"""

from fractions import Fraction
import hashlib
import itertools
import json
import math
from pathlib import Path

WORK = (998244353, 985661441, 754974721, 469762049)
BOOT = (1811939329, 2113929217, 2130706433, 1107296257)
N, T, ETA = 8192, 65537, 3
Q, QB = math.prod(WORK), math.prod(BOOT)


def nearest(x, q):
    return (x + q // 2) // q


def phase(residues, basis):
    product = math.prod(basis)
    return sum(Fraction(pow(product // m, -1, m) * r, m)
               for r, m in zip(residues, basis)) % 1


def local_coefficients(q, a, b, t):
    assert abs(a) <= q // 2 and abs(b) <= q // 2
    minus, plus = nearest(a - b, q), nearest(a + b, q)
    return ((plus + minus) * pow(2, -1, t) % t,
            (plus - minus) * pow(2, -1, t) % t)


def run():
    torus_cases = local_cases = native_local = 0
    patterns = set()
    for q, t in itertools.product((17, 23, 31), (5, 7, 11)):
        basis = (q, t)
        for k in range(-t // 2 + 1, t // 2 + 1):
            for g in range(-q // 2 + 1, q // 2 + 1):
                s = k * q + g
                value = phase([s % m for m in basis], basis)
                assert value == Fraction(s % (q * t), q * t)
                assert (value * t + Fraction(1, 2)).__floor__() % t == k % t
                # The normalized input residual is RETAINED exactly.
                difference = value * t - k
                difference -= t * ((difference + Fraction(t, 2)) // t)
                assert difference == Fraction(g, q)
                torus_cases += 1
    for q in (5, 17, 31):
        for a, b in itertools.product(range(-q // 2 + 1, q // 2 + 1), repeat=2):
            coefficients = local_coefficients(q, a, b, T)
            patterns.add(coefficients)
            for secret in (-1, 0, 1):
                actual = (coefficients[0] * secret * secret + coefficients[1] * secret) % T
                assert actual == nearest(a + b * secret, q) % T
                local_cases += 1
    h = Q // 2
    for a, b, secret in itertools.product((-h, -h + 1, -1, 0, 1, h - 1, h),
                                         (-h, -h + 1, -1, 0, 1, h - 1, h), (-1, 0, 1)):
        u, v = local_coefficients(Q, a, b, T)
        assert (u * secret * secret + v * secret) % T == nearest(a + b * secret, Q) % T
        native_local += 1
    assert len(patterns) == 5

    basis = WORK + (T,)
    product = Q * T
    assert product > (N + 1) * (Q - 1)
    native_cases = 0
    for k in range(-N // 2, N // 2 + 1):
        for g in (-Q // 8 + 1, 0, Q // 8):
            s = k * Q + g
            value = phase([s % m for m in basis], basis)
            assert (value * T + Fraction(1, 2)).__floor__() % T == k % T
            native_cases += 1
    coordinate_bounds = []
    assembly_error = 0
    for m in basis:
        weight = pow(product // m, -1, m)
        remainder = QB % m
        error = ETA * (2 * N + 1) * N * (m // 2) + (N + 1) * remainder + (remainder + 1) // 2
        assembly_error += weight * error
        coordinate_bounds.append({"plaintext_modulus": m, "CRT_weight": weight, "error_bound": error})
    assert assembly_error < QB // T // 4
    # Even one unit of encryption error flips the aligned carry at the cut.
    # Its native guarantee therefore needs a supported input residual bound.
    cut_phase = Fraction(QB * h, Q * T)
    assert nearest((cut_phase + 1) * T, QB) == 1
    assert nearest(h, Q) == 0

    input_bound = ETA * (2 * N + 1) + 1
    # The four boot primes each need four base-2^10 digits.
    digits = sum((p.bit_length() + 9) // 10 for p in BOOT)
    switch_bound = N * ETA * (2 ** 10 - 1) * digits
    factor = N * T * (N // 2 + 1) + (T - 1) // 2
    quadratic = (N * T * input_bound ** 2 + QB - 1) // QB
    square_bound = 2 * input_bound * factor + quadratic + (N * N + N + 2) // 2 + switch_bound
    local_bound = (T - 1) // 2 * (square_bound + input_bound)
    half_delta = QB // T // 2
    assert local_bound < half_delta

    # The second local crossing depends on the UPDATED encrypted remainder.
    # Resetting the public state for every term double-counts this carry.
    q, r, v = 17, 8, 8
    assert nearest(r + v + v, q) == 1
    assert nearest(r + v, q) + nearest(r + v, q) == 2

    repo = Path(__file__).resolve().parent.parent
    paths = ("scripts/safe_basis_carry_probe.py",
             "crates/nine65/src/ops/safe_basis_carry_tests.rs",
             "crates/nine65/src/ops/safe_basis_precharge_tests.rs",
             "crates/nine65/src/ops/expanded_bootstrap.rs",
             "crates/nine65/src/ops/exact_mul.rs",
             "crates/nine65/src/arithmetic/main_only_base_ext.rs", "Cargo.lock")
    return {
        "schema": "nine65-safe-basis-carry-v1",
        "scope": "clear exact certificates; actual encrypted tests recorded separately",
        "source_sha256": {p: hashlib.sha256((repo / p).read_bytes()).hexdigest() for p in paths},
        "checks": {"rational_aligned_phase_cases": torus_cases,
                   "native_aligned_phase_cases": native_cases,
                   "exhaustive_local_ternary_cases": local_cases,
                   "native_local_boundary_cases": native_local,
                   "distinct_local_gates": len(patterns),
                   "negative_controls": 2},
        "aligned_frame": {"work_Q": Q, "boot_Q": QB, "boot_primes": BOOT,
                          "payload_bits": product.bit_length(), "coordinate_bounds": coordinate_bounds,
                          "assembly_error_bound": assembly_error,
                          "retained_residual_law": "Ecarry = Qboot*g/(Qwork*t) + Eassembly",
                          "removes_input_noise": False},
        "local_ternary_gate": {"N": N, "t": T, "multiplicative_depth": 1,
                               "input_error_bound": input_bound, "square_error_bound": square_bound,
                               "output_error_bound": local_bound, "half_delta": half_delta,
                               "output_error_bits": local_bound.bit_length(),
                               "half_delta_bits": half_delta.bit_length(),
                               "covers": "public centered r0,r1 and one freshly precharged ternary coefficient",
                               "covers_full_secret_sum": False},
        "public_refresh_admitted": False,
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
