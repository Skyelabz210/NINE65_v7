#!/usr/bin/env python3
"""Exact clear-oracle experiments for the refresh carry research note.

No ciphertext evaluator, secret-key access, floating point, or refresh
admission. Toy secrets below are public exhaustive test inputs.
"""

import hashlib
import itertools
import json
from pathlib import Path

from bounded_digit_polynomial import certify, construct, evaluate, self_test


def nearest(value, modulus):
    if modulus < 3 or modulus % 2 == 0:
        raise ValueError("the oracle requires an odd positive modulus")
    return (value + modulus // 2) // modulus


def centered(value, modulus):
    return value - modulus * nearest(value, modulus)


def carry(a, b, modulus):
    return (centered(a, modulus) + centered(b, modulus)
            - centered(a + b, modulus)) // modulus


def carry_step(state, term, modulus):
    """Advance one centered representative and return its integer winding."""
    if centered(state, modulus) != state:
        raise ValueError("carry state must be the centered representative")
    next_state = centered(state + term, modulus)
    winding = (state + term - next_state) // modulus
    return next_state, winding


def carry_block(state, terms, modulus):
    """Compose local carry steps; equivalent to one translation by sum(terms)."""
    winding = 0
    for term in terms:
        state, increment = carry_step(state, term, modulus)
        winding += increment
    return state, winding


def wide_carry_requirements(n, q, base):
    """Exact range/encoding floor for aggregating K before one quotient."""
    half = (q - 1) // 2
    sum_bound = (n + 1) * half
    minimum_plaintext_modulus = 2 * sum_bound + 1
    exponent, modulus = 1, base
    while modulus < minimum_plaintext_modulus:
        exponent += 1
        modulus *= base
    carry_radius = (sum_bound + half) // q
    return sum_bound, minimum_plaintext_modulus, exponent, modulus, carry_radius


def convolution(a, b):
    n = len(a)
    result = [0] * n
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            result[(i + j) % n] += x * y * (1 if i + j < n else -1)
    return result


def component_case(c0, c1, secret, q, t):
    a0 = [nearest(t * v, q) for v in c0]
    a1 = [nearest(t * v, q) for v in c1]
    r0 = [t * v - q * a for v, a in zip(c0, a0)]
    r1 = [t * v - q * a for v, a in zip(c1, a1)]
    phase = [x + y for x, y in zip(c0, convolution(c1, secret))]
    affine = [x + y for x, y in zip(a0, convolution(a1, secret))]
    residual = [x + y for x, y in zip(r0, convolution(r1, secret))]
    correction = [nearest(v, q) for v in residual]
    target = [nearest(t * v, q) for v in phase]
    assert target == [a + k for a, k in zip(affine, correction)]
    assert [v % t for v in target] == [
        nearest(t * (v % q), q) % t for v in phase
    ]
    # Independently accumulate the centered-section defect, including each
    # sign from negacyclic multiplication. For ternary s, individual signed
    # residuals are already centered. Their accumulated carry is K_j.
    for j, expected in enumerate(correction):
        terms = [r0[j]]
        for i, value in enumerate(r1):
            k = (j - i) % len(secret)
            terms.append(value * secret[k] * (1 if i + k < len(secret) else -1))
        representative = winding = 0
        for term in terms:
            winding += carry(representative, term, q)
            representative = centered(representative + term, q)
        assert winding == expected
    return any(a % t != v % t for a, v in zip(affine, target))


def run():
    cocycles = scalar_cases = ring_cases = affine_failures = 0
    transfer_cases = local_rule_cases = extension_cases = carry_bound_cases = 0
    for q in (3, 5, 17, 31):
        for a, b, c in itertools.product(range(q), repeat=3):
            assert carry(a, b, q) + carry(a + b, c, q) == (
                carry(b, c, q) + carry(a, b + c, q)
            )
            cocycles += 1
    # The cocycle is a composable lift of translations on Z/QZ. Exhaustively
    # check that a block's winding equals the one-shot quotient and is
    # independent of where a sequence is split into sub-blocks.
    for q in (3, 5, 7):
        radius = q // 2
        terms = range(-radius, radius + 1)
        for initial in range(-radius, radius + 1):
            for length in range(4):
                for sequence in itertools.product(terms, repeat=length):
                    final_state, total_winding = carry_block(initial, sequence, q)
                    direct_state = centered(initial + sum(sequence), q)
                    direct_winding = (initial + sum(sequence) - direct_state) // q
                    assert (final_state, total_winding) == (direct_state, direct_winding)
                    for split in range(length + 1):
                        middle, left_winding = carry_block(initial, sequence[:split], q)
                        final, right_winding = carry_block(middle, sequence[split:], q)
                        assert (final, left_winding + right_winding) == (
                            final_state, total_winding
                        )
                        transfer_cases += 1
    # For centered x,v, a single representative crossing has only three
    # possible windings. This is the exact piecewise-threshold local rule.
    for q in (3, 5, 17, 31):
        # A full circuit of the residue generator crosses the centered cut
        # exactly once: the section cocycle represents the non-split integer
        # lift Z -> Z/QZ, rather than a carry removable by a homomorphic choice
        # of centered representatives.
        generator_winding = sum(carry(a, 1, q) for a in range(q))
        assert generator_winding == 1
        extension_cases += q
        radius = q // 2
        for state, term in itertools.product(range(-radius, radius + 1), repeat=2):
            _, actual = carry_step(state, term, q)
            total = state + term
            threshold = int(total >= radius + 1) - int(total <= -radius - 1)
            assert actual == threshold
            assert actual in (-1, 0, 1)
            local_rule_cases += 1
    # Phase-1 K is a rounded sum of one centered residual plus a ternary
    # negacyclic combination of N centered residuals. The l1 extremum is
    # (N+1)*h_Q, and for the listed even N / odd Q tuples its rounded quotient
    # reaches exactly N/2, the sharp signed carry radius.
    for n, q in (
        (2, 5), (4, 17), (8, 31),
        (8192, 348959453350711275087786864768188417),
    ):
        half = (q - 1) // 2
        max_sum = (n + 1) * half
        radius = (max_sum + half) // q
        assert radius == n // 2
        assert nearest(max_sum, q) == radius
        assert nearest(-max_sum, q) == -radius
        carry_bound_cases += 1
    native_q = 348959453350711275087786864768188417
    native_sum_bound, minimum_plaintext, wide_exp, wide_modulus, native_k = (
        wide_carry_requirements(8192, native_q, 65537)
    )
    assert native_k == 4096
    assert minimum_plaintext.bit_length() == 132
    assert wide_exp == 9 and wide_modulus.bit_length() == 145
    assert native_q.bit_length() == 119 < wide_modulus.bit_length()
    for q, t in ((5, 3), (17, 5), (31, 7)):
        values = range(-q // 2 + 1, q // 2 + 1)
        for a, b, s in itertools.product(values, values, (-1, 0, 1)):
            affine_failures += component_case([a], [b], [s], q, t)
            scalar_cases += 1
    for c0 in itertools.product(range(-2, 3), repeat=2):
        for c1 in itertools.product(range(-2, 3), repeat=2):
            for s in itertools.product((-1, 0, 1), repeat=2):
                affine_failures += component_case(c0, c1, s, 5, 3)
                ring_cases += 1
    assert affine_failures > 0, "dropping the carry must have counterexamples"

    contractions = winding_cases = 0
    for p in (3, 5, 17, 31):
        for w in range(p * p):
            x = (w + p // 2) % (p * p)
            r = x % p
            d = (x - r) // p
            assert d == nearest(w, p) % p
            contractions += 1
            for winding in range(-3, 4):
                assert nearest(w + winding * p * p, p) % p == d
                winding_cases += 1

    bounded = []
    for p, bound in ((17, 2), (65537, 17), (65537, 32)):
        f = construct(p, bound)
        identities = certify(f, p, bound)
        cases = 0
        for r in range(-bound, bound + 1):
            for m in (0, 1, p // 2, p - 1):
                x = (r + p * m) % (p * p)
                lifted = evaluate(f, x, p * p)
                assert lifted == r % (p * p)
                assert (x - lifted) % p == 0
                assert ((x - lifted) % (p * p)) // p == m
                cases += 1
        outside = next((r for r in range(bound + 1, p // 2 + 1)
                        if evaluate(f, r, p * p) != r), None)
        assert outside is not None, "a support violation must not count as covered"
        # The signed bounded section is not the canonical [0,p) section.
        assert evaluate(f, p * p - 1, p * p) == p * p - 1
        assert evaluate(f, p * p - 1, p * p) != p - 1
        bounded.append({
            "p": p, "bound": bound, "degree": len(f) - 1,
            "degree_depth_lower_bound": (len(f) - 2).bit_length(),
            "certificate": identities, "sampled_contractions": cases,
            "outside_support_counterexample": outside,
            "output_section": "signed [-B,B], not canonical [0,p)",
            "input_support_proved_for_native_ciphertexts": False,
        })
    sources = [Path(__file__), Path(__file__).with_name("bounded_digit_polynomial.py")]
    return {
        "schema": "nine65-refresh-carry-bridge-v1",
        "scope": "clear integer identities; no encrypted correction or security admission",
        "source_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
        "checks": {
            "centered_section_cocycle_triples": cocycles,
            "composable_translation_block_cases": transfer_cases,
            "local_piecewise_threshold_cases": local_rule_cases,
            "full_cycle_extension_winding_cases": extension_cases,
            "phase1_carry_bound_boundary_cases": carry_bound_cases,
            "scalar_component_cases": scalar_cases,
            "negacyclic_n2_cases": ring_cases,
            "cases_where_uncorrected_affine_result_is_wrong": affine_failures,
            "prime_power_contractions": contractions,
            "expanded_winding_invariance_cases": winding_cases,
            "existing_bounded_polynomial_exhaustive_cases": self_test(),
        },
        "bounded_candidates": bounded,
        "wide_sum_candidate": {
            "scope": "range and encoding width only; no noise or security admission",
            "native_Q": native_q,
            "native_Q_bits": native_q.bit_length(),
            "N": 8192,
            "sum_abs_bound": native_sum_bound,
            "minimum_plaintext_modulus": minimum_plaintext,
            "minimum_plaintext_bits": minimum_plaintext.bit_length(),
            "p_power_base": 65537,
            "p_power_exponent": wide_exp,
            "p_power_modulus_bits": wide_modulus.bit_length(),
            "carry_radius": native_k,
            "carry_coordinate_modulus": 8193,
            "current_main_Q_can_encode_sum": False,
        },
        "public_refresh_admitted": False,
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
