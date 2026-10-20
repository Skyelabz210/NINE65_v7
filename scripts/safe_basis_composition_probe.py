#!/usr/bin/env python3
"""Clear independent oracles and bounds for encrypted carry composition.

This script does not execute an encrypted evaluator or a security estimator.
Native Rust results and in-tree security screens are recorded separately.
"""

import hashlib
import itertools
import json
import math
from pathlib import Path

ROOT = (2, 3, 5, 7, 11, 13, 17, 19)
WORK = (998244353, 985661441, 754974721, 469762049)
BOOT = (1811939329, 2113929217, 2130706433, 1107296257, 1711276033, 1224736769)
N, T, ETA = 8192, 65537, 3
Q = math.prod(WORK)


def nearest(x, q):
    return (x + q // 2) // q


def check_prefixes(q, r0, terms, trits):
    direct = r0
    remainder, winding = r0, 0
    for term, trit in zip(terms, trits):
        direct += term * trit
        intermediate = remainder + term * trit
        winding += nearest(intermediate, q)
        remainder = intermediate - q * nearest(intermediate, q)
        assert winding == nearest(direct, q)
        assert remainder == direct - q * nearest(direct, q)
        for p in ROOT:
            assert (remainder % p + winding % p * (q % p)) % p == direct % p


def check_balanced(q, coefficients, trits):
    a = coefficients[0] + coefficients[1] * trits[0] + coefficients[2] * trits[1]
    b = coefficients[3] * trits[2] + coefficients[4] * trits[3]
    ka, kb = nearest(a, q), nearest(b, q)
    ga, gb = a - q * ka, b - q * kb
    crossing = nearest(ga + gb, q)
    remainder, winding = ga + gb - q * crossing, ka + kb + crossing
    assert winding == nearest(a + b, q)
    assert remainder == a + b - q * winding
    for p in ROOT:
        assert (remainder % p + winding % p * (q % p)) % p == (a + b) % p


def noise_profile(primes):
    qb = math.prod(primes)
    digits = sum((p.bit_length() + 9) // 10 for p in primes)
    switch = N * ETA * (2 ** 10 - 1) * digits
    projected = N * (ETA * (2 * N + 1) + 8) + (N - 1) * switch
    factor = N * T * (N // 2 + 1) + (T - 1) // 2
    half = qb // T // 2
    comparisons = 0

    def multiply(a, b):
        nonlocal comparisons
        exponent = max(0, a.bit_length() + b.bit_length()
                       + (N * T).bit_length() - (qb.bit_length() - 1))
        conservative_quadratic = 2 ** exponent if a and b else 0
        exact_quadratic = (N * T * a * b + qb - 1) // qb
        assert conservative_quadratic >= exact_quadratic
        comparisons += 1
        return (a + b) * factor + conservative_quadratic + (N * N + N + 2) // 2 + switch

    # Optimistic reference-tree budget: omit row-merging and projection
    # amplification. Even this bound reaches a refusal before eight leaves
    # for the selected five-prime profile. This is not an impossibility
    # theorem for other carry circuits or a measured encrypted execution.
    balanced_levels = []
    leaves, error = 1, projected
    while True:
        balanced_levels.append({"leaves": leaves, "error_bits": error.bit_length(),
                                "admitted": error < half})
        if error >= half or leaves == N:
            break
        leaves *= 2
        error = multiply(error, error)

    rows = {(Q // 2, 0): None}
    prefixes = []
    states = []
    refusal = None
    for length, term in enumerate((Q // 2, -Q // 2 + 1, Q // 2, Q // 2), 1):
        new = {}
        for (remainder, winding), error in rows.items():
            for trit in (-1, 0, 1):
                z = remainder + term * trit
                increment = nearest(z, Q)
                label = (z - Q * increment, winding + increment)
                bound = projected if error is None else multiply(error, projected)
                if bound >= half:
                    refusal = {"term": length, "stage": "selector multiply",
                               "error_bits": bound.bit_length(), "half_bits": half.bit_length()}
                    break
                new[label] = new.get(label, 0) + bound
                if new[label] >= half:
                    refusal = {"term": length, "stage": "merged selector",
                               "error_bits": new[label].bit_length(), "half_bits": half.bit_length()}
                    break
            if refusal:
                break
        if refusal:
            break
        carry_bound = sum(abs(winding) * bound for (_, winding), bound in new.items())
        root_bounds = {str(p): sum((remainder % p + winding % p * (Q % p)) % p * bound
                                  for (remainder, winding), bound in new.items()) for p in ROOT}
        if max((carry_bound, *root_bounds.values())) >= half:
            refusal = {"term": length, "stage": "output projection",
                       "error_bits": max((carry_bound, *root_bounds.values())).bit_length(),
                       "half_bits": half.bit_length()}
            break
        prefixes.append({"terms": length, "distinct_public_rows": len(new),
                         "row_error_bits": max(new.values()).bit_length(),
                         "carry_error_bound": carry_bound, "carry_error_bits": carry_bound.bit_length(),
                         "root_error_bounds": root_bounds,
                         "largest_root_error_bits": max(root_bounds.values()).bit_length()})
        rows = new
        states.append(new)

    def combine(left, right):
        output = {}
        for (ga, ka), ea in left.items():
            for (gb, kb), eb in right.items():
                crossing = nearest(ga + gb, Q)
                label = (ga + gb - Q * crossing, ka + kb + crossing)
                bound = multiply(ea, eb)
                if bound >= half:
                    return None, {"stage": "selector multiply", "error_bits": bound.bit_length()}
                output[label] = output.get(label, 0) + bound
                if output[label] >= half:
                    return None, {"stage": "merged selector", "error_bits": output[label].bit_length()}
        carry = sum(abs(k) * error for (_, k), error in output.items())
        roots = {str(p): sum((g % p + (k % p) * (Q % p)) % p * error
                            for (g, k), error in output.items()) for p in ROOT}
        maximum = max((carry, *roots.values()))
        if maximum >= half:
            return None, {"stage": "output projection", "error_bits": maximum.bit_length()}
        return output, {"terms": 4, "distinct_public_rows": len(output),
                        "carry_error_bound": carry, "carry_error_bits": carry.bit_length(),
                        "root_error_bounds": roots, "largest_root_error_bits": max(roots.values()).bit_length()}

    right_leaf = {(a * (Q // 2), 0): projected for a in (-1, 0, 1)}
    right_pair, _ = combine(right_leaf, right_leaf)
    assert right_pair is not None
    balanced_state, balanced = combine(states[1], right_pair)
    balanced["admitted"] = balanced_state is not None
    remainder = qb % T
    beta = ETA * (2 * N + 1)
    inner_error = beta * N * (T // 2) + (N + 1) * remainder + (remainder + 1) // 2
    affine_error = N * inner_error + (N - 1) * switch
    fresh_error = affine_error + prefixes[1]["carry_error_bound"]
    post_error = multiply(fresh_error, fresh_error)
    scalar_ciphertext_bytes = 2 * len(primes) * N * 8
    return {"boot_primes": primes, "Q_bits": qb.bit_length(), "half_delta_bits": half.bit_length(),
            "projected_selector_error_bound": projected, "projected_selector_error_bits": projected.bit_length(),
            "accepted_prefixes": prefixes, "first_refusal": refusal,
            "balanced_four_term": balanced,
            "optimistic_balanced_selector_levels": balanced_levels,
            "full_reference_tree_multiplication_levels": N.bit_length() - 1,
            "bounded_coefficient_refresh": {"domain": "two-term sparse source, one target coefficient",
                                            "affine_error_bound": affine_error,
                                            "fresh_error_bound": fresh_error,
                                            "fresh_error_bits": fresh_error.bit_length(),
                                            "post_multiply_error_bound": post_error,
                                            "post_multiply_error_bits": post_error.bit_length(),
                                            "post_multiply_admitted": post_error < half},
            "quadratic_bound_cross_checks": comparisons,
            "compact_packed_precharge_bytes": 3 * scalar_ciphertext_bytes,
            "shared_trace_and_relinearization_key_bytes": (N.bit_length() - 1 + 1) * digits * scalar_ciphertext_bytes,
            "direct_unpacked_selector_key_bytes": 3 * N * scalar_ciphertext_bytes}


def run():
    small_cases = native_cases = small_balanced = native_balanced = 0
    for q, alphabet in ((5, range(-2, 3)), (17, (-8, -1, 0, 1, 8)), (31, (-15, -1, 0, 1, 15))):
        for coefficients in itertools.product(alphabet, repeat=4):
            for trits in itertools.product((-1, 0, 1), repeat=3):
                check_prefixes(q, coefficients[0], coefficients[1:], trits)
                small_cases += 1
    h = Q // 2
    for coefficients in itertools.product((-h, -h + 1, -1, 0, 1, h - 1, h), repeat=4):
        for trits in itertools.product((-1, 0, 1), repeat=3):
            check_prefixes(Q, coefficients[0], coefficients[1:], trits)
            native_cases += 1
    for coefficients in itertools.product(range(-2, 3), repeat=5):
        for trits in itertools.product((-1, 0, 1), repeat=4):
            check_balanced(5, coefficients, trits)
            small_balanced += 1
    for coefficients in itertools.product((-h, 0, h), repeat=5):
        for trits in itertools.product((-1, 0, 1), repeat=4):
            check_balanced(Q, coefficients, trits)
            native_balanced += 1

    # Equal remainder is insufficient for public row merging: these two
    # possible source states have different windings and Safe Basis views.
    assert 0 % 17 == 17 % 17 and nearest(0, 17) != nearest(17, 17)
    assert (0 % 11) != (17 % 11)
    # Resetting the encrypted remainder to the initial public value is wrong.
    assert nearest(8 + 8 + 8, 17) == 1
    assert nearest(8 + 8, 17) + nearest(8 + 8, 17) == 2

    profiles = [noise_profile(BOOT[:count]) for count in (4, 5, 6)]
    assert len(profiles[0]["accepted_prefixes"]) == 2
    assert len(profiles[1]["accepted_prefixes"]) == 3
    assert profiles[1]["first_refusal"]["term"] == 4
    assert [x["distinct_public_rows"] for x in profiles[1]["accepted_prefixes"]] == [3, 5, 7]
    assert profiles[1]["balanced_four_term"]["admitted"]
    assert profiles[1]["balanced_four_term"]["distinct_public_rows"] == 9
    assert profiles[1]["optimistic_balanced_selector_levels"][-1]["leaves"] == 8
    assert not profiles[1]["optimistic_balanced_selector_levels"][-1]["admitted"]
    assert profiles[1]["bounded_coefficient_refresh"]["post_multiply_admitted"]
    source_cases = []
    for sign in (-1, 1):
        c0 = sign * h * pow(T, -1, Q) % Q
        c11 = c0
        c10 = -sign * h * pow(T, -1, Q) % Q
        raw_phase = c0 + c11 - c10
        decoded = nearest(T * (raw_phase % Q), Q) % T
        affine = (nearest(T * c0, Q) + nearest(T * c11, Q) - nearest(T * c10, Q)) % T
        carry = nearest(3 * sign * h, Q)
        g = T * raw_phase - Q * nearest(T * raw_phase, Q)
        assert (affine + carry) % T == decoded and affine != decoded
        assert abs(g) == h - 1
        source_cases.append({"sign": sign, "decoded": decoded, "uncorrected_affine": affine,
                             "carry": carry, "source_exact_grid_distance": abs(g)})

    repo = Path(__file__).resolve().parent.parent
    paths = ("scripts/safe_basis_composition_probe.py",
             "crates/nine65/src/ops/safe_basis_composition_tests.rs",
             "crates/nine65/src/ops/safe_basis_precharge_tests.rs",
             "crates/nine65/src/ops/expanded_bootstrap.rs",
             "crates/nine65/src/ops/rns_galois.rs",
             "crates/nine65/src/ops/exact_mul.rs", "Cargo.lock")
    return {"schema": "nine65-safe-basis-composition-v1",
            "scope": "clear exact composition oracles and public bounds; Rust encrypted tests separate",
            "source_sha256": {p: hashlib.sha256((repo / p).read_bytes()).hexdigest() for p in paths},
            "checks": {"small_three_trit_cases": small_cases, "native_three_trit_boundary_cases": native_cases,
                       "small_balanced_four_trit_cases": small_balanced, "native_balanced_four_trit_cases": native_balanced,
                       "prefix_checks_per_case": 3, "root_views_per_prefix": 8, "negative_controls": 2},
            "profiles": profiles,
            "sparse_work_coefficient_cases": source_cases,
            "root_encoding": "canonical root residue encoded as an integer under common plaintext t=65537",
            "known_limits": ["three sequential or four balanced terms in the selected five-prime reference profile",
                             "six-prime security screening must be checked in Rust, not inferred from range",
                             "public support may grow exponentially for arbitrary coefficients",
                             "chosen source-polynomial fixture; production key/lineage factory not supplied"],
            "public_refresh_admitted": False}


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
