#!/usr/bin/env python3
"""Source-linked public-refresh budget analysis, NOT an admission certificate.

Public integer metadata only. The native noise recurrence is mirrored to
locate its refusals; this does not independently prove that recurrence. The
Hermite calculation checks a polynomial-degree obstruction, not a lower bound
against all encrypted algorithms. No keys, ciphertexts, or production settings
are changed. Run the corresponding unittest file for boundary checks.
"""

import hashlib
import json
from math import prod
from pathlib import Path

from bounded_digit_polynomial import construct, certify
from digit_radius_oracle import rns_keyswitch_phase_bound, sparse_route_radius
from refresh_carry_bridge import multiplication_winding_budget


N = 8192
P = 65537
WORK_Q = 348959453350711275087786864768188417
BOOT_PRIMES = (1811939329, 2113929217, 2130706433, 1107296257, 1711276033)
SPARSE_PRIMES = (998244353, 985661441)


def polynomial_requirement(p, radius):
    coefficients = construct(p, radius)
    identities = certify(coefficients, p, radius)
    degree_mod_p = max((i for i, c in enumerate(coefficients) if c % p), default=0)
    # Value and derivative constraints give a unique remainder modulo G^2 in
    # F_p[X], where G has the distinct 2B+1 support points as roots. When F has
    # degree below deg(G^2), that remainder is F itself. Every other solution
    # differs by a multiple of G^2, and cannot have lower degree than F mod p.
    assert degree_mod_p < 2 * (2 * radius + 1)
    return {
        "radius": radius,
        "degree": len(coefficients) - 1,
        "minimum_polynomial_degree": degree_mod_p,
        "binary_multiplication_depth_lower_bound": 0 if degree_mod_p <= 1 else (degree_mod_p - 1).bit_length(),
        "scope": "single-variable polynomial on every r+p*m in the specified support",
        "identities": identities,
    }


def multiply_terms(n, t, q, a, b, switch):
    """Mirror prime_power_digit_lift::NoisePlan, in ideal-grid phase units.

    The plaintexts must be constants; both input bounds must already be below
    half-Delta. This is not a full-polynomial coefficientwise multiplication
    bound and cannot be used on packed slots without the transform analysis.
    """
    half = q // t // 2
    if (n < 2 or n & (n - 1) or t < 3 or t % 2 == 0 or q <= t
            or q % 2 == 0 or min(a, b, switch) < 0 or max(a, b) >= half):
        raise ValueError("requires admitted constant-plaintext operands and valid metadata")
    np = n * t
    factor = np * (n // 2 + 1) + (t - 1) // 2
    exponent = max(0, a.bit_length() + b.bit_length() + np.bit_length() - (q.bit_length() - 1))
    return {
        "message_linear": (a + b) * ((t - 1) // 2),
        "component_winding_linear": (a + b) * (factor - (t - 1) // 2),
        "quadratic_bit_bound": (1 << exponent) if a and b else 0,
        "component_rounding": (n * n + n + 2) // 2,
        "key_switch": switch,
    }


def square_schedule(n, t, q, initial, switch, steps):
    """Stop at the first refused node; never recurse on a failed certificate."""
    half = q // t // 2
    if initial < 0 or steps < 0:
        raise ValueError("negative input bound or step count")
    result = {"initial_error": initial, "initial_error_bits": initial.bit_length(),
              "half_delta": half, "half_delta_bits": half.bit_length(), "nodes": []}
    if initial >= half:
        result["first_refusal"] = "input"
        return result
    error = initial
    for index in range(1, steps + 1):
        terms = multiply_terms(n, t, q, error, error, switch)
        error = sum(terms.values())
        admitted = error < half
        result["nodes"].append({"square": index, "terms": terms, "error_bound": error,
                                "error_bits": error.bit_length(), "bound_fits": admitted})
        if not admitted:
            result["first_refusal"] = index
            break
    else:
        result["first_refusal"] = None
    return result


def native_projection_schedule(beta):
    """Same public multiplier/trace envelope; only key phase-error beta varies.

    beta=eta is a prospective secret-key encryption at KEY GENERATION, not a
    secret-key refresh and not implemented by ExpandedBootstrapKey today.
    """
    q, t = prod(BOOT_PRIMES), P * P
    remainder = q % t
    switch = rns_keyswitch_phase_bound(BOOT_PRIMES, N, 3, 10)
    expansion = beta * N * ((t - 1) // 2) + (N + 1) * remainder + (remainder + 1) // 2
    projected = N * expansion + (N - 1) * switch
    return {"beta": beta, "expansion_bound": expansion,
            "expansion_bits": expansion.bit_length(),
            "schedule": square_schedule(N, t, q, projected, switch, 7)}


def report():
    root = Path(__file__).resolve().parents[1]
    sources = [
        "scripts/public_refresh_architecture.py", "scripts/test_public_refresh_architecture.py",
        "scripts/bounded_digit_polynomial.py",
        "scripts/digit_radius_oracle.py", "scripts/refresh_carry_bridge.py",
        "crates/nine65/src/ops/bootstrap.rs", "crates/nine65/src/ops/cram_main.rs",
        "crates/nine65/src/ops/prime_power_digit_lift.rs",
        "crates/nine65/src/ops/prime_power_phase.rs",
        "crates/nine65/src/ops/expanded_bootstrap.rs",
        "crates/nine65/src/keys/expanded_bootstrap.rs",
        "crates/nine65/src/ops/safe_basis_composition_tests.rs",
        "crates/nine65/src/arithmetic/exact_scale_round.rs",
        "crates/nine65/src/arithmetic/main_only_base_ext.rs",
    ]
    switch = rns_keyswitch_phase_bound(SPARSE_PRIMES, N, 3, 10)
    # These are existing scalar-history fixtures, NOT post-transform bounds.
    radii = [dict(input_scaled_error=v, **sparse_route_radius(
        WORK_Q, prod(SPARSE_PRIMES), P, N, 32, v, switch))
        for v in (5011390467, 22046046060462580170753)]
    return {
        "schema": "nine65-public-refresh-architecture-v1",
        "scope": "research integer analysis; no native public refresh admission",
        "source_sha256": {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                          for name in sources},
        "parameters": {"N": N, "p": P, "boot_t": P * P,
                       "boot_primes": BOOT_PRIMES, "boot_Q": prod(BOOT_PRIMES)},
        "conditional_sparse_radius_fixtures_not_post_transform": radii,
        "polynomial_requirements": [polynomial_requirement(P, b) for b in (16, 17, 32)],
        "native_coefficient_projection": native_projection_schedule(3 * (2 * N + 1)),
        "prospective_low_noise_key_same_projection": native_projection_schedule(3),
        "low_noise_key_implemented": False,
        "joint_single_round_arithmetic": multiplication_winding_budget(),
        "larger_ring_projection": {
            "p": P, "N": 32768, "slots_split": (P - 1) % (2 * 32768) == 0,
            "current_fixed_minus_eight_inverse_works": (-8 * 32768) % P == 1,
            "centered_inverse": -2,
            "minus_two_is_inverse": (-2 * 32768) % P == 1,
            "same_ring_key_api_accepts_8192_to_32768": False,
        },
        "public_refresh_admitted": False,
    }


if __name__ == "__main__":
    print(json.dumps(report(), indent=2))
