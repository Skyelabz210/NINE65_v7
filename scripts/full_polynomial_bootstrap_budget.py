#!/usr/bin/env python3
"""Public bounds for the full-polynomial research pipeline, NOT admission.

Unlike compact_phase_clock_budget's coefficient/scalar comparison, charge
all N extracted ciphertext errors, an actual key/modulus return, and full
polynomial message/winding norms. Sparse norms remain conditional inputs.
"""

import json
from math import prod

from compact_phase_clock_budget import ETA, P, SOURCE_Q, shape

WORK = (998244353, 985661441, 754974721, 469762049)
SPECIAL = 1811939329
OUTER = WORK + (SPECIAL,)


def square_v(n, t, q, v, secret_norm, primes=WORK):
    if v < 0 or 2 * v >= q or not 0 <= secret_norm <= n:
        raise ValueError("requires a decodable input and bounded ternary secret")
    message_norm = n * ((t - 1) // 2)
    winding_norm = n * (secret_norm // 2 + 1)
    factor = message_norm + t * winding_norm
    # The exact product's tensor rounds before evaluating 1,s,s^2.
    rounding = (t * (1 + secret_norm + secret_norm**2) + 1) // 2
    digits = sum((q_i.bit_length() + 9) // 10 for q_i in primes)
    switch = t * n * ETA * 1023 * digits
    # 2V<Q => N*V^2/Q < (N/2)*V. No floating approximation.
    return 2 * factor * v + (n // 2) * v + rounding + switch


def plan(n=8192, source_norm=32, block=512, raw_bits=2, galois_bits=2,
         coordinate=33, phase_denominator=8, multiplication_norm=None):
    if (n < 2 or n & (n - 1) or block < 1 or block & (block - 1)
            or block > n or not 0 <= source_norm <= n
            or coordinate < 3 or coordinate % 2 == 0 or phase_denominator < 2):
        raise ValueError("invalid pipeline metadata")
    h = source_norm if multiplication_norm is None else multiplication_norm
    if not source_norm <= h <= n:
        raise ValueError("multiplication norm cannot understate the source key norm")
    q = prod(OUTER)
    assert prod(WORK) == SOURCE_Q
    d, digit_sum = shape(OUTER, raw_bits)
    dg, gal_sum = shape(OUTER, galois_bits)
    eg = n * gal_sum * ETA
    constant_beta = block * ETA + (block - 1) * eg
    secret_beta = n * constant_beta + 2 * n * digit_sum * ETA
    ext = n * digit_sum * (constant_beta + secret_beta)
    inverse_n = pow(n, -1, P)
    lookup_norm = min(inverse_n, P - inverse_n) * (coordinate // 2)
    if lookup_norm > P // 2:
        raise ValueError("lookup deposit outside centered encoding")
    remainder = q % P
    carry_v = n * (remainder * lookup_norm + 2 * n * P * ext) + P * (n - 1) * eg
    affine_v = remainder * (n + 1) * (P // 2) + 2 * n * P * ext
    coefficient_v = carry_v + affine_v
    assembled_v = n * coefficient_v
    return_switch_v = P * n * digit_sum * ETA
    returned_v = (assembled_v + return_switch_v + SPECIAL - 1) // SPECIAL
    returned_v += (P * (source_norm + 1) + 1) // 2
    phase_cap = SOURCE_Q // phase_denominator
    window2 = (4 * n * phase_cap + SOURCE_Q - 1) // SOURCE_Q + coordinate * (source_norm + 1)
    stages = {
        "clock_window": window2 < n,
        "integer_carry_range": coordinate > 2 * ((source_norm + 1) // 2),
        "assembled_decode": 2 * assembled_v < q,
        "returned_decode": 2 * returned_v < SOURCE_Q,
    }
    following_v = square_v(n, P, SOURCE_Q, returned_v, h) if stages["returned_decode"] else None
    stages["following_polynomial_square_decode"] = following_v is not None and 2 * following_v < SOURCE_Q
    stages["following_product_phase_reentry"] = following_v is not None and following_v <= phase_cap
    ciphertext_bytes = 2 * n * len(OUTER) * 8
    # Packed source, shared outer multiplier, Galois material AND return key.
    rows = 2 * (n // block) * d + 2 * d + (n.bit_length() - 1) * dg + d
    expansion_switches = 2 * (n // block) * d * (block - 1) + 4 * n * d
    online_switches = 8 * n * n + n * (n.bit_length() - 1) + 1
    return {
        "parameters": {"N": n, "source_norm": source_norm, "multiplication_norm": h,
                       "block": block, "raw_bits": raw_bits, "galois_bits": galois_bits,
                       "coordinate": coordinate, "phase_denominator": phase_denominator},
        "outer_primes": OUTER, "outer_modulus_bits": q.bit_length(),
        "window2": window2, "phase_cap": phase_cap,
        "coefficient_v_bound": coefficient_v, "coefficient_v_bits": coefficient_v.bit_length(),
        "assembled_v_bound": assembled_v, "assembled_v_bits": assembled_v.bit_length(),
        "returned_v_bound": returned_v, "returned_v_bits": returned_v.bit_length(),
        "following_polynomial_square_v_bound": following_v,
        "following_polynomial_square_v_bits": following_v.bit_length() if following_v is not None else None,
        "stages": stages, "first_refusal": next((name for name, fits in stages.items() if not fits), None),
        "conditional_arithmetic_closure": all(stages.values()),
        "stored_polynomial_bytes_including_return_key": rows * ciphertext_bytes,
        "stream_expansion_switches": expansion_switches,
        "full_polynomial_online_switches": online_switches,
        "total_switches_per_refresh": expansion_switches + online_switches,
        "security_of_sparse_source_or_key_cycles_certified": False,
        "native_encrypted_execution": False, "public_refresh_admitted": False,
    }


def report():
    candidates = [plan(block=1 << power, raw_bits=b, galois_bits=bg)
                  for b in range(1, 11) for bg in range(1, 11) for power in range(14)]
    fitting = [p for p in candidates if p["conditional_arithmetic_closure"]]
    best = min(fitting, key=lambda p: p["stored_polynomial_bytes_including_return_key"]) if fitting else None
    return {
        "scope": "Conditional full-polynomial deterministic bounds; refusals are not impossibility proofs",
        "compact_block512": plan(), "compact_block2048": plan(block=2048),
        "smallest_storage_with_conditional_arithmetic_closure": best,
        "fitting_candidates": len(fitting),
        "fitting_block_sizes": sorted({p["parameters"]["block"] for p in fitting}),
        "dense_source_refusal": plan(source_norm=8192),
        "search": {"raw_bits": [1, 10], "galois_bits": [1, 10], "block_powers": [0, 13]},
        "practical_native_execution_admitted": False, "public_refresh_admitted": False,
    }


if __name__ == "__main__":
    print(json.dumps(report(), indent=2))
