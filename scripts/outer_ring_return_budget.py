#!/usr/bin/env python3
"""Public doubled-ring, reduce-before-switch ledger; not native admission."""

import json
from math import prod

from compact_phase_clock_budget import ETA, P, SOURCE_Q, shape
from full_polynomial_bootstrap_budget import WORK, square_v

EXTRA = (1811939329, 2113929217, 2130706433, 1107296257)
OUTER = WORK + EXTRA


def plan(source_n=8192, outer_n=16384, source_norm=32, block=8192,
         raw_bits=10, galois_bits=10, return_bits=10,
         coordinate=33, phase_denominator=8, multiplication_norm=None, output_batch=64):
    if (source_n < 2 or source_n & (source_n - 1) or outer_n != 2 * source_n
            or not 0 <= source_norm <= source_n or block < 1 or block & (block - 1)
            or block > source_n or coordinate < 3 or coordinate % 2 == 0
            or phase_denominator < 2 or not 0 < output_batch <= source_n):
        raise ValueError("invalid doubled-ring metadata")
    h = source_norm if multiplication_norm is None else multiplication_norm
    if not source_norm <= h <= source_n:
        raise ValueError("understated multiplication norm")
    q = prod(OUTER)
    assert prod(WORK) == SOURCE_Q
    d, digit_sum = shape(OUTER, raw_bits)
    dg, gal_sum = shape(OUTER, galois_bits)
    dr, return_sum = shape(WORK, return_bits)
    eg = outer_n * gal_sum * ETA
    beta = block * ETA + (block - 1) * eg
    beta_secret = outer_n * beta + 2 * outer_n * digit_sum * ETA
    ext = outer_n * digit_sum * (beta + beta_secret)
    inv = pow(outer_n, -1, P)
    lookup_norm = min(inv, P - inv) * (coordinate // 2)
    if lookup_norm > P // 2:
        raise ValueError("lookup does not fit centered encoding")
    rem = q % P
    carry_v = outer_n * (rem * lookup_norm + P * 2 * source_n * ext)
    carry_v += P * (outer_n - 1) * eg
    linear_fresh_v = P * (2 * outer_n + 1) * ETA + rem * (P - 1)
    affine_v = source_n * (P - 1) * linear_fresh_v + rem * (P // 2)
    # Carry extraction errors occupy every outer coefficient. The linear
    # affine polynomial already fills the entire message in one ciphertext.
    assembled_v = source_n * carry_v + affine_v
    drops = []
    reduced_v = assembled_v
    current_q = q
    for special in reversed(EXTRA):
        reduced_v = (reduced_v + special - 1) // special + (P * (outer_n + 1) + 1) // 2
        current_q //= special
        drops.append({"special": special, "remaining_q_bits": current_q.bit_length(),
                      "v_bound": reduced_v, "v_bits": reduced_v.bit_length(),
                      "decode_fits": 2 * reduced_v < current_q})
    assert current_q == SOURCE_Q
    switch_v = 2 * P * source_n * return_sum * ETA
    returned_v = reduced_v + switch_v
    following_v = square_v(source_n, P, SOURCE_Q, returned_v, h)
    cap = SOURCE_Q // phase_denominator
    window = (4 * outer_n * cap + SOURCE_Q - 1) // SOURCE_Q + coordinate * (source_norm + 1)
    stages = {
        "clock_window": window < outer_n,
        "integer_carry_range": coordinate > 2 * ((source_norm + 1) // 2),
        "assembled_decode": 2 * assembled_v < q,
        "all_modulus_drops_decode": all(p["decode_fits"] for p in drops),
        "returned_decode": 2 * returned_v < SOURCE_Q,
        "following_polynomial_square_decode": 2 * following_v < SOURCE_Q,
        "following_product_phase_reentry": following_v <= cap,
    }
    outer_ct_bytes = 2 * outer_n * len(OUTER) * 8
    work_ct_bytes = 2 * source_n * len(WORK) * 8
    outer_rows = 2 * (source_n // block) * d + 2 * d + (outer_n.bit_length() - 1) * dg + 1
    key_bytes = outer_rows * outer_ct_bytes + 2 * dr * work_ct_bytes
    expansion = 2 * (source_n // block) * d * (block - 1) + 4 * source_n * d
    online = 4 * source_n * source_n + source_n * (outer_n.bit_length() - 1) + 2
    batches = (source_n + output_batch - 1) // output_batch
    return {
        "parameters": {"source_N": source_n, "outer_N": outer_n, "source_norm": source_norm,
                       "multiplication_norm": h, "block": block, "raw_bits": raw_bits,
                       "galois_bits": galois_bits, "return_bits": return_bits,
                       "coordinate": coordinate, "phase_denominator": phase_denominator,
                       "output_batch": output_batch},
        "outer_primes": OUTER, "outer_q_bits": q.bit_length(),
        "work_q_bits": SOURCE_Q.bit_length(), "return_key_primes": WORK,
        "window2": window, "carry_per_coefficient_v_bits": carry_v.bit_length(),
        "affine_polynomial_v_bits": affine_v.bit_length(),
        "assembled_v_bound": assembled_v, "assembled_v_bits": assembled_v.bit_length(),
        "modulus_drops": drops, "reduced_v_bits": reduced_v.bit_length(),
        "returned_v_bound": returned_v, "returned_v_bits": returned_v.bit_length(),
        "following_polynomial_square_v_bound": following_v,
        "following_polynomial_square_v_bits": following_v.bit_length(),
        "stages": stages, "conditional_arithmetic_closure": all(stages.values()),
        "first_refusal": next((k for k, v in stages.items() if not v), None),
        "stored_polynomial_bytes": key_bytes,
        "stream_expansion_switches": expansion, "online_switches": online,
        "output_batches": batches, "total_switches": batches * expansion + online,
        "single_affine_plaintext_multiply": True,
        "all_clocks_resident_bytes": source_n * outer_ct_bytes,
        "resident_clocks_bytes": output_batch * outer_ct_bytes,
        "stream_stack_upper_bytes": d * outer_ct_bytes * (block.bit_length() - 1 + 5),
        "both_polarities_stack_comparison_bytes": 2 * d * outer_ct_bytes * (block.bit_length() - 1 + 5),
        "key_stack_and_clocks_bytes_excluding_contexts_and_scratch": key_bytes + output_batch * outer_ct_bytes + d * outer_ct_bytes * (block.bit_length() - 1 + 5),
        "native_encrypted_execution": False, "practical_resources_admitted": False,
        "sparse_source_and_joint_key_security_certified": False,
        "public_refresh_admitted": False,
    }


def report():
    candidates = [plan(block=1 << power, raw_bits=b, galois_bits=bg)
                  for b in range(1, 11) for bg in range(1, 11) for power in range(14)]
    fit = [p for p in candidates if p["conditional_arithmetic_closure"]]
    return {
        "scope": "Public deterministic bounds; native sparse norm32 remains conditional",
        "minimum_stored_key_candidate": min(fit, key=lambda p: p["stored_polynomial_bytes"]),
        "passing_candidates": len(fit), "dense_source_refusal": plan(source_norm=8192),
        "search": {"raw_bits": [1, 10], "galois_bits": [1, 10], "block_powers": [0, 13]},
        "outer_dense_parameter_screen": {"N8192": "refused, 97-bit minimum", "N16384": "ScreenedFullModelAgreement, 228 classical/194 hybrid/129 quantum bits"},
        "public_refresh_admitted": False,
    }


if __name__ == "__main__":
    print(json.dumps(report(), indent=2))
