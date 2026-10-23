#!/usr/bin/env python3
"""Dense-work -> bounded low-Q source -> outer lift -> dense-work ledger.

Pure integer public analysis. External sparse and joint key security,
authenticated history and native encrypted execution remain separate gates.
"""

import json
from math import prod

from compact_phase_clock_budget import ETA, P
from full_polynomial_bootstrap_budget import WORK, square_v
from outer_ring_return_budget import plan as outer_plan
from compact_phase_clock_budget import shape

SOURCE = WORK[:2]
WORK_Q = prod(WORK)
SOURCE_Q = prod(SOURCE)


def source_transform(v, n=8192, radix_bits=10):
    if v < 0 or 2 * v >= WORK_Q or n < 2 or n & (n - 1):
        raise ValueError("working input must be decodable")
    q = WORK_Q
    nodes = []
    for prime in reversed(WORK[len(SOURCE):]):
        v = (v + prime - 1) // prime + (P * (n + 1) + 1) // 2
        q //= prime
        nodes.append({"remaining_q": q, "v_bound": v, "decode_fits": 2 * v < q})
    assert q == SOURCE_Q
    digits, digit_sum = shape(SOURCE, radix_bits)
    switch_v = P * n * digit_sum * ETA
    return {
        "drops": nodes, "switch_v": switch_v, "source_v_bound": v + switch_v,
        "source_v_bits": (v + switch_v).bit_length(),
        "source_decode_fits": 2 * (v + switch_v) < SOURCE_Q,
        "switch_rows": digits,
        "source_key_publication_primes": SOURCE,
        "source_key_ever_encrypts_at_work_Q": False,
    }


def maximum_work_input(n, source_cap):
    lo, hi = 0, (WORK_Q + 1) // 2
    if source_transform(0, n)["source_v_bound"] > source_cap:
        return None
    while hi - lo > 1:
        mid = (hi + lo) // 2
        if source_transform(mid, n)["source_v_bound"] <= source_cap:
            lo = mid
        else:
            hi = mid
    return lo


def plan(n=8192, source_norm=96, coordinate=99, phase_denominator=16,
         block=8192, output_batch=64, incoming_work_v=None):
    if phase_denominator < 2:
        raise ValueError("invalid source phase allowance")
    incoming = WORK_Q // 20 if incoming_work_v is None else incoming_work_v
    prepared = source_transform(incoming, n)
    # The output key is the ORIGINAL DENSE working key. The sparse source
    # norm cannot replace n in the following polynomial multiplication.
    outer = outer_plan(source_n=n, outer_n=2*n, source_norm=source_norm,
                       coordinate=coordinate, phase_denominator=phase_denominator,
                       block=block, output_batch=output_batch, multiplication_norm=n)
    returned = outer["returned_v_bound"]
    product_v = square_v(n, P, WORK_Q, returned, n)
    next_source = source_transform(product_v, n)
    cap = SOURCE_Q // phase_denominator
    window = (8 * n * cap + SOURCE_Q - 1) // SOURCE_Q + coordinate * (source_norm + 1)
    stages = {
        "working_input_decode": 2 * incoming < WORK_Q,
        "input_modulus_drops_decode": all(x["decode_fits"] for x in prepared["drops"]),
        "prepared_source_decode": prepared["source_decode_fits"],
        "prepared_source_phase_fits": prepared["source_v_bound"] <= cap,
        "source_clock_window": window < 2*n,
        "integer_carry_range": coordinate > 2*((source_norm + 1)//2),
        "outer_assembly_decode": outer["stages"]["assembled_decode"],
        "outer_modulus_drops_decode": outer["stages"]["all_modulus_drops_decode"],
        "working_return_decode": 2 * returned < WORK_Q,
        "following_dense_work_product_decode": 2 * product_v < WORK_Q,
        "next_prepared_source_phase_fits": next_source["source_v_bound"] <= cap,
    }
    key_bytes = prepared["switch_rows"] * 2*n*len(SOURCE)*8
    return {
        "parameters": {"working_N": n, "source_N": n, "outer_N": 2*n,
                       "working_norm_bound": n, "source_norm": source_norm,
                       "outer_norm_bound": 2*n, "coordinate": coordinate,
                       "source_phase_denominator": phase_denominator,
                       "source_Q": SOURCE_Q, "working_Q": WORK_Q},
        "working_input_v": incoming, "source_phase_cap": cap,
        "maximum_transformable_working_v": maximum_work_input(n, cap),
        "source_transform": prepared, "source_window2": window,
        "outer_v_bits": outer["assembled_v_bits"],
        "returned_work_v": returned, "returned_work_v_bits": returned.bit_length(),
        "following_dense_work_product_v": product_v,
        "following_dense_work_product_v_bits": product_v.bit_length(),
        "following_source_transform": next_source,
        "stages": stages, "conditional_arithmetic_closure": all(stages.values()),
        "first_refusal": next((name for name, fits in stages.items() if not fits), None),
        "source_transform_key_bytes": key_bytes,
        "total_stored_polynomial_bytes": outer["stored_polynomial_bytes"] + key_bytes,
        "total_raw_switches": outer["total_switches"] + 1,
        "bound_resets_to_same_returned_work_bound": True,
        "original_dense_working_key_changed": False,
        "sparse_source_security_assessment_complete": False,
        "joint_key_security_proven": False,
        "native_encrypted_bootstrap_executed": False,
        "production_admitted": False,
    }


def report():
    return {
        "scope": "Public integer ledger; dense input really switches keys before the clock",
        "candidate": plan(),
        "skipping_encapsulation_still_refuses": plan(source_norm=8192),
        "production_admitted": False,
    }


if __name__ == "__main__":
    print(json.dumps(report(), indent=2))
