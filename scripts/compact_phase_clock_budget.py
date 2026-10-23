#!/usr/bin/env python3
"""Public integer compaction/noise/storage comparison, not FHE admission.

Mirrors the packed-column research prototype. Uses the existing constant-
plaintext square envelope for the dependent operation. Source norm/history,
sparse-key security, return and repeat closure are external obligations.
"""

import json
from math import prod

from digit_radius_oracle import rns_keyswitch_phase_bound
from public_refresh_architecture import square_schedule


PRIMES = (1811939329, 2113929217, 2130706433, 1107296257, 1711276033)
SOURCE_Q = 348959453350711275087786864768188417
P = 65537
ETA = 3


def shape(primes, radix_bits):
    if not 1 <= radix_bits <= 10 or any(q < 3 for q in primes):
        raise ValueError("invalid unsigned raw gadget shape")
    digits = [(q.bit_length() + radix_bits - 1) // radix_bits for q in primes]
    mask = (1 << radix_bits) - 1
    # A public bound on sum_j |digit_j(x)| for 0<=x<q. Charge the
    # truncated most significant digit rather than pretending it is full.
    digit_sum = sum(min(mask, (q - 1) >> (j * radix_bits))
                    for q, count in zip(primes, digits) for j in range(count))
    return sum(digits), digit_sum


def plan(n=8192, source_norm=32, terms=8192, block=2048,
         raw_bits=2, galois_bits=2, coordinate=33, phase_denominator=8):
    if (n < 2 or n & (n - 1) or block < 1 or block & (block - 1)
            or block > n or not 0 <= source_norm <= n or not 0 <= terms <= n
            or coordinate < 3 or coordinate % 2 == 0 or phase_denominator < 2):
        raise ValueError("invalid public compaction metadata")
    q = prod(PRIMES)
    d, digit_sum = shape(PRIMES, raw_bits)
    dg, galois_sum = shape(PRIMES, galois_bits)
    active = min(source_norm, terms)
    source_v = SOURCE_Q // phase_denominator
    phase = (4 * n * source_v + SOURCE_Q - 1) // SOURCE_Q
    window2 = phase + coordinate * (active + 1)
    carry_bound = (active + 2) * (SOURCE_Q // 2) // SOURCE_Q
    window_fits = window2 < n
    integer_carry_fits = 2 * carry_bound < coordinate

    galois_error = n * ETA * galois_sum
    constant_beta = block * ETA + (block - 1) * galois_error
    outer_external = 2 * n * ETA * digit_sum
    secret_beta = n * constant_beta + outer_external
    derived_external = n * digit_sum * (constant_beta + secret_beta)

    # Lookup is deposited with centered inverse-N modulo p, not applied to
    # an existing noisy ciphertext. All supported n here divide p-1.
    inv_n = pow(n, -1, P)
    centered_inv = min(inv_n, P - inv_n)
    lookup_norm = centered_inv * (coordinate // 2)
    if lookup_norm > P // 2:
        raise ValueError("lookup deposit does not fit centered encoding")
    remainder = q % P
    carry_v = n * (remainder * lookup_norm + 2 * terms * P * derived_external)
    carry_v += P * (n - 1) * galois_error
    # Worst public centered A_i; deliberately charge both raw columns even
    # for a public constant whose second ciphertext component is zero.
    affine_v = remainder * (terms + 1) * (P // 2)
    affine_v += 2 * terms * P * derived_external
    output_v = carry_v + affine_v
    phase_error = (output_v + P - 1) // P
    relin_error = rns_keyswitch_phase_bound(PRIMES, n, ETA, 10)
    square = square_schedule(n, P, q, phase_error, relin_error, 1)
    square_fits = square["first_refusal"] is None
    # Optimistic NECESSARY phase condition after an ideal noiseless linear
    # return. Actual source-key norm, return rounding/error and lineage are
    # still absent, so passing this does not certify a repeat cycle.
    square_error = square["nodes"][-1]["error_bound"] if square["nodes"] else None
    repeat_phase = square_fits and phase_denominator * P * square_error < q

    ciphertext_bytes = 2 * n * len(PRIMES) * 8
    packed_rows = 2 * (n // block) * d
    multiplier_rows = 2 * d
    galois_rows = (n.bit_length() - 1) * dg
    precharge_bytes = (packed_rows + multiplier_rows + galois_rows) * ciphertext_bytes
    # Explicit computational cost; storage reduction is NOT latency reduction.
    # Each of 2N controls derives d constant rows, log2(block) switches per
    # row, followed by two raw switches for the secret-product column.
    derive_switches = 2 * terms * d * ((block.bit_length() - 1) + 2)
    # Full-source batch expansion shares even/odd Galois work. It changes
    # memory/latency, not the error of each leaf. Only quote this count when
    # every source position is processed, as in the executable prototype.
    stream_switches = 2 * (n // block) * d * (block - 1) + 4 * n * d
    online_switches = 8 * terms + (n.bit_length() - 1)
    return {
        "parameters": {"N": n, "source_norm": source_norm, "terms": terms,
                       "block": block, "raw_bits": raw_bits,
                       "galois_bits": galois_bits, "coordinate": coordinate,
                       "phase_denominator": phase_denominator},
        "window2": window2, "window_limit": n, "window_fits": window_fits,
        "carry_bound": carry_bound, "integer_carry_fits": integer_carry_fits,
        "raw_digits": d, "galois_digits": dg,
        "raw_digit_sum_bound": digit_sum, "galois_digit_sum_bound": galois_sum,
        "constant_column_error": constant_beta,
        "secret_column_error": secret_beta,
        "external_product_error": derived_external,
        "output_scaled_error_bound": output_v,
        "output_scaled_error_bits": output_v.bit_length(),
        "output_decode_fits": 2 * output_v < q,
        "following_square": square,
        "following_square_fits": square_fits,
        "optimistic_reentry_phase_fits": repeat_phase,
        "reentry_is_not_a_history_or_key_certificate": True,
        "conditional_arithmetic_fits": window_fits and integer_carry_fits and square_fits,
        "precharge_bytes": precharge_bytes,
        "packed_rows": packed_rows, "outer_multiplier_rows": multiplier_rows,
        "galois_rows": galois_rows,
        "derived_control_peak_bytes": 2 * d * ciphertext_bytes,
        "derive_raw_switches_per_coefficient": derive_switches,
        "stream_expansion_raw_switches_full_coefficient": stream_switches,
        "stream_stack_upper_bound_bytes": 2 * d * ciphertext_bytes * (block.bit_length() - 1 + 5),
        "stream_count_scope": "all N controls, packed blocks loaded as needed; temporary stack not part of stored-key bytes",
        "online_raw_switches_per_coefficient": online_switches,
        "raw_switch_count_excludes_ntt_work": True,
        "public_refresh_admitted": False,
    }


def report():
    candidates = []
    for bg in range(1, 11):
        for b in range(1, 11):
            for power in range(14):
                candidate = plan(raw_bits=b, galois_bits=bg, block=1 << power)
                if candidate["conditional_arithmetic_fits"]:
                    candidates.append(candidate)
    best = min(candidates, key=lambda p: p["precharge_bytes"])
    repeat_best = min((p for p in candidates if p["optimistic_reentry_phase_fits"]),
                      key=lambda p: p["precharge_bytes"])
    return {
        "scope": "Public integer analysis, no sparse-key or live-history admission",
        "naive_full_block_current_radix": plan(block=8192, raw_bits=10, galois_bits=10),
        "minimum_stored_bytes_in_declared_search": best,
        "minimum_stored_bytes_passing_optimistic_reentry": repeat_best,
        "full_dense_source_still_refused": plan(source_norm=8192),
        "passing_candidates": len(candidates),
        "search": {"raw_bits": [1, 10], "galois_bits": [1, 10],
                   "block_powers": [0, 13], "N": 8192},
        "practical_latency_admitted": False,
        "public_refresh_admitted": False,
    }


if __name__ == "__main__":
    print(json.dumps(report(), indent=2))
