#!/usr/bin/env python3
"""Exact range certificate for an adjacent-tray tropical carry readout.

This certifies the integer identity and K-elimination domain. It does not
claim the resulting K ciphertext resets the input phase error.
"""

from math import gcd

from compact_phase_clock_budget import ETA
from outer_ring_return_budget import OUTER
from source_encapsulation_budget import SOURCE_Q


SAFE_BASIS = (2, 3, 5, 7, 11, 13, 17, 19)
OUTER_N = 16384
M = 1 << 16
OUTPUT_PLAIN = M + 1
COORDINATE = 99
SOURCE_NORM = 96
PHASE_DENOMINATOR = 16
CARRY_RADIUS = SOURCE_NORM // 2
ADJACENT = M + 1


def ceil_div(numerator, denominator):
    if numerator < 0 or denominator <= 0:
        raise ValueError("ceil_div expects a nonnegative numerator and positive denominator")
    return (numerator + denominator - 1) // denominator


def inverse(value, modulus):
    if modulus <= 1 or gcd(value, modulus) != 1:
        raise ValueError("inverse requires a positive modulus and coprime value")
    return pow(value, -1, modulus)


def plan(source_q=SOURCE_Q, source_norm=SOURCE_NORM,
         phase_denominator=PHASE_DENOMINATOR, coordinate=COORDINATE,
         outer_n=OUTER_N):
    if (source_q <= 1 or source_norm < 0 or phase_denominator < 2
            or coordinate < 3 or coordinate % 2 == 0
            or outer_n < 2 or outer_n & (outer_n - 1)):
        raise ValueError("invalid public lift metadata")

    phase_cap = source_q // phase_denominator
    phase_scale = M
    phase_error = ceil_div(phase_scale * phase_cap, source_q)
    quantizer_error = ceil_div(coordinate * (source_norm + 1), 2)
    residual_bound = phase_error + quantizer_error

    # The source coefficient bound gives |K| <= floor((H+2)(Q-1)/(2Q));
    # this exact expression is slightly sharper than floor((H+2)/2).
    carry_radius = ((source_norm + 2) * (source_q - 1)) // (2 * source_q)
    offset = residual_bound
    carry_offset = carry_radius
    adjacent = phase_scale + 1
    quotient_max = 2 * carry_radius
    remainder_max = 2 * residual_bound
    x_max = phase_scale * quotient_max + remainder_max
    z_abs_bound = ceil_div(phase_scale * carry_radius + residual_bound, coordinate)

    # Public bound for two independently precharged views of the same source
    # polynomial, under t=M and t=M+1. All work remains ciphertext-linear.
    q_outer = 1
    for prime in OUTER:
        q_outer *= prime
    source_n = outer_n // 2
    weight_max = ceil_div(phase_scale, 2 * coordinate)
    weight_l1 = source_n * weight_max

    def chart_error(target, constant):
        q_remainder = q_outer % target
        fresh = target * (2 * outer_n + 1) * ETA + q_remainder * (target - 1)
        z_error = fresh * weight_l1 + q_remainder * weight_max
        return coordinate * z_error + q_remainder * abs(constant)

    m_chart_v = chart_error(phase_scale, offset)
    p_chart_constant = (offset + carry_offset * phase_scale) % adjacent
    if p_chart_constant > adjacent // 2:
        p_chart_constant -= adjacent
    p_chart_v = chart_error(adjacent, p_chart_constant)
    # If M*phase = Q*r + epsilon, then
    # (M+1)*phase - Q*r = (Q*r + (M+1)*epsilon)/M.
    redecode_v = ceil_div(q_outer * remainder_max + adjacent * m_chart_v, phase_scale)
    carry_output_v = redecode_v + p_chart_v + (q_outer % adjacent) * carry_offset

    conditions = {
        "carry_radius_matches_sparse_norm": carry_radius == source_norm // 2,
        "residual_fits_one_quotient_cell": 2 * residual_bound < phase_scale,
        "remainder_nonnegative_after_bias": offset >= residual_bound,
        "remainder_below_phase_scale": remainder_max < phase_scale,
        "quotient_in_adjacent_anchor": quotient_max < adjacent,
        "whole_value_in_adjacent_product": x_max < phase_scale * adjacent,
        "adjacent_moduli_coprime": gcd(phase_scale, adjacent) == 1,
        "safe_basis_contains_two_and_eleven": 2 in SAFE_BASIS and 11 in SAFE_BASIS,
        "coordinate_is_locked_to_eleven": coordinate % 11 == 0,
        "phase_scale_is_power_of_two": phase_scale & (phase_scale - 1) == 0,
        "phase_chart_fits_centered_plaintext": 2 * z_abs_bound < phase_scale,
        "adjacent_anchor_is_refresh_plaintext": adjacent == OUTPUT_PLAIN,
        "same_components_decode_m_remainder_under_adjacent_plaintext": (
            2 * (q_outer * remainder_max + adjacent * m_chart_v)
            < phase_scale * q_outer
        ),
        "carry_ciphertext_decodes_at_output_plaintext": 2 * carry_output_v < q_outer,
    }

    return {
        "parameters": {
            "source_q": source_q,
            "source_norm": source_norm,
            "source_phase_denominator": phase_denominator,
            "outer_n": outer_n,
            "phase_scale": phase_scale,
            "coordinate": coordinate,
            "adjacent_anchor": adjacent,
            "safe_basis": list(SAFE_BASIS),
        },
        "phase_error_bound": phase_error,
        "component_rounding_error_bound": quantizer_error,
        "total_residual_bound": residual_bound,
        "phase_chart_abs_bound": z_abs_bound,
        "carry_radius": carry_radius,
        "bias": offset,
        "carry_offset": carry_offset,
        "quotient_range": [0, quotient_max],
        "remainder_range": [0, remainder_max],
        "lifted_value_range": [0, x_max],
        "adjacent_product": phase_scale * adjacent,
        "inverse_phase_scale_mod_anchor": inverse(phase_scale, adjacent),
        "outer_q_bits": q_outer.bit_length(),
        "same_components_adjacent_decode_error_bound_bits": redecode_v.bit_length(),
        "adjacent_carry_output_error_bound_bits": carry_output_v.bit_length(),
        "carry_output_error_at_least_1_over_8_q": 8 * carry_output_v >= q_outer,
        "conditions": conditions,
        "all_conditions_pass": all(conditions.values()),
        "encrypted_k_elimination_implemented": False,
        "output_noise_reset_proved": False,
        "public_refresh_admitted": False,
    }


def recover_quotient_from_adjacent_residues(value, modulus=M):
    """Clear algebra oracle for K-elimination on adjacent moduli."""
    adjacent = modulus + 1
    if modulus <= 1 or value < 0 or value >= modulus * adjacent:
        raise ValueError("value is outside the adjacent-anchor uniqueness interval")
    residue_m = value % modulus
    residue_a = value % adjacent
    quotient = ((residue_a - residue_m) * inverse(modulus, adjacent)) % adjacent
    return quotient


def recover_carry_from_error(carry, residual, selected_plan=None):
    """Apply the proved bias and adjacent K-elimination to one clear case."""
    p = plan() if selected_plan is None else selected_plan
    kmax = p["carry_radius"]
    error_bound = p["total_residual_bound"]
    if abs(carry) > kmax or abs(residual) > error_bound:
        raise ValueError("case is outside the certified carry/error corridor")
    modulus = p["parameters"]["phase_scale"]
    adjacent = p["parameters"]["adjacent_anchor"]
    value = modulus * (carry + kmax) + residual + p["bias"]
    quotient = recover_quotient_from_adjacent_residues(value, modulus)
    recovered = quotient - kmax
    return recovered, value, quotient


if __name__ == "__main__":
    import json

    print(json.dumps(plan(), indent=2))
