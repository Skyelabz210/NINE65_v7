#!/usr/bin/env python3
"""Exact public ledger for the adjacent 120/121 hidden-carry route.

The 120 view isolates the centered rounding residual; the adjacent 121 view
contains that residual minus the hidden winding. A K-Elimination encoding
conversion makes both views comparable at plaintext 121, so their difference
is the winding itself. This is an integer/error certificate, not an encrypted
execution or admission claim.
"""

from math import gcd, prod

from compact_phase_clock_budget import ETA, P, shape
from full_polynomial_bootstrap_budget import square_v
from outer_ring_return_budget import EXTRA, OUTER, WORK
from source_encapsulation_budget import SOURCE_Q, source_transform


SOURCE_N = 8192
OUTER_N = 2 * SOURCE_N
SOURCE_NORM = 96
SOURCE_PHASE_DENOMINATOR = 16
WEIGHT_SCALE = 120
RESIDUE_PLAIN = 120
CARRY_PLAIN = 121
OUTPUT_PLAIN = P
SAFE_BASIS = (2, 3, 5, 7, 11, 13, 17, 19)


def ceil_div(numerator, denominator):
    if numerator < 0 or denominator <= 0:
        raise ValueError("ceil_div expects a nonnegative numerator and positive denominator")
    return (numerator + denominator - 1) // denominator


def centered(value, modulus):
    value %= modulus
    return value - modulus if value > modulus // 2 else value


def chart_error(target, q, source_n=SOURCE_N, outer_n=OUTER_N,
                weight_scale=WEIGHT_SCALE):
    """Noise from one public weighted view and its fresh secret precharge."""
    weight_max = ceil_div(weight_scale, 2)
    weight_l1 = source_n * weight_max
    remainder = q % target
    fresh = target * (2 * outer_n + 1) * ETA + remainder * (target - 1)
    return fresh * weight_l1 + remainder * weight_max


def component_scale_bound(input_error, input_plain, output_plain,
                          ring_n=OUTER_N, secret_l1=OUTER_N // 2):
    """Bound coefficient-rounding only, assuming secret winding is corrected.

    Each of c0 and c1 is rounded coefficientwise to nearest integer. Under
    ||s||_1 <= secret_l1, the induced phase rounding is at most
    (1+secret_l1)/2, then multiplied by output_plain. Scaling a ciphertext's
    components also turns its hidden decryption winding into a plaintext
    shift; this function deliberately does not bound that shift.
    """
    if min(input_error, input_plain, output_plain, ring_n, secret_l1) < 0:
        raise ValueError("scale metadata must be nonnegative")
    round_phase = ceil_div(1 + secret_l1, 2)
    return input_error + output_plain * round_phase


def scale_winding_shift(winding, input_plain, output_plain):
    """Plaintext shift caused by scaling a ciphertext with winding J."""
    return (input_plain * winding) % output_plain


def drop_and_return(output_error, output_q, ring_n=OUTER_N,
                    source_n=SOURCE_N, output_plain=OUTPUT_PLAIN):
    """Follow the existing outer->work modulus-drop and key-return ledger."""
    value = output_error
    q = output_q
    drops = []
    for special in reversed(EXTRA):
        if q % special:
            raise ValueError("special modulus is not in the outer chain")
        value = ceil_div(value, special) + ceil_div(
            output_plain * (ring_n + 1), 2
        )
        q //= special
        drops.append({
            "special": special,
            "remaining_q_bits": q.bit_length(),
            "v_bound": value,
            "v_bits": value.bit_length(),
            "decodes": 2 * value < q,
            "source_phase_16_fits": 16 * value <= q,
        })

    work_q = prod(WORK)
    if q != work_q:
        raise ValueError("outer drop chain did not reach the work modulus")
    return_rows, return_digit_sum = shape(WORK, 10)
    return_switch = 2 * output_plain * source_n * return_digit_sum * ETA
    returned = value + return_switch
    following = square_v(source_n, output_plain, work_q, returned, source_n)
    next_source = source_transform(following, source_n)
    source_cap = SOURCE_Q // 64
    return {
        "drops": drops,
        "work_q_bits": work_q.bit_length(),
        "return_key_digits": return_rows,
        "return_key_digit_sum": return_digit_sum,
        "return_switch_error": return_switch,
        "returned_v": returned,
        "returned_v_bits": returned.bit_length(),
        "returned_decodes": 2 * returned < work_q,
        "following_dense_square_v": following,
        "following_dense_square_v_bits": following.bit_length(),
        "following_dense_square_decodes": 2 * following < work_q,
        "following_dense_square_fits_work_q_over_128": 128 * following <= work_q,
        "next_prepared_source_v": next_source["source_v_bound"],
        "next_prepared_source_v_bits": next_source["source_v_bits"],
        "next_prepared_source_decodes": next_source["source_decode_fits"],
        "next_prepared_source_fits_q_over_64": next_source["source_v_bound"] <= source_cap,
    }


def plan():
    q_outer = prod(OUTER)
    q_source = SOURCE_Q
    carry_radius = ((SOURCE_NORM + 2) * (q_source - 1)) // (2 * q_source)
    phase_cap = q_source // SOURCE_PHASE_DENOMINATOR

    # There are H+1 centered component-rounding residuals in one phase
    # coefficient. Each is strictly below Q/2 because Q is odd. The phase
    # contribution is <=120/16, so the total integer residual is strictly
    # below 56 and therefore has absolute value at most 55. We retain 56 as
    # the public conservative corridor.
    strict_residual_numerator = (
        2 * WEIGHT_SCALE * phase_cap + (SOURCE_NORM + 1) * q_source
    )
    strict_residual_denominator = 2 * q_source
    strict_residual_ceiling = ceil_div(
        strict_residual_numerator, strict_residual_denominator
    )
    residual_bound = strict_residual_ceiling - 1

    weight_max = ceil_div(WEIGHT_SCALE, 2)
    weight_l1 = SOURCE_N * weight_max
    view120_v = chart_error(RESIDUE_PLAIN, q_outer)
    view121_v = chart_error(CARRY_PLAIN, q_outer)
    conversion_round_phase = ceil_div(1 + OUTER_N // 2, 2)
    conditional_view120_as121_v = component_scale_bound(
        view120_v, RESIDUE_PLAIN, CARRY_PLAIN,
        secret_l1=OUTER_N // 2,
    )
    conditional_carry_v = conditional_view120_as121_v + view121_v
    conditional_carry_to_output_v = component_scale_bound(
        conditional_carry_v, CARRY_PLAIN, OUTPUT_PLAIN,
        secret_l1=OUTER_N // 2,
    )

    scale_targets_coprime = all(
        gcd(target, prime) == 1
        for target in (RESIDUE_PLAIN, CARRY_PLAIN, OUTPUT_PLAIN)
        for prime in OUTER
    )
    conditions = {
        "safe_basis_contains_modulus_factors": all(
            p in SAFE_BASIS for p in (2, 3, 5, 11)
        ),
        "dependent_trays_are_120_and_121": RESIDUE_PLAIN == 120 and CARRY_PLAIN == 121,
        "adjacent_identity_is_120q_plus_r": CARRY_PLAIN == RESIDUE_PLAIN + 1,
        "source_carry_radius_is_48": carry_radius == 48,
        "strict_rounding_residual_bound_is_at_most_55": residual_bound <= 55,
        "residual_fits_centered_120_tray": 2 * residual_bound < RESIDUE_PLAIN,
        "carry_fits_centered_121_anchor": 2 * carry_radius < CARRY_PLAIN,
        "precharge_weight_bound": weight_max == 60 and weight_l1 == 491520,
        "encoding_scale_targets_coprime_to_outer_basis": scale_targets_coprime,
        "conditional_carry_decodes_if_scale_winding_zero": 2 * conditional_carry_v < q_outer,
        "conditional_output_decodes_if_scale_windings_zero": (
            2 * conditional_carry_to_output_v < q_outer
        ),
        "conditional_output_fits_outer_q_over_16_if_scale_windings_zero": (
            16 * conditional_carry_to_output_v <= q_outer
        ),
        "scale_conversion_secret_winding_is_corrected": False,
    }

    return {
        "scope": "Exact source lift and component arithmetic; ciphertext scale conversion has an uncorrected secret winding",
        "parameters": {
            "source_n": SOURCE_N,
            "outer_n": OUTER_N,
            "source_q_bits": q_source.bit_length(),
            "outer_q_bits": q_outer.bit_length(),
            "source_norm": SOURCE_NORM,
            "source_phase_denominator": SOURCE_PHASE_DENOMINATOR,
            "weight_scale": WEIGHT_SCALE,
            "residue_plaintext": RESIDUE_PLAIN,
            "carry_plaintext": CARRY_PLAIN,
            "output_plaintext": OUTPUT_PLAIN,
            "safe_basis": list(SAFE_BASIS),
            "outer_primes": list(OUTER),
        },
        "carry_radius": carry_radius,
        "strict_residual_ceiling": strict_residual_ceiling,
        "residual_abs_bound": residual_bound,
        "weight_max": weight_max,
        "weight_l1": weight_l1,
        "view120_error": view120_v,
        "view120_error_bits": view120_v.bit_length(),
        "view121_error": view121_v,
        "view121_error_bits": view121_v.bit_length(),
        "component_round_phase_bound": conversion_round_phase,
        "view120_component_rounding_bound_under_121": conditional_view120_as121_v,
        "conditional_carry_error_under_121": conditional_carry_v,
        "conditional_carry_error_under_121_bits": conditional_carry_v.bit_length(),
        "conditional_carry_converted_to_65537_error": conditional_carry_to_output_v,
        "conditional_carry_converted_to_65537_error_bits": conditional_carry_to_output_v.bit_length(),
        "adjacent_k_elimination": {
            "integer_lift": "z=120*K+e",
            "residue_view": "z mod120=e, |e|<=55",
            "anchor_view": "z mod121=e-K",
            "encoding_conversion": "componentwise 120/121 scale-round; ciphertext-level correctness requires correcting its secret winding J",
            "conditional_output": "Enc_121(e)-Enc_121(z)=Enc_121(K), if J=0 or corrected",
            "actual_output_message": "K-J mod121",
            "winding_shift": "120*J mod121 = -J mod121",
        },
        "conditions": conditions,
        "conditional_bounds_fit_if_windings_zero": all(
            conditions[name] for name in (
                "source_carry_radius_is_48",
                "strict_rounding_residual_bound_is_at_most_55",
                "residual_fits_centered_120_tray",
                "carry_fits_centered_121_anchor",
                "precharge_weight_bound",
                "encoding_scale_targets_coprime_to_outer_basis",
                "conditional_carry_decodes_if_scale_winding_zero",
                "conditional_output_decodes_if_scale_windings_zero",
                "conditional_output_fits_outer_q_over_16_if_scale_windings_zero",
            )
        ),
        "all_conditions_pass": False,
        "unknown_winding_error_bound_under_121": q_outer * (CARRY_PLAIN // 2),
        "first_nonzero_winding_case": {
            "winding": 1,
            "plaintext_shift": scale_winding_shift(1, RESIDUE_PLAIN, CARRY_PLAIN),
            "expected_carry_error_at_least_q": True,
        },
        "conditional_return_cycle_if_windings_zero": drop_and_return(
            conditional_carry_to_output_v, q_outer
        ),
        "rns_scale_round_primitive_implemented": False,
        "native_encrypted_execution": False,
        "public_refresh_admitted": False,
    }


def recover_carry(carry, residual, selected_plan=None):
    """Clear oracle for adjacent 120/121 residue K-Elimination."""
    p = plan() if selected_plan is None else selected_plan
    if abs(carry) > p["carry_radius"] or abs(residual) > p["residual_abs_bound"]:
        raise ValueError("case is outside the certified source envelope")
    z = WEIGHT_SCALE * carry + residual
    residue = centered(z, RESIDUE_PLAIN)
    anchor = centered(z, CARRY_PLAIN)
    recovered = centered(residue - anchor, CARRY_PLAIN)
    return recovered, z, residue, anchor


def rns_scale_divide(residues, moduli, input_plain, output_plain):
    """K-Eliminate one rounded component scale using only RNS residues.

    Return floor((input_plain*x + output_plain//2)/output_plain) modulo each
    main lane, where x is the centered CRT representative. The output_plain
    residue is the one adjacent anchor required by exact division.
    """
    if len(residues) != len(moduli) or not moduli:
        raise ValueError("RNS shape mismatch")
    q = prod(moduli)
    x = 0
    for residue, modulus in zip(residues, moduli):
        if not 0 <= residue < modulus:
            raise ValueError("noncanonical RNS residue")
        partial = q // modulus
        x += residue * partial * pow(partial, -1, modulus)
    x %= q
    x = centered(x, q)
    remainder = (input_plain * (x % output_plain) + output_plain // 2) % output_plain
    result = []
    for residue, modulus in zip(residues, moduli):
        numerator = (input_plain * residue + output_plain // 2) % modulus
        result.append(
            ((numerator - remainder) % modulus)
            * pow(output_plain, -1, modulus)
            % modulus
        )
    return result


if __name__ == "__main__":
    import json

    print(json.dumps(plan(), indent=2))
