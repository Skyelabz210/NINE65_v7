#!/usr/bin/env python3
"""Exact bounds for a scale-locked source-carry tray.

This checks a useful encoding identity and its limit.  If z=A*K+e is
encrypted with plaintext T=p*A, the same ciphertext re-decodes as K under p;
the Q-winding contributes p*J and vanishes modulo p.  The residual e/A remains
as phase error, so this is not a refresh unless an encrypted canonical section
removes e in the T encoding first.
"""

from math import prod

from compact_phase_clock_budget import ETA, P, SOURCE_Q, shape
from full_polynomial_bootstrap_budget import WORK, square_v
from outer_ring_return_budget import EXTRA, OUTER
from source_encapsulation_budget import source_transform


SOURCE_N = 8192
OUTER_N = 2 * SOURCE_N
SOURCE_NORM = 96
PHASE_DENOMINATOR = 64
SAFE_ROOTS = (2, 11)


def ceil_div(n, d):
    if d <= 0:
        raise ValueError("positive denominator required")
    return -((-n) // d)


def carry_radius(norm=SOURCE_NORM, q=SOURCE_Q):
    return ((norm + 2) * (q - 1)) // (2 * q)


def strict_residual_bound(scale, norm=SOURCE_NORM, q=SOURCE_Q,
                          phase_denominator=PHASE_DENOMINATOR):
    """Integer bound from H+1 strict half-rounding errors and source phase."""
    numerator = (norm + 1) * q + 2 * scale * (q // phase_denominator)
    return ceil_div(numerator, 2 * q) - 1


def return_cycle(output_v, q_outer=None):
    q = prod(OUTER) if q_outer is None else q_outer
    value = output_v
    levels = []
    for special in reversed(EXTRA):
        value = ceil_div(value, special) + ceil_div(P * (OUTER_N + 1), 2)
        q //= special
        levels.append({
            "special": special,
            "remaining_q_bits": q.bit_length(),
            "v_bits": value.bit_length(),
            "decodes": 2 * value < q,
        })

    q_work = prod(WORK)
    if q != q_work:
        raise ValueError("outer drop chain did not reach work modulus")
    _, digit_sum = shape(WORK, 10)
    return_switch = 2 * P * SOURCE_N * digit_sum * ETA
    returned = value + return_switch
    following = square_v(SOURCE_N, P, q_work, returned, SOURCE_N)
    following_decodes = 2 * following < q_work
    next_source = source_transform(following, SOURCE_N) if following_decodes else None
    return {
        "drops": levels,
        "returned_v_bits": returned.bit_length(),
        "returned_decodes": 2 * returned < q_work,
        "following_dense_square_v_bits": following.bit_length(),
        "following_dense_square_decodes": following_decodes,
        "next_source_v_bits": None if next_source is None else next_source["source_v_bits"],
        "next_source_phase_fits_q_over_64": (
            False if next_source is None
            else next_source["source_v_bound"] <= SOURCE_Q // 64
        ),
    }


def plan(scale):
    if scale < 2:
        raise ValueError("scale must be at least two")
    q_outer = prod(OUTER)
    input_plain = P * scale
    residual = strict_residual_bound(scale)
    carry = carry_radius()
    max_weight = scale // 2 if scale % 2 == 0 else (scale + 1) // 2
    weight_l1 = SOURCE_N * max_weight
    remainder = q_outer % input_plain
    fresh_precharge = (
        input_plain * (2 * OUTER_N + 1) * ETA
        + remainder * (input_plain - 1)
    )
    view_v = fresh_precharge * weight_l1 + remainder * max_weight

    # z=A*K+e is encoded under T=p*A. Re-decoding the unchanged phase under p
    # has ideal message z/A; its Q-winding contributes p*J, which is zero
    # modulo p. Since T=p*A, the output's scaled error is
    # (T*phase-Q*z)/A + Q*e/A. This carries the old view error and the source
    # residual into the output certificate.
    output_v = ceil_div(view_v + q_outer * residual, scale)
    output_decodes = 2 * output_v < q_outer

    conditions = {
        "input_plaintext_fits_every_outer_lane": input_plain < min(OUTER),
        "safe_root_factors_present": all(scale % root == 0 for root in SAFE_ROOTS),
        "source_carry_fits_scale_residual": 2 * residual < scale,
        "weighted_lift_fits_input_plaintext": 2 * (scale * carry + residual) < input_plain,
        "same_phase_redecode_recovers_integer_carry": 2 * residual < scale,
        "output_phase_decodes": output_decodes,
        "following_dense_product_decodes": False,
    }
    cycle = return_cycle(output_v, q_outer)
    conditions["following_dense_product_decodes"] = cycle["following_dense_square_decodes"]
    return {
        "scope": "same-phase re-decode identity and exact noise/return bounds; no canonical residual producer",
        "parameters": {
            "source_n": SOURCE_N,
            "outer_n": OUTER_N,
            "source_q_bits": SOURCE_Q.bit_length(),
            "outer_q_bits": q_outer.bit_length(),
            "source_norm": SOURCE_NORM,
            "source_phase_cap": f"Q_source/{PHASE_DENOMINATOR}",
            "scale_A": scale,
            "input_plaintext_T": input_plain,
            "output_plaintext_p": P,
            "safe_roots": list(SAFE_ROOTS),
            "outer_min_lane": min(OUTER),
        },
        "carry_radius": carry,
        "strict_residual_bound": residual,
        "weighted_lift_abs_bound": scale * carry + residual,
        "fresh_precharge_v_bits": fresh_precharge.bit_length(),
        "weighted_view_v_bits": view_v.bit_length(),
        "same_phase_output_v_bound": output_v,
        "same_phase_output_v_bits": output_v.bit_length(),
        "same_phase_output_decodes": output_decodes,
        "residual_fraction_bound": f"{residual}/{scale}",
        "hidden_q_winding_shift_mod_p": "p*J = 0 mod p",
        "canonical_residual_requirement": {
            "function": "F_T(A*K+e)=e mod T",
            "required_residual_range": [-residual, residual],
            "jacobian_condition": "exact finite-difference invariance F_T(A*(K+1)+e)=F_T(A*K+e) on the domain; zero Jacobian alone needs higher-order and boundary proof",
            "contraction": "(Enc_T(A*K+e)-Enc_T(e)) is exactly divisible by A and reinterprets as Enc_p(K)",
        },
        "return_cycle": cycle,
        "conditions": conditions,
        "all_conditions_pass": all(conditions.values()),
        "native_encrypted_execution": False,
        "canonical_residual_producer": False,
        "public_refresh_admitted": False,
    }


def same_phase_decode(message, winding, scale):
    """Ideal rational decoder; return representative modulo p."""
    # p*(message/(p*A) + winding) = message/A + p*winding.
    numerator = message + (P * scale) * winding
    denominator = scale
    decoded = (numerator + denominator // 2) // denominator
    return decoded % P


if __name__ == "__main__":
    import json

    print(json.dumps({"candidate_A_121": plan(121), "candidate_A_5632": plan(5632)}, indent=2))
