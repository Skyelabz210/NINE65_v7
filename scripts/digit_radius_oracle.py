"""Exact research bounds for two distinct layers of noisy expansion.

V = ||p*phase-Q*m|| modulo pQ includes floor-encoding error and prior history.
The inner secret bounds the plaintext residual; the outer encryption has a
separate BFV error bound. These arithmetic oracles do not authenticate history,
certify a key distribution, model slot transforms, or enable public refresh.
"""

from fractions import Fraction
from math import gcd


def residual_radius(q, p, n, scaled_error):
    """Legacy dense-ternary bound, using the full ring degree n."""
    if n < 1:
        raise ValueError("requires a positive ring degree")
    return residual_radius_for_secret(q, p, n, scaled_error)


def residual_radius_for_secret(q, p, secret_l1_bound, scaled_error):
    """H must bound the secret AT component rounding, not the outer key."""
    if (q < 3 or q % 2 == 0 or p < 3 or p % 2 == 0 or secret_l1_bound < 0
            or scaled_error < 0 or 2 * scaled_error >= q):
        raise ValueError("requires an admitted ideal-grid history bound and odd moduli")
    bound = (Fraction(p * scaled_error, q)
             + (secret_l1_bound + 1) * Fraction(q - 1, 2 * q))
    return bound.numerator // bound.denominator


def supports_bounded_digit(q, p, n, scaled_error, bound):
    return 0 <= 2 * bound < p and residual_radius(q, p, n, scaled_error) <= bound


def modswitch_scaled_error_bound(q_from, q_to, p, secret_l1_bound, scaled_error):
    """Nearest-component Q -> q switch, before changing the secret.

    This models an explicit rounding rule, not every BFV implementation's
    modswitch. V_to <= floor(q/Q*V + p*(1+H)*(Q-1)/(2Q)).
    """
    residual_radius_for_secret(q_from, p, secret_l1_bound, scaled_error)
    if q_to < 3 or q_to % 2 == 0 or q_to > q_from:
        raise ValueError("requires an odd target modulus no larger than Q")
    bound = (Fraction(q_to * scaled_error, q_from)
             + p * (secret_l1_bound + 1) * Fraction(q_from - 1, 2 * q_from))
    return bound.numerator // bound.denominator


def sparse_route_radius(q_from, q_sparse, p, dense_l1, sparse_l1,
                        scaled_error, switch_phase_error):
    """Compose modswitch, same-q key switch, then p^2 expansion.

    switch_phase_error is a proved bound on ||sum digit_j*error_j||, in
    unscaled phase units. It must include every evaluation-key error term.
    The caller's V is AFTER any slots-to-coefficients transform.
    """
    if switch_phase_error < 0:
        raise ValueError("key-switch phase error must be nonnegative")
    before_switch = modswitch_scaled_error_bound(
        q_from, q_sparse, p, dense_l1, scaled_error)
    after_switch = before_switch + p * switch_phase_error
    radius = residual_radius_for_secret(q_sparse, p, sparse_l1, after_switch)
    return {"post_modswitch_scaled_error": before_switch,
            "post_keyswitch_scaled_error": after_switch,
            "plaintext_residual_radius": radius}


def rns_keyswitch_phase_bound(source_moduli, n, eta, base_bits):
    """Independent source lanes; each gadget-key error has support [-eta,eta].

    K <= N*eta*(2^b-1)*sum_i ceil(bitlen(q_i-1)/b). CRT idempotents
    belong in the encrypted key messages, not as multipliers of their errors.
    This is NOT an implementation or a sparse-key security certificate.
    """
    if (not source_moduli or n < 1 or eta < 0 or base_bits < 1
            or any(q < 3 or q % 2 == 0 for q in source_moduli)
            or any(gcd(a, b) != 1 for i, a in enumerate(source_moduli)
                   for b in source_moduli[i + 1:])):
        raise ValueError("requires independent odd source lanes and valid sampler/digit support")
    digits = sum(((q - 1).bit_length() + base_bits - 1) // base_bits for q in source_moduli)
    return n * eta * ((1 << base_bits) - 1) * digits


def outer_expansion_scaled_error_bound(q, plaintext_modulus, a0, a1,
                                       inner_secret_l1, encapsulation_error):
    """Bound outer W=||P*phase-Q*w|| modulo PQ for Enc_P(a0+a1*s).

    a0,a1 are the exact centered public lifts used in evaluation; the key
    encrypts centered s with phase floor(Q/P)*s+e and ||e|| <= beta.
    W <= P*||a1||_1*beta + (Q mod P)*(||a0||inf+||a1||inf*H_inner).
    Outer secret/sampler contributions belong in beta, not in inner rho.
    """
    if (q < 3 or q % 2 == 0 or plaintext_modulus < 3
            or plaintext_modulus % 2 == 0 or q <= plaintext_modulus
            or not a0 or len(a0) != len(a1)
            or inner_secret_l1 < 0 or encapsulation_error < 0
            or any(2 * abs(x) >= plaintext_modulus for x in (*a0, *a1))):
        raise ValueError("requires centered components, odd moduli, and nonnegative bounds")
    return (plaintext_modulus * sum(map(abs, a1)) * encapsulation_error
            + (q % plaintext_modulus)
            * (max(map(abs, a0)) + max(map(abs, a1)) * inner_secret_l1))
