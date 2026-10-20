"""Exact p^2 residual bound for the existing certified scalar main-Q route.

Partial R01: no temporary-key switch or slot transform is assumed. The input
unit V is ||t*phase-Q*m|| modulo tQ, already including floor-encoding error.
This does not certify a complete refresh or the bootstrap ciphertext noise.
"""

from fractions import Fraction


def residual_radius(q, p, n, scaled_error):
    if (q < 3 or q % 2 == 0 or p < 3 or p % 2 == 0 or n < 1
            or scaled_error < 0 or 2 * scaled_error >= q):
        raise ValueError("requires an admitted ideal-grid history bound and odd moduli")
    # Expanded component rounding contributes at most (Q-1)/(2Q) per
    # term. For arbitrary supported ternary secrets, ||s||_1 <= N.
    bound = Fraction(p * scaled_error, q) + (n + 1) * Fraction(q - 1, 2 * q)
    return bound.numerator // bound.denominator


def supports_bounded_digit(q, p, n, scaled_error, bound):
    return 0 <= 2 * bound < p and residual_radius(q, p, n, scaled_error) <= bound
