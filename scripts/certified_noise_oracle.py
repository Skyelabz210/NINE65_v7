"""Independent exact-integer oracles for the partial C01 bound contract.

These functions validate FPD rounding, capacity arithmetic, and negacyclic
coefficient bounds. They do not issue or validate a production noise
certificate.
"""

from __future__ import annotations

from fractions import Fraction
from typing import Sequence


def _require_nonnegative(value: int, name: str) -> None:
    if value < 0:
        raise ValueError(f"{name} must be nonnegative")


def fpd_scale_round(x: int, plaintext_modulus: int, ciphertext_modulus: int) -> tuple[int, int]:
    """Return (Y, r) for Z=tX+floor(Q/2), Z=QY+r, 0<=r<Q."""
    if plaintext_modulus <= 0:
        raise ValueError("plaintext modulus must be positive")
    if ciphertext_modulus <= 0:
        raise ValueError("ciphertext modulus must be positive")
    z = plaintext_modulus * x + ciphertext_modulus // 2
    remainder = z % ciphertext_modulus
    quotient, exact_remainder = divmod(z, ciphertext_modulus)
    assert remainder == exact_remainder
    return quotient, remainder


def fpd_rounding_error(x: int, plaintext_modulus: int, ciphertext_modulus: int) -> Fraction:
    """Exact Y-tX/Q error; useful for checking the stated half-unit bound."""
    y, _ = fpd_scale_round(x, plaintext_modulus, ciphertext_modulus)
    return Fraction(y * ciphertext_modulus - plaintext_modulus * x, ciphertext_modulus)


def fpd_shift_multiplier(operand_bound_over_q_squared: int, plaintext_modulus: int) -> int:
    """Return s_mult=b*t+1 for |X|<=b*Q^2."""
    _require_nonnegative(operand_bound_over_q_squared, "operand bound")
    if plaintext_modulus <= 0:
        raise ValueError("plaintext modulus must be positive")
    return operand_bound_over_q_squared * plaintext_modulus + 1


def fpd_auxiliary_capacity_holds(
    auxiliary_product: int,
    operand_bound_over_q_squared: int,
    plaintext_modulus: int,
    ciphertext_modulus: int,
) -> bool:
    """Check the strict A > 2*s_mult*Q FPD lift condition."""
    if auxiliary_product <= 0 or ciphertext_modulus <= 0:
        return False
    shift_multiplier = fpd_shift_multiplier(operand_bound_over_q_squared, plaintext_modulus)
    return auxiliary_product > 2 * shift_multiplier * ciphertext_modulus


def negacyclic_mul(left: Sequence[int], right: Sequence[int]) -> list[int]:
    """Exact multiplication in Z[X]/(X^N+1), with no modular reduction."""
    if not left or len(left) != len(right):
        raise ValueError("operands must have the same nonzero degree")
    n = len(left)
    result = [0] * n
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            degree = i + j
            if degree >= n:
                result[degree - n] -= a * b
            else:
                result[degree] += a * b
    return result


def tensor_cross_component(
    a0: Sequence[int], a1: Sequence[int], b0: Sequence[int], b1: Sequence[int]
) -> list[int]:
    """Compute d1=a0*b1+a1*b0 in the negacyclic ring."""
    left = negacyclic_mul(a0, b1)
    right = negacyclic_mul(a1, b0)
    return [x + y for x, y in zip(left, right)]


def coefficient_product_bound(n: int, left_bound: int, right_bound: int) -> int:
    """Coefficient infinity bound N*||a||inf*||b||inf."""
    if n <= 0:
        raise ValueError("ring degree must be positive")
    _require_nonnegative(left_bound, "left coefficient bound")
    _require_nonnegative(right_bound, "right coefficient bound")
    return n * left_bound * right_bound


def tensor_cross_bound(n: int, left_bound: int, right_bound: int) -> int:
    """Bound the sum of the two ciphertext cross products."""
    return 2 * coefficient_product_bound(n, left_bound, right_bound)


def centered(value: int, modulus: int) -> int:
    residue = value % modulus
    return residue - modulus if 2 * residue > modulus else residue


def scalar_ciphertext(message, error, c1, secret, q, t):
    """Oracle-only ciphertext with prescribed fresh phase; no Rust code reused."""
    product = negacyclic_mul(c1, secret)
    c0 = [centered(e - p, q) for e, p in zip(error, product)]
    c0[0] = centered(c0[0] + (q // t) * (message % t), q)
    return c0, list(c1)


def phase_error(ciphertext, message, secret, q, t):
    """Exact integer t*E, choosing the phase lift modulo tQ (oracle only)."""
    phase = list(ciphertext[0])
    power = [1] + [0] * (len(secret) - 1)
    for component in ciphertext[1:]:
        power = negacyclic_mul(power, secret)
        phase = [x + y for x, y in zip(phase, negacyclic_mul(component, power))]
    result = [centered(t * coefficient, t * q) for coefficient in phase]
    result[0] = centered(t * phase[0] - q * centered(message, t), t * q)
    return result


def multiply_tensor(left, right, q, t):
    tensor = [negacyclic_mul(left[0], right[0]),
              tensor_cross_component(*left, *right),
              negacyclic_mul(left[1], right[1])]
    return [[(t * x + q // 2) // q for x in component] for component in tensor]


def scalar_multiply_bound(n, t, q, va, vb, switch_error=0):
    """Bound on ||tE_out|| for admitted scalar BFV operands, before/after switch."""
    if n < 2 or n % 2 or t < 3 or t % 2 == 0 or min(va, vb) < 0 or 2 * max(va, vb) >= q:
        raise ValueError("unadmitted scalar BFV operands")
    factor = (t - 1) // 2 + n * t * (n // 2 + 1)
    return (factor * (va + vb) + (n // 2) * min(va, vb)
            + (t * (1 + n + n * n) + 1) // 2 + t * switch_error)
