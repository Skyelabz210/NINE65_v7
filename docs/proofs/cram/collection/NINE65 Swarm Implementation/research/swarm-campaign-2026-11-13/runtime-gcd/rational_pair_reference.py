"""Bounded clear reference for a future residue/encrypted rational-pair adapter.

This is not a ciphertext implementation. Scalar integers are specification
inputs here, never a substitute for the production residue or encrypted state.
"""

from dataclasses import dataclass


def fixed_gcd(a: int, b: int, width: int) -> int:
    if type(width) is not int or not 1 <= width <= 64:
        raise ValueError("reference width must be 1..64")
    if any(type(v) is not int or not 0 <= v < 1 << width for v in (a, b)):
        raise ValueError("unsigned operand exceeds public width")
    for _ in range(2 * width):
        if b:
            a, b = b, a % b
    return a


@dataclass(frozen=True)
class RationalPair:
    numerator: int
    denominator: int
    width: int

    def __post_init__(self):
        if type(self.width) is not int or not 1 <= self.width <= 64:
            raise ValueError("reference width must be 1..64")
        if type(self.numerator) is not int or type(self.denominator) is not int:
            raise ValueError("integer pair required")
        if self.denominator <= 0:
            raise ValueError("positive denominator required")
        if max(abs(self.numerator), self.denominator) >= 1 << self.width:
            raise OverflowError("pair exceeds public width")
        if fixed_gcd(abs(self.numerator), self.denominator, self.width) != 1:
            raise ValueError("use normalized() for an unreduced pair")

    @classmethod
    def normalized(cls, numerator: int, denominator: int, width: int):
        if type(numerator) is not int or type(denominator) is not int or denominator == 0:
            raise ValueError("integer numerator and nonzero integer denominator required")
        if denominator < 0:
            numerator, denominator = -numerator, -denominator
        factor = fixed_gcd(abs(numerator), denominator, width)
        return cls(numerator // factor, denominator // factor, width)

    def multiply(self, other: "RationalPair") -> "RationalPair":
        if self.width != other.width:
            raise ValueError("public widths must agree")
        left = fixed_gcd(abs(self.numerator), other.denominator, self.width)
        right = fixed_gcd(abs(other.numerator), self.denominator, self.width)
        numerator = (self.numerator // left) * (other.numerator // right)
        denominator = (self.denominator // right) * (other.denominator // left)
        return RationalPair(numerator, denominator, self.width)


if __name__ == "__main__":
    from fractions import Fraction
    import json
    normalization_cases = 0
    for n in range(-31, 32):
        for d in range(1, 32):
            pair = RationalPair.normalized(n, d, 16)
            assert Fraction(pair.numerator, pair.denominator) == Fraction(n, d)
            normalization_cases += 1
    multiplication_cases = 0
    inputs = [(n, d) for n in range(-7, 8) for d in range(1, 8)]
    for n, d in inputs:
        for m, e in inputs:
            a, b = RationalPair.normalized(n, d, 16), RationalPair.normalized(m, e, 16)
            result = a.multiply(b)
            assert Fraction(result.numerator, result.denominator) == Fraction(n, d) * Fraction(m, e)
            multiplication_cases += 1
    assert RationalPair.normalized(200, 3, 8).multiply(
        RationalPair.normalized(3, 200, 8)) == RationalPair(1, 1, 8)
    assert 200 * 3 >= 1 << 8  # naive intermediate exceeds the same capacity
    assert RationalPair.normalized(1, -2, 8) == RationalPair(-1, 2, 8)
    assert RationalPair.normalized(0, 17, 8) == RationalPair(0, 1, 8)
    for thunk, expected in [
        (lambda: RationalPair.normalized(1, 0, 8), ValueError),
        (lambda: RationalPair.normalized(256, 1, 8), ValueError),
        (lambda: RationalPair(2, 4, 8), ValueError),
        (lambda: RationalPair(200, 1, 8).multiply(RationalPair(2, 1, 8)), OverflowError),
        (lambda: RationalPair(1, 2, 8).multiply(RationalPair(1, 2, 9)), ValueError),
    ]:
        try:
            thunk()
        except expected:
            pass
        else:
            raise AssertionError("expected refusal")
    print(json.dumps({"status": "PASS", "normalization_cases": normalization_cases,
                      "multiplication_cases": multiplication_cases,
                      "refusal_controls": 5,
                      "cross_cancellation_capacity_example": "200/3 * 3/200 = 1 within 8 bits",
                      "scope": "clear reference, not residue-native or encrypted implementation"}, indent=2))
