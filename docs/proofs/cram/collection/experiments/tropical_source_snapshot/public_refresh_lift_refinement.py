"""Exact research oracles for bounded native and conservative box-ball lifts.

These clear oracles establish arithmetic relations. They do not produce
encrypted anchor views or select a soliton evolution rule.
"""

from dataclasses import dataclass
from fractions import Fraction
from math import gcd


def project_lift(main: int, anchor_view: int, shell: int, anchor: int,
                 upper: int, target: int) -> int:
    """Derive a bounded sheet locally and emit only a target residue.

    The caller must bind both views and the interval to one source. An aliased
    source outside the declared interval cannot be detected from these views.
    """
    if shell < 2 or anchor < 2 or gcd(shell, anchor) != 1:
        raise ValueError("coprime shell and anchor required")
    if not 0 <= upper < shell * anchor:
        raise ValueError("interval must be smaller than the paired capacity")
    if not 0 <= main < shell or not 0 <= anchor_view < anchor or target < 1:
        raise ValueError("noncanonical view or invalid target")
    sheet = ((anchor_view - main) * pow(shell, -1, anchor)) % anchor
    if (sheet, main) > divmod(upper, shell):
        raise ValueError("derived value exceeds the certified interval")
    return (main % target + (shell % target) * (sheet % target)) % target


def project_native_signed(main: int, anchor_view: int, target: int) -> int:
    """Views encode Y=K+48 in [0,96], not the canonical K mod 65537."""
    return (project_lift(main, anchor_view, 36, 37, 96, target) - 48) % target


def interpolation_values(values: tuple[int, ...], prime: int) -> tuple[int, ...]:
    """Independent monomial interpolation on inputs 0..len(values)-1."""
    polynomial = [1]
    for root in range(len(values)):
        result = [0] * (len(polynomial) + 1)
        for i, coefficient in enumerate(polynomial):
            result[i] = (result[i] - root * coefficient) % prime
            result[i + 1] = (result[i + 1] + coefficient) % prime
        polynomial = result
    result = [0] * len(values)
    for root, value in enumerate(values):
        quotient = [0] * len(values)
        quotient[-1] = 1
        for i in range(len(quotient) - 2, -1, -1):
            quotient[i] = (polynomial[i + 1] + root * quotient[i + 1]) % prime
        derivative = polynomial_value(tuple(quotient), root, prime)
        scale = value * pow(derivative, -1, prime) % prime
        for i, coefficient in enumerate(quotient):
            result[i] = (result[i] + scale * coefficient) % prime
    while len(result) > 1 and result[-1] == 0:
        result.pop()
    return tuple(result)


def polynomial_value(coefficients: tuple[int, ...], value: int, prime: int) -> int:
    result = 0
    for coefficient in reversed(coefficients):
        result = (result * value + coefficient) % prime
    return result


@dataclass(frozen=True)
class ConservativeBoxBallFlow:
    """A supplied finite transition, not a rule that invents its successor.

    Clear-source validation binds both snapshots and their conserved mass.
    An encrypted implementation would need an admitted counterpart of this
    producer, including the user's additional topology/evolution constraints.
    """

    before: tuple[int, ...]
    after: tuple[int, ...]
    shell: int = 36
    anchor: int = 37

    def __post_init__(self) -> None:
        if any(not isinstance(cells, tuple) or any(type(v) is not int or v not in (0, 1)
               for v in cells) for cells in (self.before, self.after)):
            raise ValueError("immutable binary snapshots required")
        if len(self.before) != len(self.after) or sum(self.before) != sum(self.after):
            raise ValueError("complete snapshots must conserve mass")
        project_lift(0, 0, self.shell, self.anchor, 2 * sum(self.before), 1)

    def carrier_mod(self, index: int, target: int) -> int:
        if not 0 <= index <= len(self.before):
            raise ValueError("prefix index outside the finite snapshot")
        incoming = sum(self.before[:index])
        outgoing = sum(self.after[:index])
        # Signed net flux C lies in [-B,B]; derive views of Y=C+B in [0,2B].
        # No scalar carrier or epoch is stored.
        bound = sum(self.before)
        main = (incoming % self.shell - outgoing % self.shell + bound) % self.shell
        anchor_view = (incoming % self.anchor - outgoing % self.anchor + bound) % self.anchor
        return (project_lift(main, anchor_view, self.shell, self.anchor,
                             2 * bound, target) - bound) % target

    def lifted_height_mod(self, index: int, target: int) -> int:
        carrier = self.carrier_mod(index, target)
        height = (index - 2 * sum(self.before[:index])) % target
        return (height + 2 * carrier) % target

    @staticmethod
    def height_at(cells: tuple[int, ...], position: Fraction) -> Fraction:
        if not isinstance(position, Fraction) or not 0 <= position <= len(cells):
            raise ValueError("exact rational position inside the snapshot required")
        index = position.numerator // position.denominator
        height = index - 2 * sum(cells[:index])
        if index == len(cells):
            return Fraction(height)
        return height + (position - index) * (1 - 2 * cells[index])
