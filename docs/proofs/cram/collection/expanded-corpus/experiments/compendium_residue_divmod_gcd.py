"""Independent bounded closure model, not an uploaded/production CRAM kernel.

Runtime number state consists of two authentic residues. K is a transient order
query. No stored input integer, persistent K, reconstruction, or Garner/MRC.
Scalar integers occur only at ingress and in the independent test oracle.
Repeated subtraction is deliberately simple; no efficiency/FHE claim is made.
"""
from dataclasses import dataclass, fields
from math import gcd
from random import Random
import json


@dataclass(frozen=True, slots=True)
class Residues:
    main: int
    anchor: int


@dataclass(frozen=True, slots=True)
class Frame:
    main_modulus: int
    anchor_modulus: int
    inverse: int

    @staticmethod
    def create(m, a):
        assert m > 1 and a > 1 and gcd(m, a) == 1
        return Frame(m, a, pow(m, -1, a))

    def ingress(self, value):
        """Declared boundary; the runtime does not call this method."""
        assert 0 <= value < self.main_modulus * self.anchor_modulus
        return Residues(value % self.main_modulus, value % self.anchor_modulus)

    def transient_k(self, x):
        return ((x.anchor - x.main) * self.inverse) % self.anchor_modulus

    def less(self, x, y):
        return (self.transient_k(x), x.main) < (self.transient_k(y), y.main)

    def subtract_nonnegative(self, x, y):
        """Caller has established y <= x; subtraction preserves the window."""
        return Residues((x.main-y.main) % self.main_modulus,
                        (x.anchor-y.anchor) % self.anchor_modulus)

    def increment_bounded(self, x):
        """Caller invariant establishes value(x)+1 < capacity."""
        return Residues((x.main+1) % self.main_modulus,
                        (x.anchor+1) % self.anchor_modulus)

    def divmod(self, dividend, divisor):
        if divisor == Residues(0, 0):
            raise ZeroDivisionError('zero divisor')
        quotient = Residues(0, 0)
        remainder = dividend
        while not self.less(remainder, divisor):
            remainder = self.subtract_nonnegative(remainder, divisor)
            quotient = self.increment_bounded(quotient)
        return quotient, remainder

    def greatest_common_divisor(self, a, b):
        while b != Residues(0, 0):
            _, remainder = self.divmod(a, b)
            a, b = b, remainder
        return a


def check_pair(frame, a, b, counts):
    ar, br = frame.ingress(a), frame.ingress(b)
    assert frame.less(ar, br) == (a < b)
    counts['comparisons'] += 1
    assert frame.greatest_common_divisor(ar, br) == frame.ingress(gcd(a, b))
    counts['gcd_pairs'] += 1
    if b:
        q, r = frame.divmod(ar, br)
        assert q == frame.ingress(a // b)
        assert r == frame.ingress(a % b)
        counts['divmod_pairs'] += 1
        if gcd(b, frame.main_modulus) > 1:
            counts['divmod_shared_main_factor'] += 1
        if a % b:
            counts['divmod_inexact_integer_inputs'] += 1
    else:
        try:
            frame.divmod(ar, br)
        except ZeroDivisionError:
            counts['zero_refusals'] += 1
        else:
            raise AssertionError('division by zero accepted')


def main():
    counts = dict(comparisons=0, gcd_pairs=0, divmod_pairs=0,
                  divmod_shared_main_factor=0, divmod_inexact_integer_inputs=0,
                  zero_refusals=0)
    frames = [(2, 3), (3, 4), (5, 7), (6, 7), (12, 13)]
    for m, a in frames:
        frame = Frame.create(m, a)
        for x in range(m*a):
            for y in range(m*a):
                check_pair(frame, x, y, counts)
    frame = Frame.create(36, 37)
    cap = 36*37
    points = [0, 1, 2, 35, 36, 37, 665, 666, 667, 1295, 1296, 1297, 1330, 1331]
    for x in points:
        for y in points:
            check_pair(frame, x, y, counts)
    rng = Random(20261112)
    for _ in range(10000):
        check_pair(frame, rng.randrange(cap), rng.randrange(cap), counts)

    # Boundary refusal at ingress, plus a mutation control showing why the
    # range certificate is material (out-of-domain observations alias).
    refused = 0
    for value in (-1, cap, 2*cap):
        try:
            frame.ingress(value)
        except AssertionError:
            refused += 1
        else:
            raise AssertionError('invalid range admitted')
    assert refused == 3
    outside = cap + 1
    collapsed = Residues(outside % 36, outside % 37)
    assert collapsed == frame.ingress(1)
    assert frame.less(collapsed, frame.ingress(2)) and not outside < 2
    # Mutation: invert the sign of the adjacency extraction. The suite must
    # distinguish it from the correct comparator.
    x, y = frame.ingress(36), frame.ingress(72)
    wrong = lambda t: (t.anchor-t.main) % 37
    assert frame.less(x,y) and not ((wrong(x),x.main) < (wrong(y),y.main))
    assert [f.name for f in fields(Residues)] == ['main','anchor']

    print(json.dumps(dict(status='PASS', scope='independent bounded reference model',
        exhaustive_frames=frames, sampled_frame=[36,37], sample_seed=20261112,
        random_pairs=10000, boundary_pairs=len(points)**2, **counts,
        ingress_refusals=refused, negative_controls={
            'outside_window_alias_breaks_order':True,
            'reversed_anchor_subtraction_breaks_order':True},
        runtime_state_fields=['main','anchor'],
        performance_claim='none; repeated subtraction, data-dependent branches'),indent=2))


if __name__ == '__main__':
    main()
