"""Exact finite witnesses for the supplied documents; not an FHE proof."""
from collections import Counter
from fractions import Fraction
from math import factorial, gcd, prod
import unittest


class MaterialContracts(unittest.TestCase):
    def test_bounded_carry_and_signed_congruence(self):
        for m, a in ((17, 19), (36, 37), (37, 73)):
            inv = pow(m, -1, a)
            for x in range(-m * a, m * a):
                k = ((x % a - x % m) * inv) % a
                self.assertEqual(k, (x // m) % a)
                if 0 <= x < m * a:
                    self.assertEqual(k, x // m)

    def test_non_coprime_resolution(self):
        for m, a in ((4, 6), (6, 9), (10, 15), (260, 365)):
            d = gcd(m, a)
            for x in range(m * a):
                delta = x % a - x % m
                self.assertEqual(delta % d, 0)
                k = (delta // d * pow(m // d, -1, a // d)) % (a // d)
                self.assertEqual(k, (x // m) % (a // d))

    def test_signed_alias_requires_independent_bound(self):
        m, a, r = 17, 19, 3
        x, y = r - m, r + (a - 1) * m
        self.assertEqual((x % m, x % a), (y % m, y % a))
        self.assertTrue(abs(-1) < a and abs(a - 1) < a)
        self.assertNotEqual(x // m, y // m)

    def test_main_lanes_do_not_identify_absolute_winding(self):
        x, y, b, m = 6, 111, 3, 35
        self.assertEqual((x % 5, x % 7), (y % 5, y % 7))
        self.assertEqual((x % b, y % b), (0, 0))
        self.assertNotEqual(x // m, y // m)
        self.assertEqual((x // b) % m, (y // b) % m)
        with self.assertRaises(ValueError):
            pow(m // 7, -1, 5)  # main.pdf section 2.4

    def test_blueprint_inverse_and_modswitch_counterexamples(self):
        t, delta = 3, 4
        q, a = t * delta, t * delta + 1
        self.assertNotEqual(t * (q + 1 - t) % a, 1)
        self.assertEqual(t * (-delta) % a, 1)
        self.assertEqual(delta * (-t) % a, 1)
        # Actual Q -> t scaling is t/Q; the proposed switch divides by t.
        q, t, x = 13, 3, 6
        self.assertEqual((2 * t * x + q) // (2 * q), 1)
        self.assertEqual((2 * x + t) // (2 * t), 2)
        self.assertNotEqual(q % t, 0)

    def test_adding_a_lane_does_not_remove_shared_factors(self):
        self.assertEqual(gcd(3, 15), 3)
        self.assertEqual(gcd(3, 15 * 7), 3)
        for p in (3, 5, 7, 11, 13):
            self.assertEqual(gcd(p - 1, p + 1), 2)

    def test_frozen_quantization_is_not_frozen_output_error(self):
        true, quantized = Fraction(3, 2), 1
        self.assertEqual(abs(true - quantized), Fraction(1, 2))
        self.assertEqual(abs(10 * true - 10 * quantized), 5)

    def test_bridge_capacity_claim(self):
        capacity = prod(p**e for p, e in zip((2, 3, 5, 7, 11), (64, 40, 27, 22, 18)))
        self.assertGreater(capacity, 2**314)
        self.assertEqual(capacity.bit_length(), 315)

    def test_hidden_carry_boundary_claims(self):
        self.assertNotEqual((-0) % 37, 37 - (0 % 37))
        self.assertEqual(Counter(x * x % 2 for x in range(2)), {0: 1, 1: 1})
        # Nonuniform point-mass operands produce a constant, hence Markov, stream.
        carry, digits = 0, []
        for _ in range(20):
            carry, digit = divmod(carry + 0 + 0, 4)
            digits.append(digit)
        self.assertEqual(digits, [0] * 20)

    def test_reported_carry_fluxes(self):
        # Uniform independent base-b digits. Compute sum laws by convolution;
        # Eulerian stationary probabilities and currents use exact Fractions.
        for base, n, expected in ((13, 4, Fraction(7, 13182)),
                                   (13, 5, Fraction(21, 114244)),
                                   (2, 4, Fraction(1, 384)),
                                   (2, 5, Fraction(1, 640))):
            counts = Counter({0: 1})
            for _ in range(n):
                nxt = Counter()
                for s, count in counts.items():
                    for digit in range(base):
                        nxt[s + digit] += count
                counts = nxt
            p = [[Fraction(sum(v for s, v in counts.items() if (s + i) // base == j), base**n)
                  for j in range(n)] for i in range(n)]
            eulerian = [1]
            for order in range(2, n + 1):
                eulerian = [(k + 1) * (eulerian[k] if k < len(eulerian) else 0)
                            + (order - k) * (eulerian[k - 1] if k else 0)
                            for k in range(order)]
            pi = [Fraction(v, factorial(n)) for v in eulerian]
            self.assertEqual([sum(pi[i] * p[i][j] for i in range(n)) for j in range(n)], pi)
            self.assertEqual(max(abs(pi[i] * p[i][j] - pi[j] * p[j][i])
                                 for i in range(n) for j in range(n)), expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
