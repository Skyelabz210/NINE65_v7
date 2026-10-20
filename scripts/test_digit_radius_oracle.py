import itertools
import unittest

from certified_noise_oracle import centered, negacyclic_mul, phase_error
from digit_radius_oracle import residual_radius, supports_bounded_digit


class DigitRadiusTests(unittest.TestCase):
    def test_actual_negacyclic_phases_exhaustive(self):
        checked = 0
        rounding_is_required = False
        bound_is_attained = False
        for q, p in ((5, 3), (7, 3)):
            n = 2
            vectors = list(itertools.product(range(-(q // 2), q // 2 + 1), repeat=n))
            secrets = list(itertools.product((-1, 0, 1), repeat=n))
            for c0, c1, secret in itertools.product(vectors, vectors, secrets):
                prepared = [[(p * p * v + q // 2) // q for v in c] for c in (c0, c1)]
                expanded = [a + b for a, b in zip(prepared[0], negacyclic_mul(prepared[1], secret))]
                for message in range(p):
                    v = max(map(abs, phase_error((c0, c1), message, secret, q, p)))
                    if 2 * v >= q:
                        continue
                    radius = residual_radius(q, p, n, v)
                    residual = [centered(x - (p * centered(message, p) if j == 0 else 0), p * p)
                                for j, x in enumerate(expanded)]
                    actual = max(map(abs, residual))
                    self.assertLessEqual(actual, radius)
                    rounding_is_required |= actual > (p * v) // q
                    bound_is_attained |= actual == radius and radius > 0
                    # When admitted to a narrow interval, exact rounded
                    # extraction must preserve every plaintext coefficient.
                    if supports_bounded_digit(q, p, n, v, p // 2):
                        decoded = [((x + p // 2) // p) % p for x in expanded]
                        self.assertEqual(decoded, [message, 0])
                    checked += 1
        self.assertGreater(checked, 1000)
        self.assertTrue(rounding_is_required)
        self.assertTrue(bound_is_attained)

    def test_native_history_and_first_support_boundary(self):
        q, p, n = 348959453350711275087786864768188417, 65537, 8192
        for v, expected in ((5011390467, 4096),
                            (22046046060462580170753, 4096),
                            (96984689102983990917283450424483841, 22310)):
            self.assertEqual(residual_radius(q, p, n, v), expected)
            self.assertFalse(supports_bounded_digit(q, p, n, v, 17))
            self.assertFalse(supports_bounded_digit(q, p, n, v, 32))
            self.assertTrue(supports_bounded_digit(q, p, n, v, expected))
            self.assertFalse(supports_bounded_digit(q, p, n, v, expected - 1))
        # First V at which the floor of the exact rational radius reaches B+1.
        b = 4096
        threshold = (2 * q * (b + 1) - (n + 1) * (q - 1) + 2 * p - 1) // (2 * p)
        self.assertTrue(supports_bounded_digit(q, p, n, threshold - 1, b))
        self.assertFalse(supports_bounded_digit(q, p, n, threshold, b))

    def test_invalid_and_ambiguous_inputs_refuse(self):
        for q, p, n, v in ((4, 3, 2, 0), (17, 2, 2, 0), (17, 5, 0, 0),
                            (17, 5, 2, -1), (17, 5, 2, 9)):
            with self.assertRaises(ValueError):
                residual_radius(q, p, n, v)
        self.assertFalse(supports_bounded_digit(17, 5, 2, 0, -1))
        self.assertFalse(supports_bounded_digit(17, 5, 2, 0, 3))


if __name__ == "__main__":
    unittest.main()
