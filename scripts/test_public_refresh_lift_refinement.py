from fractions import Fraction
from itertools import product
import unittest

from public_refresh_lift_refinement import (
    ConservativeBoxBallFlow, interpolation_values, polynomial_value,
    project_lift, project_native_signed,
)


class PublicRefreshLiftRefinementTests(unittest.TestCase):
    def test_native_signed_interval_and_all_residue_transitions(self):
        targets = (1, 2, 11, 36, 37, 73, 65537)
        for k in range(-48, 49):
            y = k + 48
            for target in targets:
                self.assertEqual(project_native_signed(y % 36, y % 37, target), k % target)
            for next_k in range(-48, 49):
                delta = next_k - k
                self.assertEqual(project_native_signed((y + delta) % 36, (y + delta) % 37,
                                                        65537), next_k % 65537)

    def test_all_native_digit_cases_match_shared_factor_lift(self):
        p = 65537
        count = 0
        for rho in range(-49, 50):
            derivative = 1
            for root in range(-49, 50):
                if root != rho:
                    derivative = derivative * (rho - root) % p
            inverse = pow(derivative, -1, p)
            for k in range(-48, 49):
                x = (rho + p * k) % (p * p)
                shared_factor = ((x - rho) % (p * p)) // p
                g = 1
                for root in range(-49, 50):
                    g = g * (x - root) % (p * p)
                self.assertEqual(g % p, 0)
                self.assertEqual((g // p) * inverse % p, shared_factor)
                self.assertEqual(shared_factor, k % p)
                count += 1
        self.assertEqual(count, 9603)

    def test_direct_and_factorized_anchor_lookups_require_degree_96(self):
        for target in (4, 9, 11, 36, 37):
            values = tuple(y % target for y in range(97))
            polynomial = interpolation_values(values, 65537)
            self.assertEqual(len(polynomial) - 1, 96)
            for y, expected in enumerate(values):
                self.assertEqual(polynomial_value(polynomial, y, 65537), expected)

    def test_native_adjacency_difference_has_five_values_and_degree_four_correction(self):
        p = 65537
        left = 37 * pow(-36 * -37 * -38, -1, p) % p
        right = 37 * pow(-35 * -36 * -37, -1, p) % p
        alpha = (right - left) % p
        beta = (left + 36 * alpha) % p
        self.assertEqual((alpha, beta), (12783, 19490))
        differences = set()
        for y in range(97):
            d = y % 36 - y % 37
            differences.add(d)
            corrected = (d + d * (d - 1) * (d - 2) * (alpha * d + beta)) % p
            self.assertEqual(corrected, y // 36)
        self.assertEqual(differences, {-36, -35, 0, 1, 2})
        # This is a domain-specific consumer, not a generic modulo-37 map.
        d = 3
        self.assertNotEqual((d + d * (d - 1) * (d - 2) * (alpha * d + beta)) % p, d % 37)

    def test_factorized_crt_still_needs_canonical_reduction_in_native_field(self):
        unreduced_mismatches = []
        for y in range(97):
            r4, r9 = y % 4, y % 9
            mixed = 9 * r4 + 4 * ((r9 * 7) % 9)
            self.assertEqual(mixed % 36, y % 36)
            if mixed % 65537 != y % 36:
                unreduced_mismatches.append(y)
        self.assertIn(2, unreduced_mismatches)  # 18+20=38; canonical r36=2.

    def test_zero_defect_and_worker_reduction_do_not_create_plaintext_views(self):
        # Authentic individual views from DIFFERENT Y values can satisfy a
        # derived zero defect and the numerical interval simultaneously.
        g, a = 4 % 36, 3 % 37
        sheet = (g - a) % 37
        self.assertEqual((a - g - 36 * sheet) % 37, 0)
        self.assertEqual(project_lift(g, a, 36, 37, 96, 65537), 40)
        # Equivalent Q-ciphertexts need not have equivalent projections at 37.
        q, t, secret = 101, 7, 1
        ciphertexts = ((42, 0), (43, 100))
        phases = [(c0 + c1 * secret) % q for c0, c1 in ciphertexts]
        self.assertEqual(phases, [42, 42])
        self.assertEqual([(v * t + q // 2) // q % t for v in phases], [3, 3])
        self.assertEqual([(c0 % 37 + c1 % 37 * secret) % 37
                          for c0, c1 in ciphertexts], [5, 32])

    def test_general_conservative_flows_admit_exact_continuum_lift(self):
        cases = 0
        for before in product((0, 1), repeat=6):
            for after in product((0, 1), repeat=6):
                if sum(before) != sum(after):
                    continue
                # Smaller coprime shell forces nonzero derived sheets.
                flow = ConservativeBoxBallFlow(before, after, 2, 7)
                for i in range(7):
                    c = sum(before[:i]) - sum(after[:i])
                    for target in (2, 11, 36, 37, 65537):
                        self.assertEqual(flow.carrier_mod(i, target), c % target)
                        expected = (i - 2 * sum(after[:i])) % target
                        self.assertEqual(flow.lifted_height_mod(i, target), expected)
                for i in range(6):
                    c0 = sum(before[:i]) - sum(after[:i])
                    c1 = sum(before[:i + 1]) - sum(after[:i + 1])
                    for theta in (Fraction(1, 3), Fraction(1, 2), Fraction(2, 3)):
                        flux = (1 - theta) * c0 + theta * c1
                        self.assertTrue(-sum(before) <= flux <= sum(before))
                        self.assertEqual(flow.height_at(after, i + theta),
                                         flow.height_at(before, i + theta) + 2 * flux)
                cases += 1
        self.assertEqual(cases, 924)

    def test_mass_bound_controls_sheet_crossings(self):
        flow = ConservativeBoxBallFlow((1,) * 96 + (0,) * 96,
                                       (0,) * 96 + (1,) * 96)
        for i in (0, 35, 36, 37, 72, 95, 96, 97, 192):
            expected = min(i, 192 - i)
            self.assertEqual(flow.carrier_mod(i, 65537), expected)

    def test_rejects_invalid_views_and_flow_contracts(self):
        for args in ((0, 0, 36, 37, 1332, 11), (0, 0, 6, 9, 1, 11),
                     (36, 0, 36, 37, 96, 11), (0, 37, 36, 37, 96, 11),
                     (0, 0, 36, 37, 96, 0), (35, 36, 36, 37, 96, 11)):
            with self.assertRaises(ValueError):
                project_lift(*args)
        for before, after in (((1,), (0,)), ((0, 1), (1,)), ((2,), (2,))):
            with self.assertRaises(ValueError):
                ConservativeBoxBallFlow(before, after)
        leftward = ConservativeBoxBallFlow((0, 1), (1, 0))
        self.assertEqual(leftward.carrier_mod(1, 65537), 65536)
        # A zero phase defect alone cannot detect a whole paired-capacity alias.
        self.assertEqual(project_lift(1332 % 36, 1332 % 37, 36, 37, 96, 65537), 0)


if __name__ == "__main__":
    unittest.main()
