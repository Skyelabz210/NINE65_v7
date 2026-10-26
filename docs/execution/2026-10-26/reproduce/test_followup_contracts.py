#!/usr/bin/env python3
"""Finite witnesses for the second supplied-material review.

These tests check arithmetic statements only.  They do not certify an FHE
construction, authenticate an attachment, or turn a finite census into a
universal proof.
"""

import math
import unittest


def crt(residues, moduli):
    modulus = math.prod(moduli)
    value = 0
    for residue, lane in zip(residues, moduli):
        cofactor = modulus // lane
        value += residue * cofactor * pow(cofactor, -1, lane)
    return value % modulus


class FollowupContractTests(unittest.TestCase):
    def test_div3_census_reproduces_supplied_counts(self):
        tested = admitted = rejected = mismatches = 0
        for modulus in range(3, 65):
            for a in range(modulus):
                for b in range(modulus):
                    tested += 1
                    if math.gcd(a, modulus) != 1 or math.gcd(b, modulus) != 1:
                        rejected += 1
                        continue
                    admitted += 1
                    inv_a = pow(a, -1, modulus)
                    inv_b = pow(b, -1, modulus)
                    div_twice = inv_a * inv_b % modulus
                    recovered = pow(div_twice, -1, modulus)
                    mismatches += recovered != a * b % modulus
        self.assertEqual((tested, admitted, rejected, mismatches),
                         (89_435, 37_700, 51_735, 0))

    def test_independent_rounding_drops_the_secret_dependent_carry(self):
        q, t, c0, c1, secret = 17, 5, 1, 1, 1
        componentwise = round(t * c0 / q) + secret * round(t * c1 / q)
        phase_rounding = round(t * (c0 + c1 * secret) / q)
        self.assertEqual((componentwise, phase_rounding), (0, 1))

    def test_same_basis_residues_do_not_determine_absolute_quotient(self):
        basis = (5, 7)
        a0, a1, divisor = 6, 111, 3
        self.assertEqual(tuple(a0 % p for p in basis), tuple(a1 % p for p in basis))
        self.assertEqual((a0 // divisor, a1 // divisor), (2, 37))

    def test_modular_division_is_not_floor_division(self):
        numerator, divisor, modulus = 7, 2, 35
        modular = numerator * pow(divisor, -1, modulus) % modulus
        self.assertEqual(modular, 21)
        self.assertEqual(numerator // divisor, 3)

    def test_adding_a_coprime_auxiliary_does_not_fix_shared_factor(self):
        divisor, main_product, auxiliary = 2, 6, 5
        self.assertEqual(math.gcd(divisor, main_product * auxiliary), 2)

    def test_one_auxiliary_cannot_recover_a_shared_quotient_lane(self):
        moduli = (2, 3, 5)
        a0, a1, divisor = 2, 32, 2
        self.assertEqual(tuple(a0 % p for p in moduli), tuple(a1 % p for p in moduli))
        self.assertNotEqual((a0 // divisor) % 2, (a1 // divisor) % 2)

    def test_single_lane_sign_proxy_aliases_opposite_half_sheets(self):
        self.assertEqual(1 % 7, 22 % 7)
        self.assertGreater(1, 0)
        self.assertLess(22 - 35, 0)

    def test_lexicographic_residue_tuples_are_not_integer_order(self):
        self.assertLess(4, 5)
        self.assertGreater((4 % 5, 4 % 7), (5 % 5, 5 % 7))

    def test_finite_anchor_capacity_has_an_alias_boundary(self):
        main, anchor, value = 35, 11, 2
        alias = value + main * anchor
        self.assertEqual((value % main, value % anchor),
                         (alias % main, alias % anchor))

    def test_fifth_operator_field_division_is_not_integer_quotient(self):
        moduli = (7, 11, 13)
        residues = tuple(pow(3, -1, p) for p in moduli)
        self.assertEqual(residues, (5, 4, 9))
        self.assertEqual(crt(residues, moduli), 334)
        self.assertEqual(1 // 3, 0)

    def test_shadow_fingerprint_and_product(self):
        moduli = (2, 3, 5, 7, 13, 17, 19)
        self.assertEqual(tuple(pow(11, 6, p) for p in moduli),
                         (1, 1, 1, 1, 12, 8, 1))
        self.assertEqual(11**6 * 13 * 17 * 19, 7_438_784_639)

    def test_euler_energy_update_needs_the_quadratic_term(self):
        omega, forcing, dt = (1, 0), (0, 1), 1
        updated = tuple(x + dt * g for x, g in zip(omega, forcing))
        actual = sum(x * x for x in updated) - sum(x * x for x in omega)
        claimed_linear_term = 2 * dt * sum(x * g for x, g in zip(omega, forcing))
        self.assertEqual((actual, claimed_linear_term), (1, 0))

    def test_safe_basis_cross_scale_example_names_neither_value(self):
        reported = 25
        self.assertEqual(584 % 325, 259)
        self.assertEqual(58_400 % 325, 225)
        self.assertNotIn(reported, (584 % 325, 58_400 % 325))

    def test_safe_basis_saturation_ratio_is_not_1_point_4(self):
        self.assertAlmostEqual(41_538 / 5_760, 7.211458333333334)

    def test_p_adic_nonexpansion_does_not_imply_bounded_integer_orbit(self):
        def f(x):
            return x + 3 * x * x

        orbit = [1]
        for _ in range(4):
            orbit.append(f(orbit[-1]))
        self.assertEqual(orbit, [1, 4, 52, 8_164, 199_960_852])
        # f(x)-f(y)=(x-y)(1+3(x+y)); the second factor is integral, so
        # every p-adic valuation of x-y can only stay level or increase.
        x, y = 52, 4
        self.assertEqual((f(x) - f(y)) % (x - y), 0)

    def test_winding_need_not_be_nondecreasing(self):
        prime, value = 11, 11
        before = (value - value % prime) // prime
        after_value = 0
        after = (after_value - after_value % prime) // prime
        self.assertEqual((before, after), (1, 0))

    def test_closed_shell_formula_needs_final_reduction(self):
        winding, anchor = 0, 37
        self.assertEqual((-winding) % anchor, 0)
        self.assertEqual(anchor - (winding % anchor), 37)
        self.assertEqual((anchor - (winding % anchor)) % anchor, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
