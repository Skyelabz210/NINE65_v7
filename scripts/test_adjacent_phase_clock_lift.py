import unittest

from adjacent_phase_clock_lift import (
    M,
    plan,
    recover_carry_from_error,
    recover_quotient_from_adjacent_residues,
)


class AdjacentPhaseClockLiftTests(unittest.TestCase):
    def test_native_h96_envelope_fits_adjacent_2_and_11_trays(self):
        p = plan()
        self.assertTrue(p["all_conditions_pass"])
        self.assertEqual(p["phase_error_bound"], 4096)
        self.assertEqual(p["component_rounding_error_bound"], 4802)
        self.assertEqual(p["total_residual_bound"], 8898)
        self.assertEqual(p["carry_radius"], 48)
        self.assertEqual(p["quotient_range"], [0, 96])
        self.assertEqual(p["remainder_range"], [0, 17796])
        self.assertLess(p["lifted_value_range"][1], p["adjacent_product"])
        self.assertEqual(p["parameters"]["adjacent_anchor"], 65537)
        self.assertEqual(p["inverse_phase_scale_mod_anchor"], M)
        self.assertTrue(p["conditions"]["same_components_decode_m_remainder_under_adjacent_plaintext"])
        self.assertTrue(p["conditions"]["carry_ciphertext_decodes_at_output_plaintext"])
        self.assertTrue(p["carry_output_error_at_least_1_over_8_q"])
        self.assertFalse(p["encrypted_k_elimination_implemented"])
        self.assertFalse(p["output_noise_reset_proved"])
        self.assertFalse(p["public_refresh_admitted"])

    def test_every_carry_and_every_residual_in_the_certified_rectangle(self):
        p = plan()
        bound = p["total_residual_bound"]
        checked = 0
        for carry in range(-p["carry_radius"], p["carry_radius"] + 1):
            for residual in range(-bound, bound + 1):
                recovered, value, quotient = recover_carry_from_error(carry, residual, p)
                self.assertEqual(recovered, carry)
                self.assertEqual(quotient, carry + p["carry_offset"])
                self.assertEqual(value // M, quotient)
                self.assertEqual(value % M, residual + bound)
                checked += 1
        self.assertEqual(checked, 1_726_309)

    def test_adjacent_k_elimination_matches_direct_division_and_refuses_outside_range(self):
        modulus = M
        adjacent = modulus + 1
        for value in [0, 1, modulus - 1, modulus, modulus * 17 + 123,
                      modulus * adjacent - 1]:
            self.assertEqual(recover_quotient_from_adjacent_residues(value), value // modulus)
        with self.assertRaises(ValueError):
            recover_quotient_from_adjacent_residues(-1)
        with self.assertRaises(ValueError):
            recover_quotient_from_adjacent_residues(modulus * adjacent)

    def test_existing_clock_window_refusal_is_not_the_adjacent_quotient_bound(self):
        p = plan(phase_denominator=8)
        window2 = (4 * p["parameters"]["outer_n"]
                   * (p["parameters"]["source_q"] // 8)
                   + p["parameters"]["source_q"] - 1) // p["parameters"]["source_q"]
        window2 += p["parameters"]["coordinate"] * (p["parameters"]["source_norm"] + 1)
        self.assertGreaterEqual(window2, p["parameters"]["outer_n"])
        self.assertTrue(p["conditions"]["residual_fits_one_quotient_cell"])
        self.assertTrue(p["all_conditions_pass"])


if __name__ == "__main__":
    unittest.main()
