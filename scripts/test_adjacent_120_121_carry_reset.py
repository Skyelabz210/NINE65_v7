import itertools
import random
import unittest
from math import prod

from adjacent_120_121_carry_reset import (
    CARRY_PLAIN,
    OUTER_N,
    OUTER,
    OUTPUT_PLAIN,
    RESIDUE_PLAIN,
    centered,
    plan,
    recover_carry,
    rns_scale_divide,
    scale_winding_shift,
)


class Adjacent120121CarryResetTests(unittest.TestCase):
    def test_native_component_bounds_and_conditional_repeat_ledger(self):
        p = plan()
        self.assertTrue(p["conditional_bounds_fit_if_windings_zero"])
        self.assertFalse(p["all_conditions_pass"])
        self.assertEqual(p["residual_abs_bound"], 55)
        self.assertEqual(p["carry_radius"], 48)
        self.assertEqual(p["view120_error_bits"], 43)
        self.assertEqual(p["view121_error_bits"], 43)
        self.assertEqual(p["conditional_carry_error_under_121_bits"], 44)
        self.assertEqual(p["conditional_carry_converted_to_65537_error_bits"], 44)
        cycle = p["conditional_return_cycle_if_windings_zero"]
        self.assertEqual(cycle["returned_v_bits"], 46)
        self.assertEqual(cycle["following_dense_square_v_bits"], 88)
        self.assertEqual(cycle["next_prepared_source_v_bits"], 44)
        self.assertTrue(cycle["next_prepared_source_fits_q_over_64"])
        self.assertFalse(p["conditions"]["scale_conversion_secret_winding_is_corrected"])
        self.assertFalse(p["rns_scale_round_primitive_implemented"])
        self.assertFalse(p["native_encrypted_execution"])
        self.assertFalse(p["public_refresh_admitted"])

    def test_first_hidden_converter_winding_changes_carry_by_one(self):
        p = plan()
        self.assertEqual(scale_winding_shift(1, 120, 121), 120)
        self.assertEqual((48 + scale_winding_shift(1, 120, 121)) % 121, 47)
        self.assertEqual(p["unknown_winding_error_bound_under_121"],
                         prod(OUTER) * (121 // 2))
        self.assertTrue(p["first_nonzero_winding_case"]["expected_carry_error_at_least_q"])

    def test_every_carry_and_residual_in_the_certified_rectangle(self):
        p = plan()
        checked = 0
        for carry, residual in itertools.product(
                range(-p["carry_radius"], p["carry_radius"] + 1),
                range(-p["residual_abs_bound"], p["residual_abs_bound"] + 1)):
            recovered, z, remainder, anchor = recover_carry(carry, residual, p)
            self.assertEqual(z, 120 * carry + residual)
            self.assertEqual(remainder, residual)
            self.assertEqual(anchor, centered(residual - carry, CARRY_PLAIN))
            self.assertEqual(recovered, carry)
            checked += 1
        self.assertEqual(checked, 97 * 111)

    def test_rns_k_elimination_scale_division_matches_signed_integer_oracle(self):
        moduli = (17, 19, 23)
        q = prod(moduli)
        for input_plain, output_plain in ((RESIDUE_PLAIN, CARRY_PLAIN),
                                          (CARRY_PLAIN, OUTPUT_PLAIN)):
            self.assertTrue(all(output_plain % m for m in moduli))
            for x in range(-(q // 2), q // 2 + 1):
                residues = [x % m for m in moduli]
                got = rns_scale_divide(residues, moduli, input_plain, output_plain)
                exact = (input_plain * x + output_plain // 2) // output_plain
                self.assertEqual(got, [exact % m for m in moduli])

    def test_full_outer_basis_scale_division_matches_centered_crt_boundaries(self):
        q = prod(OUTER)
        rng = random.Random(0x120_121_65537)
        values = [-(q // 2), -(q // 2) + 1, -1, 0, 1, q // 2]
        values.extend(rng.randrange(-(q // 2), q // 2 + 1) for _ in range(64))
        for input_plain, output_plain in ((RESIDUE_PLAIN, CARRY_PLAIN),
                                          (CARRY_PLAIN, OUTPUT_PLAIN)):
            for x in values:
                residues = [x % modulus for modulus in OUTER]
                got = rns_scale_divide(residues, OUTER, input_plain, output_plain)
                exact = (input_plain * x + output_plain // 2) // output_plain
                self.assertEqual(got, [exact % modulus for modulus in OUTER])
                self.assertLessEqual(abs(output_plain * exact - input_plain * x),
                                     output_plain // 2)
        self.assertEqual(OUTER_N, 16384)

    def test_scaled_noise_formula_and_out_of_range_refusal(self):
        p = plan()
        self.assertEqual(RESIDUE_PLAIN + 1, CARRY_PLAIN)
        self.assertEqual(p["parameters"]["carry_plaintext"], 121)
        for carry, residual in ((49, 0), (0, 56)):
            with self.assertRaises(ValueError):
                recover_carry(carry, residual, p)


if __name__ == "__main__":
    unittest.main()
