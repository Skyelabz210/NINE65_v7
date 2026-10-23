import itertools
import unittest
from math import prod

from compact_phase_clock_budget import P
from outer_ring_return_budget import OUTER
from scale_locked_carry_tray import (
    carry_radius,
    plan,
    same_phase_decode,
    strict_residual_bound,
)


class ScaleLockedCarryTrayTests(unittest.TestCase):
    def test_native_121_and_5632_trays_fit_the_outer_lane_domain(self):
        for scale in (121, 5632):
            with self.subTest(scale=scale):
                result = plan(scale)
                self.assertTrue(result["conditions"]["input_plaintext_fits_every_outer_lane"])
                self.assertEqual(
                    result["conditions"]["safe_root_factors_present"],
                    scale == 5632,
                )
                self.assertEqual(result["carry_radius"], 48)
                self.assertTrue(result["same_phase_output_decodes"])
                self.assertFalse(result["all_conditions_pass"])
                self.assertFalse(result["conditions"]["following_dense_product_decodes"])
                self.assertFalse(result["canonical_residual_producer"])

    def test_exhaustive_carry_and_residual_rectangle_redecodes_exactly(self):
        for scale in (121, 5632):
            radius = carry_radius()
            residual = strict_residual_bound(scale)
            for carry, error in itertools.product(
                range(-radius, radius + 1),
                range(-residual, residual + 1),
            ):
                z = scale * carry + error
                # nearest integer z/A; the certificate requires strict half-room
                self.assertEqual((2 * error < scale), True)
                self.assertEqual((2 * z + scale) // (2 * scale), carry)
                self.assertEqual(same_phase_decode(z, winding=0, scale=scale), carry % P)

    def test_hidden_q_winding_vanishes_without_component_rescaling(self):
        for scale, carry, error in ((121, 48, 50), (5632, -48, 136)):
            z = scale * carry + error
            expected = carry % P
            self.assertEqual(same_phase_decode(z, winding=0, scale=scale), expected)
            for winding in (-4096, -1, 1, 4096):
                self.assertEqual(same_phase_decode(z, winding, scale), expected)

    def test_floored_outer_delta_preserves_every_native_carry_residual_pair(self):
        q_outer = prod(OUTER)
        for scale in (121, 5632):
            result = plan(scale)
            input_plain = P * scale
            delta = q_outer // input_plain
            residual = result["strict_residual_bound"]
            for carry, error in itertools.product(
                range(-result["carry_radius"], result["carry_radius"] + 1),
                range(-residual, residual + 1),
            ):
                z = scale * carry + error
                decoded = (P * delta * z + q_outer // 2) // q_outer
                self.assertEqual(decoded % P, carry % P)
                scaled_error = abs(P * delta * z - q_outer * carry)
                self.assertLessEqual(scaled_error, result["same_phase_output_v_bound"])

    def test_5632_is_valid_but_encoding_residual_blocks_a_repeat_cycle(self):
        result = plan(5632)
        self.assertEqual(result["parameters"]["input_plaintext_T"], P * 5632)
        self.assertLess(P * 5632, min(OUTER))
        self.assertEqual(result["strict_residual_bound"], 136)
        self.assertEqual(result["same_phase_output_v_bits"], 236)
        cycle = result["return_cycle"]
        self.assertEqual(cycle["returned_v_bits"], 113)
        self.assertEqual(cycle["following_dense_square_v_bits"], 155)
        self.assertFalse(cycle["following_dense_square_decodes"])
        self.assertLess(prod(OUTER).bit_length(), 256)


if __name__ == "__main__":
    unittest.main()
