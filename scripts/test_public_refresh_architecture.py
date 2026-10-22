import unittest
from fractions import Fraction

from public_refresh_architecture import (
    N, P, multiply_terms, native_projection_schedule, polynomial_requirement,
    report, square_schedule,
)


class PublicRefreshArchitectureTests(unittest.TestCase):
    def test_minimal_degree_requires_seven_or_eight_levels(self):
        for radius, degree, depth in ((0, 0, 0), (16, 65, 7), (17, 69, 7), (32, 129, 8)):
            result = polynomial_requirement(P, radius)
            self.assertEqual(result["minimum_polynomial_degree"], degree)
            self.assertEqual(result["binary_multiplication_depth_lower_bound"], depth)

    def test_quadratic_bound_dominates_exact_rational_product(self):
        for n in (2, 4, 8):
            for q, t in ((101, 3), (997, 25)):
                for a in range(q // t // 2):
                    for b in range(q // t // 2):
                        terms = multiply_terms(n, t, q, a, b, 0)
                        self.assertGreaterEqual(terms["quadratic_bit_bound"], Fraction(n * t * a * b, q))
                        if a == 0 or b == 0:
                            self.assertEqual(terms["quadratic_bit_bound"], 0)

    def test_current_and_low_noise_key_first_refusals(self):
        current = native_projection_schedule(3 * (2 * N + 1))
        candidate = native_projection_schedule(3)
        self.assertEqual(current["schedule"]["first_refusal"], 1)
        self.assertEqual(candidate["schedule"]["first_refusal"], 2)
        self.assertEqual(current["schedule"]["nodes"][0]["error_bits"], 131)
        self.assertEqual(candidate["schedule"]["nodes"][0]["error_bits"], 117)
        self.assertEqual(candidate["schedule"]["nodes"][1]["error_bits"], 175)

    def test_refused_input_cannot_be_reused_as_certificate(self):
        result = square_schedule(2, 3, 101, 101 // 3 // 2, 0, 7)
        self.assertEqual(result["first_refusal"], "input")
        self.assertEqual(result["nodes"], [])
        with self.assertRaises(ValueError):
            multiply_terms(2, 3, 101, 17, 0, 0)
        result = native_projection_schedule(3)["schedule"]
        self.assertEqual(len(result["nodes"]), 2)
        self.assertFalse(result["nodes"][-1]["bound_fits"])

    def test_strict_integer_boundary_not_bit_count(self):
        result = square_schedule(2, 3, 101, 15, 0, 0)
        self.assertIsNone(result["first_refusal"])
        self.assertEqual(result["initial_error_bits"], result["half_delta_bits"] - 1)
        result = square_schedule(2, 3, 109, 17, 0, 0)
        self.assertIsNone(result["first_refusal"])
        self.assertEqual(result["initial_error_bits"], result["half_delta_bits"])
        self.assertEqual(square_schedule(2, 3, 109, 18, 0, 0)["first_refusal"], "input")

    def test_report_keeps_independent_obligations_open(self):
        data = report()
        self.assertFalse(data["public_refresh_admitted"])
        self.assertFalse(data["low_noise_key_implemented"])
        self.assertEqual([v["plaintext_residual_radius"] for v in
                          data["conditional_sparse_radius_fixtures_not_post_transform"]], [17, 17])
        wide = data["joint_single_round_arithmetic"]
        self.assertFalse(wide["single_round_native_wide_kernel_implemented"])
        self.assertEqual(wide["single_round_reverse_rank_fallback_required_bits"], 286)
        larger = data["larger_ring_projection"]
        self.assertTrue(larger["slots_split"])
        self.assertFalse(larger["current_fixed_minus_eight_inverse_works"])
        self.assertTrue(larger["minus_two_is_inverse"])
        self.assertFalse(larger["same_ring_key_api_accepts_8192_to_32768"])


if __name__ == "__main__":
    unittest.main()
