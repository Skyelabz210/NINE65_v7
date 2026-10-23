import unittest

from full_polynomial_bootstrap_budget import P, SOURCE_Q, plan, report, square_v


class FullPolynomialBootstrapBudgetTests(unittest.TestCase):
    def test_full_assembly_cannot_reuse_one_coefficient_error(self):
        p = plan()
        self.assertEqual(p["assembled_v_bound"], 8192 * p["coefficient_v_bound"])
        self.assertEqual(p["first_refusal"], "following_polynomial_square_decode")
        self.assertFalse(p["conditional_arithmetic_closure"])

    def test_public_probe_bound_matches_rust_ledger(self):
        p = plan(n=32, source_norm=2, block=8, coordinate=9,
                 phase_denominator=128, multiplication_norm=32)
        self.assertEqual((p["assembled_v_bits"], p["returned_v_bits"],
                          p["following_polynomial_square_v_bits"]), (68, 37, 63))
        self.assertEqual(2 * p["total_switches_per_refresh"], 44674)
        self.assertTrue(p["conditional_arithmetic_closure"])
        self.assertFalse(p["public_refresh_admitted"])

    def test_sparse_norm_does_not_admit_dense_source(self):
        p = plan(source_norm=8192)
        self.assertFalse(p["stages"]["clock_window"])
        self.assertFalse(p["stages"]["integer_carry_range"])
        self.assertEqual(p["first_refusal"], "clock_window")

    def test_full_search_retains_resource_and_security_refusal(self):
        r = report()
        self.assertEqual(r["fitting_block_sizes"], [1, 2])
        best = r["smallest_storage_with_conditional_arithmetic_closure"]
        self.assertGreater(best["stored_polynomial_bytes_including_return_key"], 200 * 1024**3)
        self.assertGreater(best["full_polynomial_online_switches"], 500_000_000)
        self.assertFalse(best["security_of_sparse_source_or_key_cycles_certified"])
        self.assertFalse(r["practical_native_execution_admitted"])

    def test_product_refuses_undecodable_input_and_understated_norm(self):
        with self.assertRaises(ValueError):
            square_v(8192, P, SOURCE_Q, (SOURCE_Q + 1) // 2, 32)
        with self.assertRaises(ValueError):
            plan(multiplication_norm=2)


if __name__ == "__main__":
    unittest.main()
