import unittest

from outer_ring_return_budget import OUTER, WORK, plan, report


class OuterRingReturnBudgetTests(unittest.TestCase):
    def test_new_return_closes_polynomial_bound_at_work_q(self):
        p = plan()
        self.assertTrue(p["conditional_arithmetic_closure"])
        self.assertEqual((p["outer_q_bits"], p["work_q_bits"]), (241, 119))
        self.assertEqual(p["returned_v_bits"], 46)
        self.assertEqual(p["following_polynomial_square_v_bits"], 80)
        self.assertEqual(tuple(p["return_key_primes"]), WORK)
        self.assertNotEqual(WORK, OUTER)
        self.assertTrue(all(x["decode_fits"] for x in p["modulus_drops"]))

    def test_bound_requires_more_than_128_bits_before_dropping(self):
        p = plan()
        self.assertGreater(p["assembled_v_bits"], 128)
        self.assertEqual(p["reduced_v_bits"], 30)

    def test_minimum_key_storage_does_not_claim_full_memory_or_latency(self):
        p = report()["minimum_stored_key_candidate"]
        self.assertLess(p["stored_polynomial_bytes"], 1024**3)
        self.assertGreater(p["all_clocks_resident_bytes"], 16 * 1024**3 - 1)
        self.assertGreater(p["total_switches"], 250_000_000)
        self.assertFalse(p["practical_resources_admitted"])
        self.assertFalse(p["sparse_source_and_joint_key_security_certified"])
        self.assertFalse(p["public_refresh_admitted"])

    def test_dense_source_is_not_silently_replaced_by_sparse_bound(self):
        p = plan(source_norm=8192)
        self.assertFalse(p["stages"]["clock_window"])
        self.assertFalse(p["stages"]["integer_carry_range"])
        self.assertEqual(p["first_refusal"], "clock_window")

    def test_ring_ratio_and_understated_source_norm_refuse(self):
        with self.assertRaises(ValueError):
            plan(outer_n=8192)
        with self.assertRaises(ValueError):
            plan(multiplication_norm=2)

    def test_batching_preserves_noise_and_charges_repeated_expansion(self):
        small = plan(output_batch=64)
        whole = plan(output_batch=8192)
        self.assertEqual(small["returned_v_bound"], whole["returned_v_bound"])
        self.assertEqual(small["assembled_v_bound"], whole["assembled_v_bound"])
        self.assertEqual(small["output_batches"], 128)
        self.assertEqual(small["total_switches"],
                         128 * small["stream_expansion_switches"] + small["online_switches"])
        self.assertGreater(small["total_switches"], whole["total_switches"])
        self.assertEqual(2 * small["stream_stack_upper_bytes"],
                         small["both_polarities_stack_comparison_bytes"])
        self.assertLess(small["resident_clocks_bytes"], whole["resident_clocks_bytes"])

    def test_tiny_probe_ledger_matches_executed_switches(self):
        p = plan(source_n=16, outer_n=32, source_norm=2, block=8,
                 coordinate=9, phase_denominator=128, multiplication_norm=16,
                 output_batch=4)
        self.assertEqual((p["assembled_v_bits"], p["returned_v_bits"],
                          p["following_polynomial_square_v_bits"]), (79, 37, 61))
        self.assertEqual(2 * p["total_switches"], 22820)


if __name__ == "__main__":
    unittest.main()
