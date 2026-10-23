import unittest

from source_encapsulation_budget import P, SOURCE_Q, WORK_Q, maximum_work_input, plan, source_transform


class SourceEncapsulationBudgetTests(unittest.TestCase):
    def test_actual_low_modulus_source_covers_original_dense_work_key(self):
        p = plan()
        self.assertTrue(p["conditional_arithmetic_closure"])
        self.assertEqual(p["parameters"]["working_norm_bound"], 8192)
        self.assertEqual(p["parameters"]["source_norm"], 96)
        self.assertEqual(p["parameters"]["outer_norm_bound"], 16384)
        self.assertEqual(p["source_window2"], 13699)
        self.assertLess(SOURCE_Q, WORK_Q)
        self.assertFalse(p["source_transform"]["source_key_ever_encrypts_at_work_Q"])

    def test_dense_following_product_is_reencapsulated_before_reentry(self):
        p = plan()
        self.assertEqual(p["returned_work_v_bits"], 46)
        self.assertEqual(p["following_dense_work_product_v_bits"], 88)
        self.assertLess(p["following_source_transform"]["source_v_bound"], p["source_phase_cap"])
        self.assertGreater(p["following_dense_work_product_v"], p["source_phase_cap"])
        self.assertFalse(p["production_admitted"])

    def test_maximum_input_boundary_is_exact_under_the_public_envelope(self):
        cap = SOURCE_Q // 16
        v = maximum_work_input(8192, cap)
        self.assertLessEqual(source_transform(v)["source_v_bound"], cap)
        self.assertGreater(source_transform(v+1)["source_v_bound"], cap)
        self.assertFalse(plan(incoming_work_v=v+1)["stages"]["prepared_source_phase_fits"])

    def test_source_switch_error_is_not_credited_with_sparse_norm(self):
        p = plan()
        self.assertGreater(p["source_transform"]["switch_v"], P*8192*3)
        self.assertEqual(p["total_raw_switches"], 444703747)
        self.assertEqual(p["source_transform_key_bytes"], 1572864)

    def test_relabeling_dense_source_without_key_switch_remains_invalid(self):
        p = plan(source_norm=8192)
        self.assertFalse(p["stages"]["source_clock_window"])
        self.assertFalse(p["stages"]["integer_carry_range"])

    def test_decoder_limit_is_rejected_before_propagation(self):
        with self.assertRaises(ValueError):
            source_transform((WORK_Q+1)//2)


if __name__ == "__main__":
    unittest.main()
