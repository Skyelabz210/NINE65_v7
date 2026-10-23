import unittest

from compact_phase_clock_budget import PRIMES, plan, report, shape


class CompactClockBudgetTests(unittest.TestCase):
    def test_unsigned_digit_sum_bound_is_exhaustive_on_small_moduli(self):
        for modulus in [17, 31, 97, 257]:
            for b in range(1, 6):
                digits, bound = shape([modulus], b)
                mask = (1 << b) - 1
                for value in range(modulus):
                    observed = sum((value >> (b * j)) & mask for j in range(digits))
                    self.assertLessEqual(observed, bound)

    def test_naive_compaction_decodes_but_cannot_fund_next_square(self):
        p = plan(block=8192, raw_bits=10, galois_bits=10)
        self.assertGreater(p["constant_column_error"], 3)
        self.assertGreater(p["secret_column_error"], p["constant_column_error"])
        self.assertTrue(p["output_decode_fits"])
        self.assertFalse(p["following_square_fits"])

    def test_native_candidate_charges_all_public_positions(self):
        p = plan()
        self.assertTrue(p["conditional_arithmetic_fits"])
        self.assertEqual(p["window2"], 5185)
        self.assertEqual(p["carry_bound"], 16)
        self.assertEqual(p["precharge_bytes"], 1205862400)
        self.assertGreater(p["derive_raw_switches_per_coefficient"], 16000000)
        self.assertEqual(p["stream_expansion_raw_switches_full_coefficient"],3931520)
        self.assertFalse(p["optimistic_reentry_phase_fits"])
        self.assertFalse(p["public_refresh_admitted"])

    def test_compaction_does_not_fix_dense_window(self):
        p = plan(source_norm=8192)
        self.assertTrue(p["following_square_fits"])
        self.assertFalse(p["window_fits"])
        self.assertFalse(p["integer_carry_fits"])
        self.assertFalse(p["conditional_arithmetic_fits"])

    def test_small_encrypted_probe_tuple_is_budgeted(self):
        p = plan(n=64, source_norm=2, terms=64, block=16,
                 coordinate=9, phase_denominator=16)
        self.assertTrue(p["conditional_arithmetic_fits"])
        self.assertEqual(p["window2"], 43)
        self.assertEqual(p["derive_raw_switches_per_coefficient"], 61440)
        self.assertEqual(p["stream_expansion_raw_switches_full_coefficient"],30080)

    def test_search_has_no_implicit_security_or_latency_claim(self):
        r = report()
        p = r["minimum_stored_bytes_in_declared_search"]
        self.assertEqual(p["precharge_bytes"], 1205862400)
        self.assertEqual(shape(PRIMES, 10)[0], 20)
        self.assertFalse(r["practical_latency_admitted"])
        self.assertFalse(r["public_refresh_admitted"])

    def test_dependent_reentry_check_requires_a_different_tuple(self):
        r = report()
        first = r["minimum_stored_bytes_in_declared_search"]
        second = r["minimum_stored_bytes_passing_optimistic_reentry"]
        self.assertFalse(first["optimistic_reentry_phase_fits"])
        self.assertTrue(second["optimistic_reentry_phase_fits"])
        self.assertEqual(second["parameters"]["block"], 512)
        self.assertEqual(second["precharge_bytes"], 2464153600)
        self.assertFalse(second["public_refresh_admitted"])

    def test_invalid_metadata_refused(self):
        for changes in [{"block": 3}, {"raw_bits": 0}, {"terms": 8193},
                        {"coordinate": 22}, {"source_norm": -1}]:
            with self.assertRaises(ValueError):
                plan(**changes)


if __name__ == "__main__":
    unittest.main()
