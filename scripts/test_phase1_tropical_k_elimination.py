import unittest

from phase1_tropical_k_elimination import run


class Phase1TropicalKEliminationTests(unittest.TestCase):
    def test_component_rounding_difference_is_tropical_sheet_carry(self):
        result = run()
        self.assertEqual(result["polynomial_cases"], 40)
        self.assertEqual(result["coefficient_cases"], 40 * 32)
        self.assertTrue(result["component_switch_difference_equals_tropical_carry"])
        self.assertGreater(result["nonzero_carries"], 0)

    def test_safe_basis_and_phase_locked_trays_recover_full_signed_corridor(self):
        result = run()
        self.assertEqual(result["full_signed_corridor_residue_checks"], 33 * 5 * 3)
        self.assertTrue(result["all_three_trays_recover_signed_carry"])

    def test_oracle_does_not_claim_an_encrypted_producer_or_refresh(self):
        result = run()
        self.assertFalse(result["same_source_encrypted_pair_produced"])
        self.assertFalse(result["public_refresh_admitted"])


if __name__ == "__main__":
    unittest.main()
