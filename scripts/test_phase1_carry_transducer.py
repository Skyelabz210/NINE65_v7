import unittest

from phase1_carry_transducer import (
    affine_phase2_hits,
    candidate,
    displaced_polynomial,
    displaced_scalar,
    evaluator_signed_carry,
)


class Phase1CarryTransducerTests(unittest.TestCase):
    def test_pinned_scalar_and_negacyclic_matches_bootstrap_oracle(self):
        scalar = displaced_scalar(17, 5, 1, 1, 1)
        self.assertEqual(scalar["component"], 0)
        self.assertEqual(scalar["decoded"], 1)
        self.assertEqual(scalar["k"], 1)
        self.assertTrue(scalar["already_centered"])
        poly = displaced_polynomial(17, 5, [1, 0], [1, 1], [1, -1])
        self.assertEqual(poly["decoded"], [1, 0])
        self.assertEqual(poly["component"], [0, 0])
        self.assertEqual(poly["k"], [1, 0])
        self.assertTrue(poly["within_radius"])

    def test_affine_phase2_cannot_hit_every_ternary_secret(self):
        self.assertEqual(affine_phase2_hits(17, 5, 1, 1), 0)

    def test_evaluator_rejects_noncanonical_residues(self):
        with self.assertRaises(ValueError):
            evaluator_signed_carry(49, 0, 0, 0)
        with self.assertRaises(ValueError):
            evaluator_signed_carry(-1, 0, 0, 0)

    def test_candidate_keeps_public_refresh_closed(self):
        result = candidate()
        self.assertEqual(result["scalar_counterexample"]["k"], 1)
        self.assertEqual(result["negacyclic_k"], [1, 0])
        self.assertEqual(result["affine_phase2_hits"], 0)
        self.assertEqual(result["evaluator_boundary_points"], 7)
        self.assertGreater(result["chart_envelope_admitted_by_existing_oracle"], 0)
        self.assertFalse(result["dense_ciphertext_producer"])
        self.assertFalse(result["production_gate_relaxed"])
        self.assertFalse(result["public_refresh_admitted"])
        for row in result["scale_lock"]:
            self.assertFalse(row["square_decodes"])
            self.assertGreater(row["square_bits"], row["return_bits"])


if __name__ == "__main__":
    unittest.main()
