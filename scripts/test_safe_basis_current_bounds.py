"""Regression tests for the public bound diagnostic, not native FHE tests."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import safe_basis_current_bounds as model


class CurrentBoundTests(unittest.TestCase):
    def setUp(self):
        self.budget = model.Budget()

    def test_source_pins_match_reviewed_snapshot(self):
        self.assertEqual(model.checked_sources(Path(__file__).resolve().parents[1]),
                         model.PINNED_SOURCE_SHA256)

    def test_source_drift_refuses_before_reporting_current_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'input.rs').write_text('changed formula')
            with patch.object(model, 'PINNED_SOURCE_SHA256', {'input.rs': '0' * 64}):
                with self.assertRaisesRegex(ValueError, 'review model after source drift'):
                    model.report(root)

    def test_current_margin_is_preserved(self):
        self.assertEqual(self.budget.projected, 65_904_671_850_496)
        self.assertEqual(self.budget.projected, 16 * model.Budget(margin=1).projected)
        self.assertEqual(self.budget.half, 117_984_527_272_727_065_037_126_399_264_836_478_558_604)

    def test_exact_boundary_is_not_bit_length_ordering(self):
        half = self.budget.half
        for bound, admitted in ((half - 1, True), (half, False), (half + 1, False)):
            with self.subTest(bound=bound):
                observation = self.budget.observation(bound, 'boundary')
                self.assertEqual(observation['exact_admitted'], admitted)
                self.assertFalse(observation['bit_length_admitted'])

    def test_terminal_false_rejection_has_real_exact_headroom(self):
        result = model.terminal_carry(self.budget)
        self.assertEqual(result['bound'], 93_745_078_102_582_398_588_188_168_775_782_131_116_281)
        self.assertEqual(result['bound_bits'], result['threshold_bits'])
        self.assertTrue(result['exact_admitted'])
        self.assertFalse(result['bit_length_admitted'])

    def test_pair_six_term_refuses_without_relaxing_root(self):
        result = model.pair_failure(self.budget)
        self.assertEqual((result['stage'], result['modulus']), ('Safe Basis projection', 3))
        self.assertEqual(result['bound'], 143_487_364_442_685_097_949_665_097_315_220_891_543_597)
        self.assertFalse(result['exact_admitted'])
        self.assertIsNone(model.pair_failure(model.Budget(margin=1)))

    def test_triple_refresh_does_not_admit_following_square(self):
        result = model.triple_square(self.budget)
        self.assertTrue(result['refreshed_admitted'])
        self.assertFalse(result['exact_admitted'])
        self.assertEqual(result['bound'], 223_202_566_911_318_450_070_487_589_240_156_854_456_321)
        self.assertTrue(model.triple_square(model.Budget(margin=1))['exact_admitted'])

    def test_sister_compact_layout_still_exceeds_real_budget(self):
        result = model.sister_failure(self.budget)
        self.assertEqual((result['step'], result['modulus']), (3, 21))
        self.assertEqual(result['stage'], 'dependent sister view')
        self.assertEqual(result['bound'], 120_529_386_131_860_840_228_865_404_486_405_906_096_233)
        self.assertFalse(result['exact_admitted'])
        self.assertIsNone(model.sister_failure(model.Budget(margin=1)))

    def test_zero_product_term_matches_rust_model(self):
        expected_rounding = (model.N * model.N + model.N + 2) // 2
        self.assertEqual(self.budget.multiply(0, 0), expected_rounding + self.budget.switch)

    def test_model_never_claims_native_execution_or_production_admission(self):
        result = model.report(Path(__file__).resolve().parents[1])
        self.assertEqual(result['native_tests_executed'], 0)
        self.assertFalse(result['production_refresh_admitted'])
        self.assertFalse(result['legacy_clockwork_gate_changed'])


if __name__ == '__main__':
    unittest.main()
