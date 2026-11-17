"""Producer/certificate boundary checks complement the exhaustive model oracle."""
import unittest

from models import (AdjacentFrame, compile_integer_query, orientation_from_views,
                    observe_point, bbs_residue_step, hensel_step,
                    jet_quotient_query)


class AdmissionTests(unittest.TestCase):
    def test_reject_nonunimodular_certificate(self):
        with self.assertRaisesRegex(ValueError, 'unimodular'):
            compile_integer_query([[1]], [1], 6, [[2]], [[1]])

    def test_reject_certificate_that_does_not_diagonalize(self):
        with self.assertRaisesRegex(ValueError, 'diagonalize'):
            compile_integer_query([[2, 1], [0, 3]], [2, 1], 6,
                                  [[1, 0], [0, 1]], [[1, 0], [0, 1]])

    def test_reject_invalid_dimensions_and_noninteger_inputs(self):
        for args in [([[1, 2]], [1], 6, [[1]], [[1]]),
                     ([[1]], [1], 6, [[True]], [[1]]),
                     ([[1]], [1.0], 6, [[1]], [[1]])]:
            with self.assertRaises(ValueError):
                compile_integer_query(*args)

    def test_decoder_requires_observation_dimension_and_integer_type(self):
        decoder = compile_integer_query([[2]], [4], 6, [[1]], [[1]])
        for bad in [[], [1, 2], [1.0], [True]]:
            with self.assertRaises(ValueError):
                decoder.evaluate(bad)

    def test_geometry_requires_capacity_and_canonical_lanes(self):
        frame = AdjacentFrame(9)
        points = [observe_point(p, frame) for p in ((0, 0), (1, 0), (0, 1))]
        with self.assertRaisesRegex(ValueError, 'capacity'):
            orientation_from_views(points, 3, frame)
        points[0] = ((9, 0), (0, 0))
        with self.assertRaisesRegex(ValueError, 'noncanonical'):
            orientation_from_views(points, 1, frame)

    def test_geometry_cannot_infer_a_source_bound_from_observations(self):
        # Real determinant -1. Lying about H=0 can give the wrong sign; this is
        # a documented external producer obligation, not a validated input.
        frame = AdjacentFrame(9)
        points = [observe_point(p, frame) for p in ((0, 0), (1, 0), (0, -1))]
        self.assertEqual(orientation_from_views(points, 0, frame), 1)
        self.assertEqual(orientation_from_views(points, 1, frame), -1)

    def test_bbs_retains_outgoing_carrier_and_requires_capacity(self):
        frame = AdjacentFrame(2)
        result, readings = bbs_residue_step([1], frame)
        self.assertEqual(result, (0,))
        self.assertEqual(readings[-1], (1, 1))
        result, readings = bbs_residue_step([1, 0], frame)
        self.assertEqual(result, (0, 1))
        self.assertEqual(readings[-1], (0, 0))
        with self.assertRaisesRegex(ValueError, 'capacity'):
            bbs_residue_step([1] * 6, frame)

    def test_local_root_and_jet_unit_admission(self):
        with self.assertRaisesRegex(ValueError, 'certificate'):
            hensel_step([0, 0, 1], 2, 1, 0)  # multiple root
        with self.assertRaisesRegex(ValueError, 'certificate'):
            hensel_step([-1, 1], 5, 1, 0)  # not a root
        with self.assertRaisesRegex(ValueError, 'unit'):
            jet_quotient_query(3, 1, 2, 6)


if __name__ == '__main__':
    unittest.main()
