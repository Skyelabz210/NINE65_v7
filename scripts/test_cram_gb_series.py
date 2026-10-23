import unittest

from cram_gb_series import direct_first_negative, first_negative, upstream_compatibility_cases


class ExactGröbnerSeriesTests(unittest.TestCase):
    def test_lazy_recurrence_matches_independent_binomial_expansions(self):
        for n in (1, 4, 8, 16):
            for d in (2, 3, 5, 7):
                for count in (0, n, n**d):
                    with self.subTest(n=n, degree=d, count=count):
                        equations = [(d, count), (3, n)]
                        self.assertEqual(first_negative(n, equations),
                                         direct_first_negative(n, equations, 2*n))

    def test_pinned_upstream_comparison_inputs_are_nontrivial(self):
        for n, equations, _, precision in upstream_compatibility_cases():
            precision = 2*n if precision is None else precision
            self.assertEqual(first_negative(n, equations, precision),
                             direct_first_negative(n, equations, precision))

    def test_native_bounded_error_model_stops_at_degree_seven(self):
        self.assertEqual(first_negative(8192, [(7, 8192**7), (3, 8192)]), 7)

    def test_unchanged_inconclusive_cutoff_is_preserved(self):
        self.assertIsNone(first_negative(8192, [(40000, 100)]))
        self.assertIsNone(first_negative(16, [(3, 0)], precision=0))

    def test_noninteger_or_negative_exponents_are_rejected(self):
        for n, equations in ((-1, []), (1, [(0, 1)]), (1, [(2, -1)]), (1, [(2, 1.5)])):
            with self.assertRaises(ValueError):
                first_negative(n, equations)


if __name__ == "__main__":
    unittest.main()
