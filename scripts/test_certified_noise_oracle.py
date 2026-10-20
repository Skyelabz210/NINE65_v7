import unittest
from fractions import Fraction
from itertools import product

from certified_noise_oracle import (
    coefficient_product_bound,
    fpd_auxiliary_capacity_holds,
    fpd_rounding_error,
    fpd_scale_round,
    fpd_shift_multiplier,
    negacyclic_mul,
    tensor_cross_bound,
    tensor_cross_component,
    scalar_ciphertext,
    phase_error,
    multiply_tensor,
    scalar_multiply_bound,
)


class CertifiedNoiseOracleTests(unittest.TestCase):
    def test_floor_delta_encoding_correction_is_required(self):
        q, t = 17, 3
        secret = (0, 0)
        ct = scalar_ciphertext(2, (0, 0), (0, 0), secret, q, t)
        actual = max(map(abs, phase_error(ct, 2, secret, q, t)))
        self.assertEqual(actual, 4)
        self.assertGreater(actual, 0, "zero sampled noise does not mean zero ideal-scale error")
        self.assertEqual(actual, (q % t) * (t - 1))

    def test_fresh_error_bound_exhausts_ternary_and_cbd_support(self):
        vectors = list(product((-1, 0, 1), repeat=2))
        maximum = 0
        for secret, mask, pk_error, e1, e2 in product(vectors, repeat=5):
            a = negacyclic_mul(pk_error, mask)
            b = negacyclic_mul(e2, secret)
            actual = max(abs(-x + y + z) for x, y, z in zip(a, e1, b))
            self.assertLessEqual(actual, 5)  # (2N+1)*eta, N=2, eta=1
            maximum = max(maximum, actual)
        self.assertEqual(maximum, 5, "the support bound is attained")

    def test_scalar_multiply_bound_on_actual_phase_and_missing_winding_negative(self):
        q, t, n = 257, 3, 2
        vectors = list(product((-1, 0, 1), repeat=n))
        components = [(0, 0), (-128, -128), (-128, 128), (128, -128), (128, 128)]
        winding_counterexample = None
        checked = 0
        for secret, c1a, c1b, ma, mb in product(vectors, components, components, range(t), range(t)):
            for ea, eb in product(vectors, repeat=2):
                a = scalar_ciphertext(ma, ea, c1a, secret, q, t)
                b = scalar_ciphertext(mb, eb, c1b, secret, q, t)
                va = max(map(abs, phase_error(a, ma, secret, q, t)))
                vb = max(map(abs, phase_error(b, mb, secret, q, t)))
                result = multiply_tensor(a, b, q, t)
                actual = max(map(abs, phase_error(result, ma * mb, secret, q, t)))
                bound = scalar_multiply_bound(n, t, q, va, vb)
                self.assertLessEqual(actual, bound)
                omitted_winding = ((t - 1) // 2 * (va + vb)
                    + (n * va * vb + q - 1) // q + (t * (1 + n + n*n) + 1) // 2)
                if actual > omitted_winding:
                    winding_counterexample = (actual, omitted_winding)
                checked += 1
        self.assertEqual(checked, 164025)
        self.assertIsNotNone(winding_counterexample, "must detect the missing phase-winding terms")

    def test_fpd_identity_and_rounding_bound_exhaustive(self):
        for q in range(3, 32, 2):
            for t in range(1, q):
                for x in range(-2 * q, 2 * q + 1):
                    y, remainder = fpd_scale_round(x, t, q)
                    z = t * x + q // 2
                    self.assertEqual(z, q * y + remainder)
                    self.assertGreaterEqual(remainder, 0)
                    self.assertLess(remainder, q)
                    self.assertLess(abs(fpd_rounding_error(x, t, q)), Fraction(1, 2))

    def test_negative_inputs_use_floor_rule(self):
        # Q=5, t=2, X=-1: floor((-2+2)/5)=0, not truncation of -2/5.
        self.assertEqual(fpd_scale_round(-1, 2, 5), (0, 0))
        self.assertEqual(fpd_scale_round(-2, 2, 5), (-1, 3))

    def test_omitting_fpd_floor_scale_term_fails_fixture(self):
        q, t, x = 5, 2, 2
        actual, _ = fpd_scale_round(x, t, q)
        omitted_term = (t * x) // q
        self.assertEqual(actual, 1)
        self.assertEqual(omitted_term, 0)
        self.assertNotEqual(actual, omitted_term)

    def test_fpd_auxiliary_capacity_is_strict_and_lift_fits(self):
        q, t, b = 15, 3, 2
        s_mult = fpd_shift_multiplier(b, t)
        required = 2 * s_mult * q
        self.assertFalse(fpd_auxiliary_capacity_holds(required, b, t, q))
        self.assertTrue(fpd_auxiliary_capacity_holds(required + 1, b, t, q))

        shift = s_mult * q
        for x in range(-b * q * q, b * q * q + 1):
            y, _ = fpd_scale_round(x, t, q)
            self.assertGreaterEqual(y + shift, 0)
            self.assertLessEqual(y + shift, 2 * shift)

    def test_negacyclic_product_bound_exhaustive_toy_domain(self):
        for n in (1, 2, 4):
            vectors = [
                tuple(values)
                for values in product((-1, 0, 1), repeat=n)
            ]
            for left in vectors:
                for right in vectors:
                    result = negacyclic_mul(left, right)
                    self.assertLessEqual(
                        max(map(abs, result)), coefficient_product_bound(n, 1, 1)
                    )

    def test_d1_cross_term_exceeds_single_product_bound(self):
        # Q=9 gives centered coefficient support [-4,4]. For N=2 the
        # selected vectors attain 2*N*B^2 in d1, twice the single-product bound.
        b = 4
        component = (b, b)
        single = negacyclic_mul(component, component)
        d1 = tensor_cross_component(component, component, component, component)
        single_bound = coefficient_product_bound(2, b, b)
        cross_bound = tensor_cross_bound(2, b, b)
        self.assertEqual(max(map(abs, single)), single_bound)
        self.assertEqual(max(map(abs, d1)), cross_bound)
        self.assertGreater(max(map(abs, d1)), single_bound)


if __name__ == "__main__":
    unittest.main()
