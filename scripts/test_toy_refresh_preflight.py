import unittest
from check_toy_refresh_preflight import residual_radius, admitted


class PreflightTests(unittest.TestCase):
    def test_stressed_attachment_is_admitted(self):
        q, p = 97 * 2**40, 97
        e = 2**40 // (4 * p) + 8
        self.assertEqual(residual_radius(q, p, 4, e), 2)
        self.assertTrue(admitted(q, p, 4, e, 3))

    def test_exact_error_boundary(self):
        q, p, h, b = 97 * 2**40, 97, 4, 3
        maximum = (2*q*(b+1)-q*(h+1)-1)//(2*p*p)
        self.assertTrue(admitted(q,p,h,maximum,b))
        self.assertFalse(admitted(q,p,h,maximum+1,b))
        self.assertFalse(admitted(q,p,h,q//(2*p)-1,b))

    def test_invalid_inputs_refuse(self):
        for args in [(0,5,1,0), (80,0,1,0), (80,5,-1,0), (80,5,1,-1)]:
            with self.assertRaises(ValueError):
                residual_radius(*args)

    def test_exhaustive_scalar_component_rounding(self):
        q,p=80,5
        for s in [-1,0,1]:
            for c0 in range(q):
                for c1 in range(q):
                    phase=c0+c1*s
                    m=(2*p*phase+q)//(2*q)
                    error=abs(phase-(q//p)*m)
                    projected=(2*p*p*c0+q)//(2*q)+s*((2*p*p*c1+q)//(2*q))
                    self.assertLessEqual(abs(projected-p*m),residual_radius(q,p,abs(s),error))


if __name__ == '__main__':
    unittest.main()
