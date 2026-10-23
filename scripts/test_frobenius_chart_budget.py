import random
import unittest

from frobenius_chart_budget import BASE,T,plan,product,report,section


class FrobeniusChartTests(unittest.TestCase):
    def test_ring_section_is_stable_on_a_dense_11_multiple_and_idempotent(self):
        rng=random.Random(11991)
        for _ in range(32):
            a=[rng.randrange(121) for _ in range(8)]
            h=[rng.randrange(11) for _ in a]
            value=section(a)
            self.assertEqual([v%11 for v in value],[v%11 for v in a])
            self.assertEqual(section([(x+11*y)%121 for x,y in zip(a,h)]),value)
            self.assertEqual(section(value),value)

    def test_section_keeps_the_multiplicative_ring_structure(self):
        a=[4,7,91,0,53,2,11,118];b=[8,9,33,17,2,0,84,1]
        self.assertEqual(section(product(a,b)),product(section(a),section(b)))

    def test_ring_section_does_not_impersonate_the_canonical_coefficient_lift(self):
        r=report()["example"]
        self.assertEqual(r["section"],[78,78,99,77,33,88,44,22])
        self.assertNotEqual(r["section"],r["canonical_coefficient_section"])
        self.assertEqual([(x+11*y)%121 for x,y in zip(r["section"],r["witt_quotient"])],r["input"])

    def test_witt_quotient_retains_the_11_multiple(self):
        a=[103,41,18,20,119,1,11,93];h=list(range(8))
        f=section(a)
        qa=[((x-y)%121)//11 for x,y in zip(a,f)]
        shifted=[(x+11*y)%121 for x,y in zip(a,h)]
        qb=[((x-y)%121)//11 for x,y in zip(shifted,f)]
        self.assertEqual(qb,[(x+y)%11 for x,y in zip(qa,h)])

    def test_section_and_witt_quotient_respect_the_integer_chart_relation(self):
        u=[2,7,9,1,0,10,8,3];d=[33,102,18,91,5,20,81,119]
        z=[(11*x+5*y)%121 for x,y in zip(u,d)]
        fd=section(d);fz=section(z)
        self.assertEqual(fz,[(pow(5,11,121)*x)%121 for x in fd])
        wd=[((x-y)%121)//11 for x,y in zip(d,fd)]
        wz=[((x-y)%121)//11 for x,y in zip(z,fz)]
        scalar=(5-5**11)//11
        self.assertEqual(wz,[(x+5*y+scalar*v)%11 for x,y,v in zip(u,wd,d)])

    def test_public_native_plan_admits_one_section_and_refuses_a_reset(self):
        r=plan()
        self.assertTrue(r["admitted"])
        self.assertEqual(r["multiplication_depth"],4)
        self.assertEqual(r["exact_ciphertext_products"],5)
        self.assertEqual(r["ciphertext_Q_bits"],211)
        self.assertLessEqual(r["input_V_bits"],21)
        self.assertLess(r["section_V_bits"],r["ciphertext_Q_bits"])
        self.assertFalse(plan(input_v=r["section_V"])["admitted"])
        self.assertFalse(r["canonical_integer_lift"])
        self.assertFalse(r["production_admitted"])


if __name__=="__main__":
    unittest.main()
