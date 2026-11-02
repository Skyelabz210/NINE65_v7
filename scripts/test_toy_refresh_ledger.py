import unittest
from toy_refresh_ledger import plan, multiply, switching, QIN, QOUT, P


class LedgerTests(unittest.TestCase):
    def test_complete_cycle_closes(self):
        p=plan()
        self.assertEqual(p['returned_error'],195849)
        self.assertEqual(p['next_residual_radius'],3)
        self.assertEqual(len(p['horner_errors']),13)
        self.assertLess(2*P*P*p['restored_error'],QOUT)

    def test_exhausted_or_invalid_operands_refuse(self):
        for error in [-1,QIN//P]:
            with self.assertRaises(ValueError):
                multiply(QIN,P,error,1,switching(QIN,8))

    def test_source_square_includes_every_deposit(self):
        e=195849
        exact=(2*e)*(16*48+16*97*9)+(16*97*e*e+QIN-1)//QIN+137+195840
        self.assertEqual(plan()['following_square_error'],exact)


if __name__=='__main__':
    unittest.main()
