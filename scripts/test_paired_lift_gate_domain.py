import unittest

from paired_lift_gate_domain import H, M, P, Q, analyze, evaluate_newton, newton_interpolation, report, round_weight, simplex_indices, triple_simplex_certificate, witness


class PairedLiftDomainTests(unittest.TestCase):
    def test_valid_edge_witnesses_use_the_true_native_period_and_phase_cap(self):
        for denominator, edges in [(16, [(-336,-1),(-262,-1),(-62,0),(62,0),(262,1),(336,1)]),
                                   (64, [(-323,-1),(-278,-1),(-48,0),(48,0),(278,1),(323,1)])]:
            for t, k in edges:
                w = witness(t, k, denominator)
                self.assertIsNotNone(w)
                self.assertEqual(sum(w["residuals"]), Q*k+w["g"])
                self.assertLessEqual(abs(w["g"]), Q//denominator)
                self.assertEqual(w["Z"][:2], [t, t])
                self.assertEqual((w["U"],w["D"]),(t,-2*t))
                self.assertEqual(len(w["residuals"]), H+1)

    def test_adjacent_excluded_points_are_not_smuggled_into_the_domain(self):
        for t,k,den in [(63,0,16),(261,1,16),(337,1,16),(49,0,64),(277,1,64),(324,1,64)]:
            self.assertIsNone(witness(t,k,den))

    def test_exact_restriction_rejects_shallow_fixed_pair_luts(self):
        for denominator,count,degree,depth in [(16,275,273,9),(64,189,187,8)]:
            r=analyze(denominator)
            self.assertEqual(r["witness_count"],count)
            self.assertEqual(r["minimal_univariate_restriction_degree"],degree)
            self.assertEqual(r["binary_ciphertext_multiply_depth_lower_bound"],depth)
            self.assertNotEqual(r["newton_degree_certificate"]["leading_nonzero_value"],0)

    def test_interpolator_recovers_an_independently_known_polynomial(self):
        polynomial=lambda x:(17*x**4-9*x**2+5*x+12)%P
        points=[(x,polynomial(x)) for x in [-7,-1,0,3,5,9,15]]
        xs,coefficients=newton_interpolation(points)
        self.assertEqual(max(i for i,c in enumerate(coefficients) if c),4)
        for x in [-19,2,4,137,65536]:
            self.assertEqual(evaluate_newton(xs,coefficients,x),polynomial(x))

    def test_third_anchored_tray_distinguishes_the_zero_phase_line(self):
        r=report()["third_tray"]
        self.assertEqual(r["zero_phase_block_views"],[1,1,-1])
        self.assertEqual(r["unit_lift_views"],[288,288,192])
        self.assertFalse(r["low_degree_three_variable_gate_proven"])
        self.assertTrue(report()["covers_input_adaptive_coefficients"] is False)

    def test_triple_chart_keeps_bounded_period_and_integer_winding(self):
        r=report()["third_tray"]
        self.assertEqual(r["component_triples"],757)
        self.assertEqual(r["component_chart_ranges"],[[-5,5],[-9,9],[-11,11]])
        self.assertEqual(r["H96_chart_integer_bounds"],[485,873,1067])
        self.assertEqual(r["chart_period_increment"],[1,0,0])
        self.assertEqual(r["determinant"],1)

    def test_tighter_source_entry_refuses_old_input_and_funds_reference_reentry(self):
        r=report()["reference_return_envelope"]
        self.assertEqual(r["old_Q119_over_20_input_refusal"],"prepared_source_phase_fits")
        self.assertLess(r["accepted_example_working_v"],r["maximum_admitted_working_v"])
        self.assertEqual(r["following_dense_work_product_v_bits"],88)
        self.assertEqual(r["following_prepared_source_v_bits"],44)
        self.assertTrue(r["conditional_reference_arithmetic_closure"])
        self.assertFalse(r["triple_chart_nonlinear_gate_executed"])

    def test_triple_zero_phase_simplex_is_unisolvent_without_claiming_a_gate(self):
        r=triple_simplex_certificate()
        self.assertEqual(r["zero_lift_public_witnesses"],6545)
        self.assertNotEqual(r["nonzero_determinant_mod_plaintext"],0)
        self.assertEqual(r["fixed_trivariate_total_degree_lower_bound"],33)
        self.assertFalse(r["degree_33_gate_constructed"])
        # Independently check the full triangular evaluation pattern on a
        # small graded basis; the native certificate uses the same theorem.
        from math import factorial, prod
        nodes=simplex_indices(5)
        for alpha in nodes:
            for beta in nodes:
                value=prod(prod(beta[i]-j for j in range(alpha[i])) for i in range(3))%P
                if sum(beta)<sum(alpha) or sum(beta)==sum(alpha) and beta!=alpha:
                    self.assertEqual(value,0)
                if alpha==beta:
                    self.assertEqual(value,prod(factorial(v) for v in alpha)%P)

    def test_existing_outer_ledger_refuses_the_minimum_generic_gate_depth(self):
        r=report()["generic_native_polynomial_budget"]
        self.assertEqual(r["minimum_triple_gate_depth"],6)
        self.assertEqual(r["first_refused_level"],5)
        self.assertFalse(r["all_circuits_proven_impossible"])


if __name__ == "__main__":
    unittest.main()
