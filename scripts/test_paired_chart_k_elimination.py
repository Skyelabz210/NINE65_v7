import unittest

from paired_chart_k_elimination import (
    M,
    P,
    SOURCE_K_RADIUS,
    chart_carry,
    composite_tray_carry,
    composite_sister_trays_signed_carry,
    k_eliminate_quotient,
    lift,
    report,
    source_residual_bound,
)


class KEliminationTropicalLiftTests(unittest.TestCase):
    def test_integer_quotient_matches_chart_rounding_over_native_window(self):
        for z99 in range(-16_005, 16_006):
            result = lift(z99)
            self.assertEqual(result["k_centered"], chart_carry(z99))
            self.assertLessEqual(abs(result["k_centered"]), SOURCE_K_RADIUS)

    def test_crt_quotient_recovers_negative_and_positive_carries(self):
        for z99 in (-16_005, -10_000, -1, 0, 1, 10_000, 16_005):
            result = lift(z99)
            self.assertEqual(result["k_centered"], result["expected_k"])
            self.assertEqual(
                result["centered_residual"], result["residual_from_low_tray"]
            )
        self.assertEqual(lift(-1)["expected_k"], 0)
        self.assertEqual(lift(1)["expected_k"], 0)
        self.assertGreater(lift(16_005)["expected_k"], 0)
        self.assertLess(lift(-16_005)["expected_k"], 0)

    def test_safe_basis_two_relation_removes_the_inverse(self):
        self.assertEqual(P, 2 * M + 1)
        self.assertEqual(pow(M, -1, P), P - 2)
        for z99 in range(-16_005, 16_006):
            result = lift(z99)
            self.assertEqual(
                result["k_from_phase_locked_2_relation"],
                result["k_eliminated_mod_p"],
            )

    def test_quotient_identity_rejects_unmatched_or_noncanonical_residues(self):
        with self.assertRaises(ValueError):
            k_eliminate_quotient(M, 0)
        with self.assertRaises(ValueError):
            k_eliminate_quotient(0, P)
        with self.assertRaises(ValueError):
            k_eliminate_quotient(0, 0, modulus=P, plaintext=P * 2)

    def test_source_error_bound_is_strictly_inside_the_half_clock_cell(self):
        bound = source_residual_bound()
        self.assertEqual(bound, 5_313)
        self.assertLess(bound, M // 2)

    def test_composite_98_tray_recovers_the_bounded_carry(self):
        checked = 0
        for z99 in range(-16_005, 16_006):
            result = lift(z99)
            if abs(result["centered_residual"]) <= source_residual_bound():
                composite = composite_tray_carry(z99)
                self.assertEqual(composite["k_centered"], result["k_centered"])
                self.assertEqual(composite["e99"], result["centered_residual"])
                checked += 1
        self.assertGreater(checked, 0)

    def test_composite_49_2_trays_isolate_the_signed_carry_bit(self):
        checked = 0
        bound = source_residual_bound()
        for z99 in range(-16_005, 16_006):
            result = lift(z99)
            if abs(result["centered_residual"]) <= bound:
                carry = result["k_centered"]
                sister = composite_sister_trays_signed_carry(z99)
                self.assertEqual(sister["k_mod_49_canonical"], carry % 49)
                self.assertEqual(sister["k_mod_2"], carry % 2)
                self.assertEqual(sister["sign_correction_bit"], int(carry < 0))
                self.assertEqual(sister["k_signed"], carry)
                checked += 1
        self.assertEqual(checked, 10_411)

    def test_low_tray_and_eliminated_carry_reconstruct_centered_residual(self):
        checked = 0
        bound = source_residual_bound()
        for z99 in range(-16_005, 16_006):
            result = lift(z99)
            residual = result["centered_residual"]
            if abs(residual) <= bound:
                self.assertEqual(residual, result["low_residue"] - M // 2)
                self.assertEqual(
                    residual,
                    99 * z99 - M * result["k_centered"],
                )
                checked += 1
        self.assertGreater(checked, 0)

    def test_report_does_not_claim_encrypted_gate_or_refresh(self):
        result = report()
        self.assertTrue(result["k_elimination"]["all_integer_quotient_checks_pass"])
        self.assertTrue(result["k_elimination"]["all_period_winding_checks_pass"])
        self.assertTrue(result["composite_sister_trays_49_2"]["all_signed_49_2_checks_pass"])
        self.assertFalse(
            result["composite_sister_trays_49_2"]["encrypted_canonicalization_or_sign_gate_exists"]
        )
        self.assertTrue(
            result["centered_chart_residual"]["removes_sheet_direction_exactly"]
        )
        self.assertFalse(result["centered_chart_residual"]["refresh_reset_proved"])
        self.assertFalse(result["public_refresh_admitted"])
        self.assertIn("do not implement", result["unclosed_encrypted_obligation"])


if __name__ == "__main__":
    unittest.main()
