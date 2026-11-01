#!/usr/bin/env python3
"""Regression tests for bounded, operation-executing arrow validation."""
import unittest

from a2_arrow_suite import audit_construct, audit_trace


def gate(report, name):
    return next(item for item in report["gates"] if item["gate"] == name)["verdict"]


class ArrowSuiteTests(unittest.TestCase):
    def identity(self, **kwargs):
        arguments = dict(name="identity", input_moduli=[2, 3], output_moduli=[2, 3],
                         step=lambda state, order: state, inverse=lambda state: state,
                         expected=lambda state: state)
        arguments.update(kwargs)
        return audit_construct(**arguments)

    def test_actual_step_is_executed_and_wrong_identity_semantics_fail(self):
        calls = []

        def shifted(state, order):
            calls.append((state, order))
            return ((state[0] + 1) % 2, state[1])

        report = self.identity(step=shifted, inverse=lambda out: ((out[0] - 1) % 2, out[1]))
        self.assertEqual(len(calls), 12)
        self.assertEqual(gate(report, "G1"), "PASS")
        self.assertEqual(gate(report, "G3"), "PASS")
        self.assertEqual(gate(report, "G4"), "FAIL")

    def test_constant_operation_fails_actual_output_census(self):
        report = self.identity(step=lambda state, order: (0, 0))
        self.assertEqual(gate(report, "G1"), "FAIL")
        self.assertEqual(gate(report, "G3"), "FAIL")

    def test_bad_inverse_fails(self):
        self.assertEqual(gate(self.identity(inverse=lambda state: (0, 0)), "G1"), "FAIL")

    def test_actual_schedule_dependence_fails(self):
        report = self.identity(step=lambda state, order: state if order[0] == 0 else ((state[0] + 1) % 2, state[1]))
        self.assertEqual(gate(report, "G2"), "FAIL")

    def test_full_joint_check_rejects_pairwise_independent_xor(self):
        report = audit_construct(name="xor", input_moduli=[2, 2], output_moduli=[2, 2, 2],
                                 step=lambda state, order: (*state, state[0] ^ state[1]),
                                 inverse=lambda out: out[:2], expected=lambda state: (*state, state[0] ^ state[1]))
        self.assertEqual(gate(report, "G1"), "PASS")
        self.assertEqual(gate(report, "G3"), "FAIL")

    def test_quotient_only_is_lossy_but_quotient_remainder_can_be_reversible(self):
        lossy = audit_construct(name="floor", input_moduli=[6], output_moduli=[3],
                                step=lambda state, order: (state[0] // 2,),
                                inverse=lambda out: (2 * out[0],), expected=lambda state: (state[0] // 2,))
        self.assertEqual(gate(lossy, "G1"), "FAIL")
        retained = audit_construct(name="division", input_moduli=[6], output_moduli=[3, 2],
                                   step=lambda state, order: divmod(state[0], 2),
                                   inverse=lambda out: (2 * out[0] + out[1],), expected=lambda state: divmod(state[0], 2))
        self.assertEqual(gate(retained, "G1"), "PASS")
        self.assertEqual(gate(retained, "G3"), "PASS")

    def test_redundant_quotient_lanes_can_be_reversible_and_still_fail_iid(self):
        report = audit_construct(name="redundant quotient", input_moduli=[6], output_moduli=[2, 3, 2],
                                 step=lambda state, order: (state[0] // 2 % 2, state[0] // 2 % 3, state[0] % 2),
                                 inverse=lambda out: (2 * out[1] + out[2],),
                                 expected=lambda state: (state[0] // 2 % 2, state[0] // 2 % 3, state[0] % 2))
        self.assertEqual(gate(report, "G1"), "PASS")
        self.assertEqual(gate(report, "G3"), "FAIL")

    def test_sampling_cannot_certify_iid(self):
        report = self.identity(domain=[(0, 0), (1, 1)])
        self.assertEqual(gate(report, "G3"), "UNVERIFIED")

    def test_absent_evidence_and_self_compared_custody_are_unverified(self):
        report = self.identity()
        self.assertEqual(gate(report, "G5"), "UNVERIFIED")
        self.assertEqual(gate(report, "G6"), "UNVERIFIED")
        self.assertEqual(report["status"], "INCOMPLETE")
        report = self.identity(lineage=dict(observed=["a"], authorized=["a"], observed_ref="same", authorized_ref="same"))
        self.assertEqual(gate(report, "G6"), "UNVERIFIED")

    def test_structural_policy_and_ordered_lineage_use_independent_references(self):
        report = self.identity(
            source_policy=dict(observed_emissions=["mixed-radix digit"], allowed_emissions=[],
                               observed_ref="execution-trace", policy_ref="user-policy"),
            lineage=dict(observed=["a", "b"], authorized=["b", "a"],
                         observed_ref="observed-log", authorized_ref="authorized-log"))
        self.assertEqual(gate(report, "G5"), "FAIL")
        self.assertEqual(gate(report, "G6"), "FAIL")

    def test_bijection_counts_cannot_establish_no_synthetic_emissions(self):
        report = self.identity(source_policy=dict(observed_emissions=[], allowed_emissions=[],
                                                  observed_ref="recorded-source-audit", policy_ref="user-policy"),
                               lineage=dict(observed=["authorized"], authorized=["authorized"],
                                            observed_ref="observed-trace", authorized_ref="approved-trace"))
        self.assertEqual(report["status"], "PASS_FINITE_DOMAIN")
        self.assertIn("external obligations", report["limitations"])

    def test_mixed_radix_can_pass_distribution_gates_and_fail_structural_policy(self):
        def digits(state, order):
            value = (3 * state[0] + 4 * state[1]) % 6
            return value % 2, value // 2

        def restore(output):
            value = output[0] + 2 * output[1]
            return value % 2, value % 3

        report = self.identity(
            step=digits, inverse=restore, expected=lambda state: digits(state, (0, 1)),
            source_policy=dict(observed_emissions=["mixed-radix digit"], allowed_emissions=[],
                               observed_ref="observed-digit-trace", policy_ref="user-policy"))
        for name in ("G1", "G2", "G3", "G4"):
            self.assertEqual(gate(report, name), "PASS")
        self.assertEqual(gate(report, "G5"), "FAIL")

    def test_incomplete_or_duplicate_exhaustive_claim_is_rejected(self):
        trace = dict(name="invalid", input_moduli=[2], output_moduli=[2], exhaustive_product=True,
                     rows=[dict(input=[0], output=[0])])
        with self.assertRaisesRegex(ValueError, "incomplete"):
            audit_trace(trace)
        trace["exhaustive_product"] = False
        trace["rows"] *= 2
        with self.assertRaisesRegex(ValueError, "duplicate"):
            audit_trace(trace)

    def test_missing_inverse_and_expected_output_are_not_passes(self):
        report = self.identity(inverse=None, expected=None)
        self.assertEqual(gate(report, "G1"), "UNVERIFIED")
        self.assertEqual(gate(report, "G4"), "UNVERIFIED")

    def test_exhaustive_product_size_has_an_explicit_limit(self):
        with self.assertRaisesRegex(ValueError, "max_states"):
            self.identity(max_states=5)

    def test_evaluation_orders_must_be_actual_lane_permutations(self):
        with self.assertRaisesRegex(ValueError, "permutation"):
            self.identity(orders=[(0, 0), (0, 1)])


if __name__ == "__main__":
    unittest.main()
