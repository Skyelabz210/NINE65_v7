#!/usr/bin/env python3
"""Negative controls for the forced public-refresh evidence contract."""
import unittest
import math

from check_real_refresh_evidence import validate_report


def oracle(index=1):
    return {"operation_index": index, "expected": 7, "decrypted": 7, "correct": True}


def fixture():
    primes = [998244353, 985661441, 754974721, 469762049]
    q = math.prod(primes)
    n, t, eta = 8192, 65537, 3
    injection = q // (8 * n * t)
    noise_bits = t.bit_length() + 2 * (n.bit_length() - 1) + eta.bit_length() + 2
    bound = t * ((1 << noise_bits) + n + t + 1)
    section = {
        "requested_operations": 1, "operations_achieved": 1,
        "completed_requested": True, "achieved_chain_correct": True,
        "expected_result": 7, "decrypted_result": 7, "real_refreshes": 1,
        "entries": [oracle()], "refresh_checks": [oracle()],
    }
    trial = dict(section, trial_index=1)
    return {
        "schema": "nine65-real-refresh-evidence-v1",
        "overall_correct": True,
        "metadata": {"integer_only_reporting": True, "simulated_refreshes": 0,
                     "trigger_pct": 100, "bootstrap_mode": "real",
                     "config": "secure_128_deep", "t": t, "n": n,
                     "eta": eta, "rns_primes": primes},
        "renewal_witness": {"enabled": True, "passed": True, "input_admitted": True,
                            "real_refreshes": 1, "expected": 7, "input_decrypted": 7,
                            "output_decrypted": 7, "input_coefficients_checked": n,
                            "output_coefficients_checked": n, "modulus_q": str(q),
                            "injected_error": str(injection), "input_reserve_scaled": str(q // (2 * n)),
                            "input_error_scaled": str(t * injection), "output_error_scaled": "1",
                            "refresh_error_bound_scaled": str(bound),
                            "declared_refresh_noise_mb": noise_bits * 1000},
        "operation_chain": section,
        "statistical_test": {"enabled": True, "successes": 1, "trials": 1,
                             "operations_per_trial": 1, "real_refreshes": 1,
                             "entries": [trial]},
    }


class RealRefreshEvidenceTests(unittest.TestCase):
    def errors(self, report):
        return validate_report(report, requested_operations=1, trials=1,
                               operations_per_trial=1)

    def test_complete_current_schema_passes(self):
        self.assertEqual(self.errors(fixture()), [])

    def test_stale_or_missing_schema_fails(self):
        for payload in ({}, {"depth_chain": {"correct": True}}, None):
            self.assertTrue(self.errors(payload))

    def test_zero_real_refresh_or_missing_checks_fails(self):
        for key, value in (("real_refreshes", 0), ("refresh_checks", [])):
            payload = fixture()
            payload["operation_chain"][key] = value
            self.assertTrue(self.errors(payload))

    def test_oracle_disagrees_despite_forged_correct_flag(self):
        for path in ("entries", "refresh_checks"):
            payload = fixture()
            payload["operation_chain"][path][0]["decrypted"] = 6
            self.assertTrue(self.errors(payload))

    def test_incomplete_chain_fails(self):
        payload = fixture()
        payload["operation_chain"]["operations_achieved"] = 0
        self.assertTrue(self.errors(payload))

    def test_wrong_final_plaintext_fails(self):
        payload = fixture()
        payload["operation_chain"]["decrypted_result"] = 6
        self.assertTrue(self.errors(payload))

    def test_failed_overall_status_cannot_pass(self):
        payload = fixture()
        payload["overall_correct"] = False
        self.assertTrue(self.errors(payload))

    def test_statistical_trial_must_execute_and_refresh(self):
        for field, value in (("entries", []), ("real_refreshes", 0), ("successes", 0)):
            payload = fixture()
            payload["statistical_test"][field] = value
            self.assertTrue(self.errors(payload))

    def test_a_wrong_refresh_in_any_trial_fails(self):
        payload = fixture()
        payload["statistical_test"]["entries"][0]["refresh_checks"][0]["decrypted"] = 6
        self.assertTrue(self.errors(payload))

    def test_float_and_boolean_counters_fail(self):
        for value in (1.0, True, "1", None):
            payload = fixture()
            payload["operation_chain"]["real_refreshes"] = value
            self.assertTrue(self.errors(payload))

    def test_simulated_or_mislabeled_run_fails(self):
        for key, value in (("simulated_refreshes", 1), ("bootstrap_mode", "disabled"),
                           ("trigger_pct", 25), ("integer_only_reporting", False)):
            payload = fixture()
            payload["metadata"][key] = value
            self.assertTrue(self.errors(payload))

    def test_identity_refresh_cannot_pass_even_with_correct_plaintext(self):
        payload = fixture()
        witness = payload["renewal_witness"]
        witness["output_error_scaled"] = witness["input_error_scaled"]
        self.assertTrue(self.errors(payload))

    def test_missing_or_understressed_renewal_fails(self):
        for field, value in (("input_error_scaled", "1"), ("output_error_scaled", None),
                             ("real_refreshes", 0), ("output_coefficients_checked", 1),
                             ("output_decrypted", 6)):
            payload = fixture()
            payload["renewal_witness"][field] = value
            self.assertTrue(self.errors(payload))

    def test_forged_renewal_threshold_or_out_of_corridor_input_fails(self):
        for field in ("refresh_error_bound_scaled", "input_reserve_scaled", "injected_error"):
            payload = fixture()
            payload["renewal_witness"][field] = "1"
            self.assertTrue(self.errors(payload))
        payload = fixture()
        payload["renewal_witness"]["input_error_scaled"] = payload["renewal_witness"]["modulus_q"]
        self.assertTrue(self.errors(payload))


if __name__ == "__main__":
    unittest.main()
