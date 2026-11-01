import unittest
from validate_cram_comparative_smoke import validate


def fixture():
    return {
        "schema": "nine65-comparative-probe-v1",
        "status": "FAIL",
        "metadata": {
            "build_profile": "debug", "allow_insecure_feature": True,
            "comparison_only_parameter_set": True, "security_claim_bits": 0,
        },
        "correctness": {
            "legacy": {
                "encrypt": True, "decrypt": True, "add_ct": True, "sub_ct": True,
                "negate_ct": True, "add_plain": True, "mul_plain": True,
                "mul_ct": False, "mul_ct_status": "refused-#135",
            },
            "dual_rns": {
                "encrypt": True, "decrypt": True, "add_ct": True,
                "add_plain": True, "mul_plain": True, "mul_ct": True,
            },
        },
        "operations_ns": {"legacy": {"mul_ct": "refused-#135"}},
        "ct_mul_depth": {
            "requested": 2, "completed": 2,
            "all_completed_entries_correct": True, "first_error": None,
            "entries": [
                {"depth": 1, "expected": 64, "decrypted": 64,
                 "correct": True, "mismatch_delta_mod_t": 0},
                {"depth": 2, "expected": 4096, "decrypted": 4096,
                 "correct": True, "mismatch_delta_mod_t": 0},
            ],
        },
    }


class SmokeValidationTests(unittest.TestCase):
    def test_expected_refusal_is_classified_without_cryptographic_success_claim(self):
        result = validate(fixture(), probe_exit=1)
        self.assertEqual(result["status"], "UNSUPPORTED")
        self.assertEqual(result["first_divergence"]["reason"], "refused-#135")
        self.assertEqual(result["dual_rns_depth"], "PASS")
        self.assertIs(result["security_equivalent_comparison"], False)

    def assert_rejected(self, mutate, code=1):
        document = fixture()
        mutate(document)
        with self.assertRaises(AssertionError):
            validate(document, probe_exit=code)

    def test_wrong_dual_multiply_rejected(self):
        self.assert_rejected(lambda d: d["correctness"]["dual_rns"].__setitem__("mul_ct", False))

    def test_wrong_legacy_supported_operation_rejected(self):
        self.assert_rejected(lambda d: d["correctness"]["legacy"].__setitem__("sub_ct", False))

    def test_plaintext_mismatch_rejected_even_if_flag_true(self):
        self.assert_rejected(lambda d: d["ct_mul_depth"]["entries"][1].__setitem__("decrypted", 4095))

    def test_missing_depth_rejected(self):
        self.assert_rejected(lambda d: d["ct_mul_depth"].__setitem__("completed", 1))

    def test_absent_depth_oracle_rejected(self):
        self.assert_rejected(lambda d: d["ct_mul_depth"]["entries"].__setitem__(1, {"depth": 2, "correct": True}))

    def test_unexpected_legacy_result_rejected(self):
        self.assert_rejected(lambda d: d["correctness"]["legacy"].__setitem__("mul_ct_status", "unexpected-ciphertext"))

    def test_unexpected_probe_crash_rejected(self):
        self.assert_rejected(lambda d: None, code=101)

    def test_wrong_profile_rejected(self):
        self.assert_rejected(lambda d: d["metadata"].__setitem__("build_profile", "release"))

    def test_wrong_raw_status_rejected(self):
        self.assert_rejected(lambda d: d.__setitem__("status", "PASS"))

    def test_security_claim_rejected(self):
        self.assert_rejected(lambda d: d["metadata"].__setitem__("security_claim_bits", 128))

    def test_missing_boolean_rejected(self):
        self.assert_rejected(lambda d: d["correctness"]["dual_rns"].pop("decrypt"))

    def test_nonsequential_depth_rejected(self):
        self.assert_rejected(lambda d: d["ct_mul_depth"]["entries"][1].__setitem__("depth", 3))


if __name__ == "__main__":
    unittest.main()
