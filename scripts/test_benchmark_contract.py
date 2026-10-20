#!/usr/bin/env python3
"""Regression gates for issue #190; no cryptographic correctness claim."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from benchmark_contract import build_command, classify_result, evidence_contract
from cram_compare_results import group_report
from test_cram_compare_results import record
import run_nine65_v7_scale_sweep as sweep
import run_nine65_v6_v7_compare as compare


def passing_payload():
    return {
        "schema": "nine65-comparative-probe-v1", "status": "PASS",
        "metadata": {"build_profile": "debug", "allow_insecure_feature": True},
        "correctness": {"dual_rns": {"encrypt": True, "mul_ct": True}},
        "ct_mul_depth": {
            "requested": 1, "completed": 1, "all_completed_entries_correct": True,
            "first_error": None,
            "entries": [{"depth": 1, "correct": True, "expected": 64, "decrypted": 64}],
        },
    }


class BenchmarkContractTests(unittest.TestCase):
    def test_debug_command_keeps_seeded_fixtures_out_of_release(self):
        command = build_command("cram_comparative_probe")
        self.assertIn("--locked", command)
        self.assertNotIn("--release", command)
        self.assertEqual(command[-1], "serde,allow_insecure")
        self.assertEqual(build_command("nine65_bench", insecure=False)[-1], "serde")

    def test_release_is_refused_before_build(self):
        for insecure in (True, False):
            with self.subTest(insecure=insecure), self.assertRaises(ValueError):
                build_command("cram_comparative_probe", "release", insecure=insecure)

    def test_release_security_gate_is_preserved(self):
        source = (sweep.ROOT / "crates/nine65/src/lib.rs").read_text()
        gate = re.search(r'#\[cfg\(all\(feature = "allow_insecure"[^\n]+\ncompile_error!\([^\n]+', source)
        self.assertIsNotNone(gate)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "gate.rs"
            path.write_text(gate.group(0) + "\n")
            for debug, insecure in ((True, True), (False, False), (False, True)):
                command = ["rustc", "--crate-type", "lib", "--emit", "metadata", str(path),
                           "--out-dir", directory, "-C", f"debug-assertions={'yes' if debug else 'no'}"]
                if insecure:
                    command += ["--cfg", 'feature="allow_insecure"']
                result = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, debug or not insecure, result.stderr)

    def test_correct_depth_requires_oracle_entries(self):
        self.assertEqual(classify_result(passing_payload(), 0), ("PASS", None))
        payload = passing_payload()
        payload["ct_mul_depth"]["entries"] = []
        self.assertEqual(classify_result(payload, 0)[0], "UNRUN")

    def test_wrong_plaintext_is_red_even_when_process_claims_pass(self):
        payload = passing_payload()
        payload["ct_mul_depth"]["entries"][0].update(correct=False, decrypted=63)
        status, first = classify_result(payload, 0)
        self.assertEqual(status, "WRONG_PLAINTEXT")
        self.assertEqual(first["depth"], 1)

    def test_oracle_values_override_a_forged_correct_flag(self):
        payload = passing_payload()
        payload["ct_mul_depth"]["entries"][0]["decrypted"] = 63
        self.assertEqual(classify_result(payload, 0)[0], "WRONG_PLAINTEXT")

    def test_malformed_depth_evidence_never_passes(self):
        for value in (None, [], {"entries": [None]}):
            payload = passing_payload()
            payload["ct_mul_depth"] = value
            self.assertEqual(classify_result(payload, 0)[0], "UNRUN")

    def test_operation_mismatch_is_reported(self):
        payload = passing_payload()
        payload["correctness"]["dual_rns"]["encrypt"] = False
        self.assertEqual(classify_result(payload, 0),
                         ("WRONG_PLAINTEXT", {"path": "dual_rns", "operation": "encrypt"}))

    def test_retired_legacy_multiply_is_not_a_plaintext_mismatch(self):
        payload = passing_payload()
        payload["correctness"]["legacy"] = {"encrypt": True, "mul_ct": False, "mul_ct_status": "refused-#135"}
        payload["status"] = "FAIL"
        self.assertEqual(classify_result(payload, 1)[0], "UNSUPPORTED")
        payload["correctness"]["dual_rns"]["mul_ct"] = False
        self.assertEqual(classify_result(payload, 1)[0], "WRONG_PLAINTEXT")

    def test_typed_operation_refusal_is_unsupported(self):
        payload = passing_payload()
        entry = payload["ct_mul_depth"]["entries"][0]
        entry.update(correct=False, operation_error="capacity exceeded")
        self.assertEqual(classify_result(payload, 0), ("UNSUPPORTED", entry))

    def test_missing_or_failed_process_never_passes(self):
        self.assertEqual(classify_result(None, 127)[0], "UNRUN")
        self.assertEqual(classify_result(passing_payload(), 1)[0], "UNRUN")
        payload = passing_payload()
        payload["correctness"] = {}
        self.assertEqual(classify_result(payload, 0)[0], "UNRUN")

    def test_mislabeled_binary_profile_is_refused(self):
        payload = passing_payload()
        payload["metadata"]["build_profile"] = "release"
        self.assertEqual(classify_result(payload, 0)[0], "UNRUN")

    def test_debug_and_explicit_nonperformance_evidence_cannot_rank(self):
        left, right = record("left", 0), record("right", 0)
        for profile, allowed in (("release", False), ("debug", True)):
            a, b = copy.deepcopy(left), copy.deepcopy(right)
            for value in (a, b):
                value["compatibility"]["build_profile"] = profile
                value["provenance"]["performance_ranking_allowed"] = allowed
            comparison = group_report([a, b])[0]["comparisons"][0]
            self.assertTrue(comparison["correctness_gate"])
            self.assertFalse(comparison["ranking_allowed"])
            self.assertIsNone(comparison["left_over_right_median"])

    def test_build_failure_archives_every_planned_case(self):
        with tempfile.TemporaryDirectory() as directory:
            failure = {"returncode": 101, "stderr": "release feature rejected", "command": []}
            argv = ["sweep", "--output-dir", directory, "--configs", "secure_128", "--seeds", "42"]
            with patch("sys.argv", argv), patch.object(sweep, "build_probe", return_value=failure):
                self.assertEqual(sweep.main(), 2)
            manifest = json.loads((Path(directory) / "manifest.json").read_text())
            self.assertEqual(manifest["records"][0]["status"], "BUILD_FAILURE")
            self.assertEqual(manifest["summary"]["cases"], 1)
            self.assertFalse(manifest["evidence_contract"]["performance_ranking_allowed"])

    def test_missing_binary_is_archived(self):
        with tempfile.TemporaryDirectory() as directory:
            argv = ["sweep", "--skip-build", "--output-dir", directory, "--configs", "secure_128"]
            with patch("sys.argv", argv), patch.object(sweep, "BINARY", Path(directory) / "absent"):
                self.assertEqual(sweep.main(), 2)
            manifest = json.loads((Path(directory) / "manifest.json").read_text())
            self.assertEqual(manifest["records"][0]["status"], "UNRUN")

    def test_wrong_depth_fails_an_observational_sweep(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "probe"
            binary.touch()

            def fake_probe(command):
                payload = passing_payload()
                payload["ct_mul_depth"]["entries"][0].update(correct=False, decrypted=63)
                output = Path(command[command.index("--output") + 1])
                output.write_text(json.dumps(payload))
                return subprocess.CompletedProcess(command, 0, "", "")

            argv = ["sweep", "--skip-build", "--output-dir", directory,
                    "--configs", "secure_128", "--ct-mul-depth", "1"]
            with patch("sys.argv", argv), patch.object(sweep, "BINARY", binary), patch.object(sweep, "run", fake_probe):
                self.assertEqual(sweep.main(), 1)
            manifest = json.loads((Path(directory) / "manifest.json").read_text())
            self.assertEqual(manifest["records"][0]["status"], "WRONG_PLAINTEXT")
            self.assertEqual(manifest["summary"]["wrong_plaintext"], 1)

    def test_empty_matrix_is_refused(self):
        import argparse
        args = argparse.Namespace(profile="quick", configs=",", seeds="42")
        with self.assertRaises(SystemExit):
            sweep.make_cases(args)

    def test_both_runners_reject_release_argument(self):
        for runner in ("run_nine65_v7_scale_sweep.py", "run_nine65_v6_v7_compare.py"):
            result = subprocess.run(["python3", str(sweep.ROOT / "scripts" / runner),
                                     "--cargo-profile", "release"], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)

    def test_cross_version_records_keep_debug_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            contract = evidence_contract(Path(directory), Path(directory) / "absent")
        self.assertEqual(contract["security_equivalence"], "NON_SECURITY_EQUIVALENT")
        self.assertEqual(contract["allocation_tracking"], "UNMEASURED")
        payload = passing_payload()
        payload["operations_ns"] = {"legacy": {"encrypt": 42}}
        payload["correctness"]["legacy"] = {"encrypt": True}
        result = compare.RunResult("v7-comparative", 0, [], 0, 1, "out", "err", "raw.json", payload, None)
        normalized = compare.normalized_records([result], "host", "v6sha", "v7sha")
        self.assertEqual(normalized[0]["compatibility"]["build_profile"], "debug")
        self.assertFalse(normalized[0]["provenance"]["performance_ranking_allowed"])


if __name__ == "__main__":
    unittest.main()
