import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

from summarize_ct_verdicts import EXPECTED_OBSERVATIONS, summarize


NAME = "test_ct_dudect_example"
PREFIX = "security::ct_verification::constant_time_statistical"


def observation(verdict="CONSTANT-TIME at this sample size", control="1.0000", signal="2.0000"):
    return (
        "--- dudect: example observable ---\n"
        "  samples kept 5400/6000 after 90th-percentile crop\n"
        f"  t_control (A vs A', same class) = {control}\n"
        f"  t_signal  (A vs B,  cross class) = {signal}\n"
        f"  VERDICT: {verdict}\n"
    )


def transcript(reports=None, passed=1, failed=0, name=NAME):
    return (
        f"running 1 test\ntest {PREFIX}::{name} ... \n"
        + (observation() if reports is None else reports)
        + f"test result: {'FAILED' if failed else 'ok'}. {passed} passed; {failed} failed; "
        "0 ignored; 0 measured; 1256 filtered out; finished in 0.03s\n"
    )


class TimingSummaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.log = self.root / f"{NAME}.log"
        self.log.write_text(transcript())
        self.status = self.root / "status.tsv"
        self.status.write_text(f"{NAME}\t0\t0\n")

    def summary(self, count=1):
        return summarize(self.root, {NAME: count})

    def assert_invalid(self):
        result = self.summary()
        self.assertEqual(result["evidence_status"], "invalid")
        self.assertFalse(result["blocking_gate_pass"])
        self.assertTrue(result["errors"])

    def test_below_threshold_is_sample_evidence_without_certification(self):
        result = self.summary()
        self.assertEqual(result["observations"], {"below_threshold": 1, "inconclusive": 0, "timing_dependence": 0})
        self.assertTrue(result["blocking_gate_pass"])
        self.assertFalse(result["constant_time_established"])
        self.assertEqual(len(result["tests"][0]["log_sha256"]), 64)

    def test_inconclusive_is_not_promoted_by_successful_process_exit(self):
        self.log.write_text(transcript(observation("INCONCLUSIVE — noisy control", "6.3406", "2.0117")))
        result = self.summary()
        self.assertEqual(result["evidence_status"], "inconclusive")
        self.assertEqual(result["observations"]["below_threshold"], 0)
        self.assertTrue(result["blocking_gate_pass"])  # Existing Rust policy.
        self.assertFalse(result["all_observations_conclusive"])

    def test_measured_dependence_preserves_failure_and_observation(self):
        self.status.write_text(f"{NAME}\t101\t0\n")
        self.log.write_text(transcript(observation("TIMING DEPENDENCE MEASURED — signal", "1.4003", "8.6550"), passed=0, failed=1))
        result = self.summary()
        self.assertEqual(result["evidence_status"], "timing_dependence")
        self.assertFalse(result["blocking_gate_pass"])
        self.assertEqual(result["observations"]["timing_dependence"], 1)

    def test_missing_log_is_invalid(self):
        self.log.unlink()
        self.assert_invalid()

    def test_zero_matching_tests_cannot_pass(self):
        self.log.write_text("running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 1257 filtered out; finished in 0.00s\n")
        self.assert_invalid()

    def test_wrong_exact_test_cannot_supply_evidence(self):
        self.log.write_text(transcript(name="some_other_test"))
        self.assert_invalid()

    def test_crash_after_good_verdict_cannot_pass(self):
        self.status.write_text(f"{NAME}\t137\t0\n")
        self.assert_invalid()

    def test_capture_failure_cannot_pass(self):
        self.status.write_text(f"{NAME}\t0\t1\n")
        self.assert_invalid()

    def test_duplicate_invocation_cannot_hide_another_result(self):
        self.status.write_text(self.status.read_text() * 2)
        self.assert_invalid()

    def test_missing_expected_invocation_is_invalid(self):
        self.status.write_text("")
        self.assert_invalid()

    def test_multiple_observables_are_all_required(self):
        self.assertFalse(self.summary(count=2)["blocking_gate_pass"])
        self.log.write_text(transcript(observation() + observation("INCONCLUSIVE — noisy control", "6", "7")))
        result = self.summary(count=2)
        self.assertEqual(result["observations"]["inconclusive"], 1)
        self.assertEqual(result["observations"]["below_threshold"], 1)

    def test_malformed_or_unknown_statistics_never_become_clean_evidence(self):
        for text in (observation(signal="NaN"), observation(control="-1"),
                     observation().replace("t_signal", "missing_signal"),
                     observation(verdict="UNKNOWN")):
            with self.subTest(text=text):
                self.log.write_text(transcript(text))
                self.assert_invalid()

    def test_rounded_threshold_display_does_not_override_rust_verdict(self):
        self.log.write_text(transcript(observation(signal="5.0000")))
        self.assertTrue(self.summary()["blocking_gate_pass"])

    def test_cli_emits_failure_artifacts_even_when_build_or_run_is_missing(self):
        output = self.root / "summary.json"
        markdown = self.root / "summary.md"
        result = subprocess.run([sys.executable, str(Path(__file__).with_name("summarize_ct_verdicts.py")),
                                 "--input-dir", str(self.root), "--output", str(output),
                                 "--markdown", str(markdown)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(output.read_text())["evidence_status"], "invalid")
        self.assertIn("not established", markdown.read_text())

    def capture_workflow(self, inject_failure):
        """Exercise the actual shell loop with synthetic timing transcripts."""
        workflow = Path(__file__).resolve().parents[1] / ".github/workflows/ct_verification.yml"
        shell = workflow.read_text().split(
            "      - name: Run blocking dudect tests\n        run: |\n", 1)[1].split("\n      - name:", 1)[0]
        fixtures = self.root / "fixtures"
        fixtures.mkdir()
        failing_name = "test_ct_dudect_montgomery_mul_operand_magnitude"
        for name, count in EXPECTED_OBSERVATIONS.items():
            fail = inject_failure and name == failing_name
            report = observation("TIMING DEPENDENCE MEASURED — injected control", "1", "8") if fail else observation()
            (fixtures / f"{name}.log").write_text(transcript(report * count, int(not fail), int(fail), name))
        cargo = self.root / "cargo"
        cargo.write_text(
            "#!/usr/bin/env python3\nimport os,sys\nfrom pathlib import Path\n"
            "name=sys.argv[-1].rsplit('::',1)[-1]\n"
            "print((Path(os.environ['CT_TEST_FIXTURES'])/(name+'.log')).read_text())\n"
            "raise SystemExit(101 if name==os.environ.get('CT_TEST_FAIL') else 0)\n")
        cargo.chmod(0o755)
        env = dict(os.environ, PATH=str(self.root) + os.pathsep + os.environ["PATH"],
                   CT_TEST_FIXTURES=str(fixtures), CT_TEST_FAIL=failing_name if inject_failure else "")
        result = subprocess.run(["bash", "-c", textwrap.dedent(shell)], cwd=self.root,
                                env=env, capture_output=True, text=True)
        summary = summarize(self.root / "ct_dudect_tests")
        return result, summary

    def test_workflow_capture_collects_all_ten_tests_and_eleven_observables(self):
        result, summary = self.capture_workflow(False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(summary["blocking_gate_pass"], summary["errors"])
        self.assertEqual(summary["observations"]["below_threshold"], 11)

    def test_workflow_preserves_failed_process_and_continues_remaining_tests(self):
        result, summary = self.capture_workflow(True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse(summary["blocking_gate_pass"])
        self.assertEqual(summary["evidence_status"], "timing_dependence")
        self.assertEqual(summary["observations"]["timing_dependence"], 1)
        self.assertEqual(len(summary["tests"]), 10)
        self.assertEqual(summary["observations"]["below_threshold"], 10)


if __name__ == "__main__":
    unittest.main()
