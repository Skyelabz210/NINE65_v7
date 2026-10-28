import unittest

try:
    from .run_public_refresh_research_gates import SUITES, command_for, validate_result
except ImportError:
    from run_public_refresh_research_gates import SUITES, command_for, validate_result


class PublicRefreshRunnerTests(unittest.TestCase):
    name = "research::complete_refresh"

    def output(self, passed=1, failed=0, ignored=0, name=None):
        status = "FAILED" if failed else "ok"
        return (f"running 1 test\ntest {name or self.name} ... diagnostic output\nok\n\n"
                f"test result: {status}. {passed} passed; {failed} failed; "
                f"{ignored} ignored; 0 measured; 42 filtered out; finished in 2.24s\n")

    def test_accepts_one_exact_executed_test_with_diagnostic_output(self):
        validate_result(self.output(), 0, self.name)

    def test_rejects_cargo_success_with_zero_tests_or_only_ignored_tests(self):
        for output in (self.output(passed=0), self.output(passed=0, ignored=1)):
            with self.subTest(output=output), self.assertRaises(ValueError):
                validate_result(output, 0, self.name)

    def test_rejects_failure_even_with_a_successful_summary(self):
        with self.assertRaises(ValueError):
            validate_result(self.output(), 101, self.name)
        with self.assertRaises(ValueError):
            validate_result(self.output(passed=0, failed=1), 0, self.name)

    def test_rejects_wrong_name_and_multiple_or_missing_summaries(self):
        for output in (self.output(name="other::test"), self.output() * 2,
                       "running 1 test\n", self.output(passed=2)):
            with self.subTest(output=output), self.assertRaises(ValueError):
                validate_result(output, 0, self.name)

    def test_each_command_selects_exactly_one_test_in_its_intended_target(self):
        for suite, specs in SUITES.items():
            for spec in specs:
                with self.subTest(suite=suite, name=spec[2]):
                    command = command_for(spec)
                    before, after = command[:command.index("--")], command[command.index("--")+1:]
                    self.assertIn(spec[0], before)
                    if spec[1]:
                        self.assertEqual(before[before.index(spec[0])+1], spec[1])
                    self.assertEqual(after[0], spec[2])
                    self.assertIn("--exact", after)
                    self.assertEqual("--ignored" in after, spec[3])
                    self.assertIn("--test-threads=1", after)


if __name__ == "__main__":
    unittest.main()
