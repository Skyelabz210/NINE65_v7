"""Regression tests for the required CI job actor-bypass guard."""

from __future__ import annotations

import contextlib
import io
import pathlib
import tempfile
import unittest
from unittest import mock

from scripts import check_required_ci_actor_bypass as guard


def workflow(*, fast_if: str = "", include_full: bool = True) -> str:
    """Build a minimal workflow fixture with all required mechanical jobs."""
    full = "  full-test:\n    runs-on: ubuntu-latest\n" if include_full else ""
    return (
        "name: fixture\n"
        "jobs:\n"
        "  fast-gate:\n"
        "    runs-on: ubuntu-latest\n"
        f"{fast_if}"
        "  static-analysis:\n"
        "    runs-on: ubuntu-latest\n"
        f"{full}"
        "  ai-review:\n"
        "    if: github.actor != 'dependabot[bot]'\n"
    )


class ActorBypassGuardTests(unittest.TestCase):
    def run_guard(self, contents: str) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory, "ci.yml")
            path.write_text(contents, encoding="utf-8")
            output = io.StringIO()
            with mock.patch("sys.argv", ["guard", str(path)]), contextlib.redirect_stdout(
                output
            ), contextlib.redirect_stderr(output):
                status = guard.main()
        return status, output.getvalue()

    def test_accepts_actor_independent_required_jobs(self) -> None:
        status, output = self.run_guard(workflow())
        self.assertEqual(status, 0)
        self.assertIn("actor-independent", output)

    def test_rejects_actor_condition_on_required_job(self) -> None:
        status, output = self.run_guard(
            workflow(fast_if="    if: github.actor != 'dependabot[bot]'\n")
        )
        self.assertEqual(status, 1)
        self.assertIn("fast-gate", output)

    def test_allows_actor_condition_on_optional_review_job(self) -> None:
        status, _ = self.run_guard(workflow())
        self.assertEqual(status, 0)

    def test_rejects_missing_required_job(self) -> None:
        status, output = self.run_guard(workflow(include_full=False))
        self.assertEqual(status, 1)
        self.assertIn("full-test", output)


if __name__ == "__main__":
    unittest.main()
