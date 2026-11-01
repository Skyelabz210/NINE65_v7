#!/usr/bin/env python3
"""Run the actual Lean kernel, including negative proof-gate controls."""

import os
from pathlib import Path
import shutil
import tempfile
import unittest

from check_public_refresh_proofs import MODULES, ProofError, verify


PACKAGE = Path(__file__).resolve().parents[1] / "lean4/KElimination"
LEAN = os.environ.get("LEAN", "lean")


class PublicRefreshProofTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.package = Path(self.directory.name)
        shutil.copy(PACKAGE / "lean-toolchain", self.package)
        for name in (*MODULES, "scripts/PublicRefreshAudit"):
            target = self.package / (name.replace(".", "/") + ".lean")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(PACKAGE / (name.replace(".", "/") + ".lean"), target)

    def append(self, source):
        path = self.package / (MODULES[0].replace(".", "/") + ".lean")
        with path.open("a") as handle:
            handle.write("\n" + source + "\n")

    def test_real_kernel_checks_all_modules_and_audits_dependencies(self):
        report = verify(self.package, LEAN)
        self.assertEqual(report["status"], "passed")
        self.assertEqual(len(report["modules"]), len(MODULES))
        self.assertIn("Public refresh axiom audit OK", report["audit"])

    def test_missing_compiler_fails_closed(self):
        with self.assertRaisesRegex(ProofError, "cannot execute Lean"):
            verify(self.package, str(self.package / "absent-lean"))

    def test_missing_proof_fails_closed(self):
        (self.package / (MODULES[0].replace(".", "/") + ".lean")).unlink()
        with self.assertRaisesRegex(ProofError, "missing proof input"):
            verify(self.package, LEAN)

    def test_broken_proof_is_rejected(self):
        self.append("theorem broken_refresh_control : (1 : Nat) = 2 := by rfl")
        with self.assertRaisesRegex(ProofError, "Lean failed"):
            verify(self.package, LEAN)

    def test_removed_required_theorem_is_rejected(self):
        path = self.package / "KElimination/PublicRefreshReturn.lean"
        path.write_text(path.read_text().replace(
            "dense_product_return", "renamed_dense_product_return"))
        with self.assertRaisesRegex(ProofError, "Missing required public refresh theorem"):
            verify(self.package, LEAN)

    def test_sorry_is_rejected_even_when_source_disables_warnings(self):
        self.append("set_option warningAsError false\n"
                    "theorem hidden_refresh_control : False := by sorry")
        with self.assertRaisesRegex(ProofError, "sorryAx|Lean failed"):
            verify(self.package, LEAN)

    def test_axiom_outside_proof_namespace_is_rejected(self):
        self.append("axiom outside_refresh_namespace : False")
        with self.assertRaisesRegex(ProofError, "Unexpected axiom"):
            verify(self.package, LEAN)

    def test_unused_opaque_sorry_is_rejected(self):
        self.append("set_option warningAsError false\n"
                    "opaque unused_refresh_control : False := by sorry")
        with self.assertRaisesRegex(ProofError, "sorryAx|Lean failed"):
            verify(self.package, LEAN)


if __name__ == "__main__":
    unittest.main()
