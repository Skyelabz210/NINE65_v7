#!/usr/bin/env python3
"""Exercise the whole-library axiom gate on fresh, standard-library-only fixtures.

Uses the repository's pinned Lean version through lake, with no Mathlib download.
Fixtures intentionally containing sorry must build so the kernel audit, not a
warning grep, demonstrates rejection. Run from the repository root.
"""

from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "lean4/KElimination"
AUDIT = PACKAGE / "scripts/axiom_audit.sh"


class AxiomAuditControls(unittest.TestCase):
    def check_fixture(self, source, expected=None, foreign=""):
        with tempfile.TemporaryDirectory(prefix="nine65-audit-control-") as directory:
            package = Path(directory)
            (package / "KElimination").mkdir()
            (package / "lean-toolchain").write_bytes((PACKAGE / "lean-toolchain").read_bytes())
            (package / "lakefile.lean").write_text(
                'import Lake\nopen Lake DSL\npackage AuditControl\n'
                'lean_lib Foreign\n@[default_target] lean_lib KElimination where\n'
                '  globs := #[.andSubmodules `KElimination]\n'
            )
            (package / "Foreign.lean").write_text(foreign or "theorem foreign_clean : True := trivial\n")
            (package / "KElimination.lean").write_text("import KElimination.Probe\n")
            (package / "KElimination/Probe.lean").write_text(source)
            environment = os.environ.copy()
            environment.pop("LEAN_PATH", None)
            build = subprocess.run(["lake", "build"], cwd=package, env=environment,
                                   text=True, capture_output=True, timeout=120)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            result = subprocess.run(["bash", str(AUDIT)], cwd=package, env=environment,
                                    text=True, capture_output=True, timeout=120)
            output = result.stdout + result.stderr
            if expected is None:
                self.assertEqual(result.returncode, 0, output)
                self.assertIn("Axiom audit OK:", output)
            else:
                self.assertNotEqual(result.returncode, 0, output)
                self.assertIn(expected, output)

    def test_clean_theorem_and_definition(self):
        self.check_fixture("theorem witness : True := trivial\ndef value : Nat := 7\n")

    def test_former_hardness_axiom_is_rejected(self):
        self.check_fixture("namespace KElimination.AHOP.Hardness\n"
                           "axiom ahop_hardness : False\n", "Unexpected axiom")

    def test_axiom_outside_project_namespace(self):
        self.check_fixture("namespace OtherNamespace\naxiom bad : False\n", "Unexpected axiom")

    def test_macro_generated_axiom(self):
        self.check_fixture('import Lean\nmacro "hidden_assumption" : command => '
                           "`(axiom disguised : False)\nhidden_assumption\n", "Unexpected axiom")

    def test_transitive_imported_axiom(self):
        self.check_fixture("import Foreign\ntheorem witness : False := bridge\n",
                           "ForeignTrust.bad", "namespace ForeignTrust\naxiom bad : False\n"
                           "end ForeignTrust\ntheorem bridge : False := ForeignTrust.bad\n")

    def test_definition_dependency_without_theorem(self):
        self.check_fixture("import Foreign\nnoncomputable def value : Nat := ForeignTrust.value\n",
                           "ForeignTrust.value", "axiom ForeignTrust.value : Nat\n")

    def test_type_dependency_without_proof_use(self):
        self.check_fixture("import Foreign\ndef identity : ForeignTrust.P → ForeignTrust.P := id\n",
                           "ForeignTrust.P", "axiom ForeignTrust.P : Prop\n")

    def test_native_decide_requires_extra_trust(self):
        self.check_fixture("import Lean\nimport Std.Tactic\n"
                           "theorem native_witness : 1 + 1 = 2 := by native_decide\n",
                           "Lean.ofReduceBool")

    def test_sorry_in_theorem(self):
        self.check_fixture("theorem witness : False := by sorry\n", "sorryAx")

    def test_sorry_in_opaque(self):
        self.check_fixture("opaque hidden : False := by sorry\n", "sorryAx")

    def test_unused_foreign_axiom_is_not_a_project_dependency(self):
        self.check_fixture("import Foreign\ntheorem witness : True := trivial\n",
                           foreign="axiom ForeignTrust.unused : False\n")


if __name__ == "__main__":
    if shutil.which("lake") is None:
        raise SystemExit("lake is required; install the toolchain pinned in lean-toolchain")
    unittest.main()
