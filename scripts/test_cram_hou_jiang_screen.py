import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from cram_hou_jiang_screen import complete, describe, LOCK, TASKS, verify_source


class HouJiangScreenTests(unittest.TestCase):
    def test_exact_native_parameters_and_pinned_source_manifest(self):
        spec = describe("balanced96_low_q")
        self.assertEqual((spec["n"], spec["positive"], spec["negative"], spec["q"]),
                         (8192, 48, 48, 983930967448092673))
        self.assertEqual(spec["error"], {"distribution": "CenteredBinomial", "eta": 3})
        lock = json.loads(LOCK.read_text())
        self.assertEqual(lock["revision"], "d60cac04dea5a397b8489cce7171f3fe38b277d8")
        self.assertEqual(len(lock["files"]), 24)
        self.assertTrue(all(len(digest) == 64 for digest in lock["files"].values()))

    def test_missing_duplicate_wrong_model_and_nonfinite_results_fail_closed(self):
        results = [dict(model=m, variant=v, bits=150.0, status="finite") for m, v in TASKS]
        self.assertTrue(complete(results))
        for bad in ([], results[:-1], results + results[:1], results[:-1] + results[:1], [{}]):
            self.assertFalse(complete(bad))
        for value in (float("inf"), float("nan"), -1, True, None, "150"):
            bad = [dict(r) for r in results]
            bad[0]["bits"] = value
            self.assertFalse(complete(bad))
        bad = [dict(r) for r in results]
        bad[0]["status"] = "timeout"
        self.assertFalse(complete(bad))
        bad[0]["status"] = "finite"
        bad[0]["model"] = "unrequested"
        self.assertFalse(complete(bad))

    def test_changed_missing_and_extra_python_sources_are_refused_before_import(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            package = root / "lattice-estimator/estimator"
            package.mkdir(parents=True)
            source = package / "__init__.py"
            source.write_text("raise AssertionError('must never import during verification')\n")
            lock = {"files": {str(source.relative_to(root)): hashlib.sha256(source.read_bytes()).hexdigest()}}
            verify_source(root, lock)
            source.write_text("changed")
            with self.assertRaises(ValueError):
                verify_source(root, lock)
            source.unlink()
            with self.assertRaises(ValueError):
                verify_source(root, lock)
            source.write_text("raise AssertionError('must never import during verification')\n")
            (package / "extra.py").write_text("")
            with self.assertRaises(ValueError):
                verify_source(root, lock)
            with self.assertRaises(ValueError):
                verify_source(root, {"files": {}})


if __name__ == "__main__":
    unittest.main()
