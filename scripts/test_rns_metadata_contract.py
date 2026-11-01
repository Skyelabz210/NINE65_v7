#!/usr/bin/env python3
"""Negative controls for the exact RNS metadata source contract."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("metadata_contract", ROOT / ".github/scripts/apply_issue29_rns_metadata_patch.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class MetadataContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = module.TARGET.read_text(encoding="utf-8")

    def test_current_contract(self):
        self.assertEqual(module.metadata_errors(self.source), [])

    def test_legacy_scalar_read_is_rejected(self):
        self.assertTrue(module.metadata_errors(self.source + "\nfn bad(&self) { let _ = self.q_product; }\n"))

    def test_recumbency_gate_rejects_legacy_reads_in_each_consumer(self):
        for path in ("crates/nine65/src/ops/rns_fhe.rs",
                     "crates/nine65/src/ops/gso_fhe.rs",
                     "crates/nine65/src/cram_ct_wrap.rs"):
            with self.subTest(path=path), patch.object(module._gate, "read", return_value="fn f(ctx: &Ctx) { let _ = ctx.q_product; }"):
                failures = module._gate.require_absent(path, [(r"\.\s*q_product\b", "legacy scalar")])
                self.assertTrue(failures)

    def test_missing_or_incorrect_exact_metadata_is_rejected(self):
        for original, replacement in [
            ("pub q_product_checked: Option<u128>", "pub q_product_checked: u128"),
            ("pub q_product_limbs: Vec<u64>", "pub q_product_limbs: Vec<u32>"),
            ("config.rns_product_bit_length()", "config.primes.len()"),
            ("config.try_rns_product()", "Some(0)"),
            ("config.rns_product_limbs()", "vec![0]"),
        ]:
            with self.subTest(original=original):
                self.assertIn(original, self.source)
                self.assertTrue(module.metadata_errors(self.source.replace(original, replacement, 1)))

    def test_comments_and_test_only_code_do_not_trigger_gate(self):
        source = self.source + "\n// self.q_product\n#[cfg(test)]\nfn oracle(ctx: &Ctx) { let _ = ctx.q_product; }\n"
        self.assertEqual(module.metadata_errors(source), [])


if __name__ == "__main__":
    unittest.main()
