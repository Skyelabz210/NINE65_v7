#!/usr/bin/env python3
import tempfile
import unittest
from pathlib import Path
from check_recumbency import findings


class RecumbencyGateTests(unittest.TestCase):
    def scan(self, code, products_only=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "crates/nine65/src/probe.rs"
            path.parent.mkdir(parents=True)
            path.write_text(code)
            return findings(root, products_only)

    def test_production_injection_is_rejected(self):
        for call in ["ctx.to_int(x)", "ctx.extract_k_rns_level(x)",
                     "crt_reconstruct_u256(x)", "garner_reconstruct(x)",
                     "mixed_radix(x)", "incremental_crt_lift(x)"]:
            with self.subTest(call=call):
                self.assertTrue(self.scan(f"fn probe() {{ {call}; }}"))

    def test_test_oracle_is_excluded_but_following_production_is_not(self):
        oracle = '#[cfg(test)]\nmod tests {\n fn oracle() { ctx.to_int(x); }\n}\n'
        self.assertEqual(self.scan(oracle), [])
        self.assertTrue(self.scan(oracle + 'fn live() { ctx.to_int(x); }'))
        self.assertEqual(self.scan('// to_int(x)\nfn live() { checked(x); }'), [])

    def test_product_gate_checks_calls_and_allows_checked_api(self):
        self.assertTrue(self.scan('fn live() { config.rns_product(); }', True))
        self.assertEqual(self.scan('fn live() { config.try_rns_product(); }', True), [])
        self.assertEqual(self.scan('fn live() { ctx.to_int(x); }', True), [])

    def test_missing_sources_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertTrue(findings(Path(directory)))


if __name__ == '__main__':
    unittest.main()
