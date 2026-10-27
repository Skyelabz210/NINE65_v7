#!/usr/bin/env python3
import tempfile
import unittest
from pathlib import Path
from check_recumbency import findings


class RecumbencyGateTests(unittest.TestCase):
    def scan(self, code, products_only=False, legacy_reconstruction_audit=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "crates/nine65/src/probe.rs"
            path.parent.mkdir(parents=True)
            path.write_text(code)
            if legacy_reconstruction_audit:
                return findings(root, products_only, legacy_reconstruction_audit=True)
            return findings(root, products_only)

    def test_production_injection_is_rejected(self):
        for call in ["garner(x)", "garner_reconstruct(x)",
                     "GarnerLift::new(x)", "mixed_radix(x)",
                     "mixed_radix_step(x)", "mixedradix_project(x)"]:
            with self.subTest(call=call):
                self.assertTrue(self.scan(f"fn probe() {{ {call}; }}"))

    def test_reconstruction_is_not_itself_a_synthetic_emission(self):
        for call in ["ctx.to_int(x)", "ctx.extract_k_rns_level(x)",
                     "crt_reconstruct_u256(x)", "incremental_crt_lift(x)"]:
            with self.subTest(call=call):
                code = f"fn probe() {{ {call}; }}"
                self.assertEqual(self.scan(code), [])
                self.assertTrue(self.scan(code, legacy_reconstruction_audit=True))

    def test_test_oracle_is_excluded_but_following_production_is_not(self):
        oracle = '#[cfg(test)]\nmod tests {\n fn oracle() { garner_reconstruct(x); }\n}\n'
        self.assertEqual(self.scan(oracle), [])
        self.assertTrue(self.scan(oracle + 'fn live() { garner_reconstruct(x); }'))
        self.assertEqual(self.scan('// garner_reconstruct(x)\nfn live() { checked(x); }'), [])

    def test_product_gate_checks_calls_and_allows_checked_api(self):
        self.assertTrue(self.scan('fn live() { config.rns_product(); }', True))
        self.assertEqual(self.scan('fn live() { config.try_rns_product(); }', True), [])
        self.assertEqual(self.scan('fn live() { ctx.to_int(x); }', True), [])

    def test_printed_mechanism_names_are_not_executable_emissions(self):
        for literal in ['"Sequential Garner (Simulated)"',
                        '"garner_reconstruct(x); mixed_radix_project(x)"',
                        r'"quoted \\\"garner(x)\\\" marker"']:
            with self.subTest(literal=literal):
                self.assertEqual(self.scan(f"fn probe() {{ println!({literal}); }}"), [])

    def test_comment_markers_inside_strings_do_not_hide_following_calls(self):
        for call in ["garner_reconstruct(x)", "mixed_radix_project(x)"]:
            with self.subTest(call=call):
                self.assertTrue(self.scan(
                    f'fn probe() {{ println!("https://example.invalid/{call}"); {call}; }}'
                ))
        self.assertEqual(self.scan(
            'fn probe() { println!("https://example.invalid/"); } // garner(x)'
        ), [])

    def test_missing_sources_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertTrue(findings(Path(directory)))


if __name__ == '__main__':
    unittest.main()
