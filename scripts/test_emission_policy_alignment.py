#!/usr/bin/env python3
"""Synthetic-emission policy regressions across scanners and the arrow wrapper."""

import importlib.util
import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import check_residue_native_architecture as architecture
import check_recumbent_arrow as arrow
from a2_arrow_suite import audit_trace


def load_contract():
    source = Path(__file__).resolve().parents[1] / ".github/scripts/check_cram_recumbency.py"
    spec = importlib.util.spec_from_file_location("cram_contract_for_test", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


contract = load_contract()


class EmissionPolicyTests(unittest.TestCase):
    def run_contract(self, bootstrap, extra_fhe="", legacy=False):
        files = {
            "crates/nine65/src/ops/bootstrap.rs": bootstrap,
            "crates/nine65/src/ops/rns_fhe.rs": (
                "struct Context { q_product_checked: Option<u128>, q_product_limbs: Vec<u64> }\n"
                + extra_fhe
            ),
            "crates/nine65/src/arithmetic/rns.rs": """
                struct Context {
                    main_product_checked: Option<u128>, main_product_limbs: Vec<u64>,
                    main_product_bit_length: u32, anchor_product_checked: Option<u128>,
                    anchor_product_limbs: Vec<u64>, anchor_product_bit_length: u32,
                    main_inv_anchor_checked: Option<u128>
                }
            """,
            "crates/nine65/src/arithmetic/k_elimination.rs":
                "pub fn try_capacity() -> Option<u128> { Some(1) }",
            "crates/nine65/src/arithmetic/kelim_residue_divider.rs":
                "pub fn project_bounded() {}",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative, contents in files.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents)
            argv = ["check_cram_recumbency.py"]
            if legacy:
                argv.append("--legacy-reconstruction-audit")
            with patch.object(contract, "ROOT", root), patch.object(sys, "argv", argv):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    return contract.main()

    def scan_architecture(self, code, legacy=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "probe.rs"
            path.write_text(code)
            with patch.object(architecture, "ROOT", root):
                if legacy:
                    return architecture.scan_file(path, legacy_reconstruction_audit=True)
                return architecture.scan_file(path)

    def test_named_reconstruction_and_big_integer_types_are_not_default_bans(self):
        code = "fn probe() { crt_reconstruct_u256(x); let n: BigInt = boundary(x); }"
        self.assertEqual(self.scan_architecture(code), [])
        self.assertTrue(self.scan_architecture(code, legacy=True))

    def test_suffixed_emission_calls_are_still_rejected(self):
        for call in ["garner_reconstruct(x)", "GarnerLift::new(x)",
                     "mixed_radix_project(x)", "mixedradix_step(x)"]:
            with self.subTest(call=call):
                self.assertTrue(self.scan_architecture(f"fn probe() {{ {call}; }}"))

    def test_architecture_scans_code_after_strings_without_scanning_the_strings(self):
        self.assertEqual(self.scan_architecture(
            'fn probe() { println!("Garner (Simulated); mixed_radix(x)"); }'
        ), [])
        self.assertTrue(self.scan_architecture(
            'fn probe() { println!("https://example.invalid"); garner_reconstruct(x); }'
        ))
        self.assertTrue(self.scan_architecture(
            'fn probe() { println!("// marker"); mixed_radix_project(x); }'
        ))
        self.assertEqual(self.scan_architecture(
            '// garner_reconstruct(x)\nfn probe() { emit_checked(x); }'
        ), [])

    def test_float_gate_and_test_exclusion_remain_active(self):
        self.assertTrue(self.scan_architecture("fn probe() { let x: f64 = source(); }"))
        self.assertEqual(self.scan_architecture(
            "#[cfg(test)]\nmod tests {\n fn probe() { garner_reconstruct(x); }\n}\n"
        ), [])

    def test_contract_keeps_capacity_checks_when_reconstruction_is_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "probe.rs"
            path.write_text("fn probe() { let q_product = 0; if q_product == 0 {} }")
            with patch.object(contract, "ROOT", root):
                self.assertTrue(contract.require_absent(
                    "probe.rs", [(r"q_product\s*==\s*0", "zero sentinel")]
                ))
                self.assertTrue(contract.require_present(
                    "probe.rs", [(r"q_product_checked\s*:\s*Option<u128>", "checked product")]
                ))
                self.assertTrue(contract.require_present("missing.rs", []))

    def test_contract_default_allows_reconstruction_but_legacy_inventory_records_it(self):
        code = "fn probe() { crt_reconstruct_n(x); crt_reconstruct_u256(x); }"
        self.assertEqual(self.run_contract(code), 0)
        self.assertEqual(self.run_contract(code, legacy=True), 1)

    def test_contract_still_rejects_emissions_and_zero_sentinels(self):
        for call in ["garner_reconstruct(x)", "mixed_radix_project(x)"]:
            with self.subTest(call=call):
                self.assertEqual(self.run_contract(f"fn probe() {{ {call}; }}"), 1)
        self.assertEqual(self.run_contract(
            "fn probe() {}", "fn bad() { if q_product == 0 {} }"
        ), 1)


class ArrowEmissionPolicyTests(unittest.TestCase):
    def source_gate(self, code):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "probe.rs").write_text(code)
            with patch.object(arrow, "ROOT", root), patch.object(arrow, "SOURCE_FILES", ("probe.rs",)):
                policy = arrow.inspect_sources()
        report = audit_trace(dict(
            name="source-policy probe", input_moduli=[2], output_moduli=[2],
            exhaustive_product=True,
            rows=[dict(input=[i], output=[i], expected=[i], restored=[i],
                       order_outputs=[[i]]) for i in range(2)],
            source_policy=policy,
        ))
        return next(gate["verdict"] for gate in report["gates"] if gate["gate"] == "G5")

    def test_arrow_g5_rejects_all_emission_call_spellings(self):
        for call in ("garner(x)", "GarnerLift::new(x)",
                     "mixed_radix(x)", "mixed_radix_project(x)",
                     "mixedradix(x)", "mixedradix_project(x)",
                     "MixedRadixLift::new(x)"):
            with self.subTest(call=call):
                self.assertEqual(self.source_gate(f"fn probe() {{ {call}; }}"), "FAIL")

    def test_arrow_g5_excludes_diagnostic_strings_and_comments(self):
        for code in (
            'fn probe() { println!("garner(x); mixed_radix(x); mixedradix_project(x)"); }',
            'fn probe() { println!("escaped \\"mixedradix(x)\\" diagnostic"); }',
            '// mixedradix_project(x)\nfn probe() { checked_emit(x); }',
            '#[cfg(test)]\nmod tests { fn probe() { mixedradix_project(x); } }',
        ):
            with self.subTest(code=code):
                self.assertEqual(self.source_gate(code), "PASS")

    def test_arrow_g5_keeps_real_calls_after_diagnostic_strings_visible(self):
        for text in ("https://example.invalid", "// marker"):
            for call in ("garner_reconstruct(x)", "mixed_radix_project(x)", "mixedradix_project(x)"):
                with self.subTest(text=text, call=call):
                    self.assertEqual(self.source_gate(
                        f'fn probe() {{ println!("{text}"); {call}; }}'
                    ), "FAIL")


if __name__ == "__main__":
    unittest.main()
