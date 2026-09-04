"""Regression tests for the benches/tests/bin no-floats gate (issue #90).

Item 6 of issue #90 requires proving that tokens in comments/strings do not
create false classifications while real float types/casts do fail. That is
the point of this file: every "does not flag" test below mirrors a real
shape already present in this repository.
"""

from __future__ import annotations

import pathlib
import tempfile
import unittest

from scripts import check_no_floats_benches_and_tests as gate


class CodeOnlyStripperTests(unittest.TestCase):
    def test_strips_line_comments(self) -> None:
        stripped = gate.code_only("// zero f32/f64 anywhere\nlet x = 1;\n")
        self.assertNotIn("f64", stripped)
        self.assertNotIn("f32", stripped)

    def test_strips_block_comments_preserving_line_count(self) -> None:
        src = "/* f64\n   f32 */\nlet x = 1;\n"
        stripped = gate.code_only(src)
        self.assertNotIn("f64", stripped)
        self.assertNotIn("f32", stripped)
        self.assertEqual(stripped.count("\n"), src.count("\n"))

    def test_strips_string_literal_contents(self) -> None:
        # crates/nine65/src/bin/nine65_v7_demo.rs, real line.
        src = 'println!("Integer-only: YES (zero f32/f64)");'
        self.assertNotIn("f64", gate.code_only(src))
        self.assertNotIn("f32", gate.code_only(src))

    def test_strips_decimal_looking_text_inside_strings(self) -> None:
        src = 'println!("Noise Level: 2.0 (High Variance)");'
        self.assertIsNone(gate.DECIMAL_LITERAL.search(gate.code_only(src)))

    def test_leaves_real_code_around_a_stripped_string_intact(self) -> None:
        src = 'let s = "f64"; let y: f32 = 1.0;'
        stripped = gate.code_only(src)
        self.assertIsNotNone(gate.FLOAT_TOKEN.search(stripped))
        self.assertIsNotNone(gate.DECIMAL_LITERAL.search(stripped))


class FloatTokenPatternTests(unittest.TestCase):
    def test_flags_explicit_type_annotation(self) -> None:
        self.assertIsNotNone(gate.FLOAT_TOKEN.search("let x: f64 = 1.0;"))

    def test_flags_as_cast(self) -> None:
        self.assertIsNotNone(gate.FLOAT_TOKEN.search("total as f64"))

    def test_flags_associated_path(self) -> None:
        self.assertIsNotNone(gate.FLOAT_TOKEN.search("f32::consts::PI"))

    def test_does_not_flag_f64_as_identifier_prefix(self) -> None:
        # f64_helper is one identifier, not the type f64 — no word boundary
        # between "64" and "_".
        self.assertIsNone(gate.FLOAT_TOKEN.search("let f64_helper = 1;"))


class DecimalLiteralPatternTests(unittest.TestCase):
    def test_flags_a_bare_float_literal(self) -> None:
        # crates/nine65/src/bin/resilience_audit.rs, real line (pre-fix):
        # inferred f64 with no f32/f64 token anywhere on the line.
        self.assertIsNotNone(gate.DECIMAL_LITERAL.search("let latency_ms = 9.2;"))

    def test_does_not_flag_a_range(self) -> None:
        self.assertIsNone(gate.DECIMAL_LITERAL.search("for i in 0..10 {}"))

    def test_does_not_flag_tuple_of_tuple_field_access(self) -> None:
        self.assertIsNone(gate.DECIMAL_LITERAL.search("self.0.1"))

    def test_does_not_flag_underscore_grouped_integers(self) -> None:
        self.assertIsNone(gate.DECIMAL_LITERAL.search("let n = 1_000_000;"))


class ScanFileTests(unittest.TestCase):
    def write(self, directory: pathlib.Path, contents: str) -> pathlib.Path:
        path = directory / "fixture.rs"
        path.write_text(contents, encoding="utf-8")
        return path

    def test_clean_file_has_no_failures(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = self.write(
                pathlib.Path(d),
                "// zero f32/f64 anywhere\n"
                'fn f() { let x: u64 = 1; println!("no floats here"); }\n',
            )
            self.assertEqual(gate.scan_file(path), [])

    def test_real_float_type_is_reported_with_line_number(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = self.write(pathlib.Path(d), "fn f() {\n    let x: f64 = 1.0;\n}\n")
            failures = gate.scan_file(path)
            # Both the `f64` token and the bare `1.0` literal are real
            # violations on the same line.
            self.assertEqual(len(failures), 2)
            for failure in failures:
                self.assertIn(":2:", failure)

    def test_scanner_self_test_arrays_do_not_false_positive(self) -> None:
        # Mirrors the real pattern in
        # crates/exact_transcendentals/tests/cram_gates.rs and
        # crates/nine65/tests/audit_regressions.rs: a list of forbidden-token
        # STRINGS belonging to another gate's own self-test. This must stay
        # silent — this is exactly the false-classification issue #90 item 6
        # calls out.
        with tempfile.TemporaryDirectory() as d:
            path = self.write(
                pathlib.Path(d),
                'for forbidden in ["f32", "f64", "SIMULATED REFRESH"] {\n'
                "    assert!(!source.contains(forbidden));\n"
                "}\n",
            )
            self.assertEqual(gate.scan_file(path), [])

    def test_ratio_helper_call_sites_are_clean(self) -> None:
        # The shape every fix in this PR converged on: integer nanoseconds
        # in, a pre-formatted string out, no float anywhere.
        with tempfile.TemporaryDirectory() as d:
            path = self.write(
                pathlib.Path(d),
                "fn f(elapsed_ns: u128, ops: u128) -> String {\n"
                "    format_ratio(elapsed_ns, ops * 1_000_000, 2)\n"
                "}\n",
            )
            self.assertEqual(gate.scan_file(path), [])


class TestGatedLinesTests(unittest.TestCase):
    def test_captures_cfg_test_mod_block(self) -> None:
        src = (
            "fn production() {}\n"
            "\n"
            "#[cfg(test)]\n"
            "mod tests {\n"
            "    #[test]\n"
            "    fn f() {\n"
            "        let x: f64 = 1.0;\n"
            "    }\n"
            "}\n"
        )
        gated = dict(gate.test_gated_lines(src))
        # Line 1 (production) must NOT be captured.
        self.assertNotIn(1, gated)
        # The #[cfg(test)] line itself and everything through the closing
        # brace of `mod tests { ... }` must be captured.
        self.assertIn(3, gated)
        self.assertIn(7, gated)  # the f64 line
        self.assertIn(9, gated)  # closing brace

    def test_captures_cfg_all_test_feature_gate(self) -> None:
        # The exact shape ops/rns_fhe.rs's gate_harness uses.
        src = (
            '#[cfg(all(test, feature = "allow_insecure", feature = "benchmarks"))]\n'
            "mod gate {\n"
            "    #[test]\n"
            "    fn gate_harness() {\n"
            "        let ns = elapsed as f64 / count as f64;\n"
            "    }\n"
            "}\n"
        )
        gated = dict(gate.test_gated_lines(src))
        self.assertIn(5, gated)
        self.assertIn("f64", gated[5])

    def test_production_code_outside_any_gate_is_never_captured(self) -> None:
        src = "fn production() {\n    let x: f64 = 1.0;\n}\n"
        self.assertEqual(gate.test_gated_lines(src), [])


class ScanTestGatedRegionsTests(unittest.TestCase):
    def write(self, directory: pathlib.Path, contents: str) -> pathlib.Path:
        path = directory / "fixture.rs"
        path.write_text(contents, encoding="utf-8")
        return path

    def test_flags_a_float_inside_the_gated_region_only(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = self.write(
                pathlib.Path(d),
                "fn production() -> f64 { 1.0 }\n"  # would-be violation, NOT scanned here
                "\n"
                "#[cfg(test)]\n"
                "mod tests {\n"
                "    #[test]\n"
                "    #[ignore]\n"
                "    fn bench() {\n"
                "        let ns = 100u128 as f64 / 3.0;\n"
                "        println!(\"{ns:.1}\");\n"
                "    }\n"
                "}\n",
            )
            failures = gate.scan_test_gated_regions(path)
            self.assertTrue(any(":8:" in f for f in failures))
            # Line 1's production `f64` return type must NOT appear — this
            # function only scans the #[cfg(test)] region.
            self.assertFalse(any(":1:" in f for f in failures))

    def test_named_files_are_clean_after_this_prs_fix(self) -> None:
        # The load-bearing regression check for this PR: the three files it
        # converted must have zero remaining violations in their gated
        # regions.
        for rel in gate.NAMED_TEST_GATED_FILES:
            path = gate.ROOT / rel
            if not path.is_file():
                self.skipTest(f"{rel} not present in this checkout")
            self.assertEqual(
                gate.scan_test_gated_regions(path),
                [],
                f"{rel} still has a float in its #[cfg(test)] region",
            )


class IterTargetFilesTests(unittest.TestCase):
    def test_covers_the_files_this_pr_fixed(self) -> None:
        # A representative sample of files this PR's commit converted off
        # floats — if the directory list in TARGET_SUBDIRS ever regresses,
        # this fails instead of the gate silently going quiet on them.
        expected = {
            gate.ROOT / "crates/nine65/benches/depth_chain.rs",
            gate.ROOT / "crates/nine65/tests/op_timings.rs",
            gate.ROOT / "crates/nine65/src/bin/dpa_simulation.rs",
        }
        found = set(gate.iter_target_files())
        missing = expected - found
        self.assertEqual(missing, set(), f"gate stopped covering: {missing}")


if __name__ == "__main__":
    unittest.main()
