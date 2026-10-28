import shutil
import unittest
from unittest.mock import patch

from audit_modulus_classes import (
    RNS, SUPPORTED_N, anchors_for_n, parse_anchors, verify_runtime_catalogue,
)


SOURCE = """
impl Context {
    pub fn canonical_anchor_primes_for_n(n: usize) -> Vec<u64> {
        let mut primes = vec![17, 97, 113]; // comment 31 is not a lane
        if n == 32 {
            primes.truncate(2);
            primes.extend_from_slice(&[193, 257]);
        } else if n >= 16 {
            primes.extend_from_slice(&[241]);
        }
        primes
    }
}
"""


class AnchorCatalogueTests(unittest.TestCase):
    def test_mutually_exclusive_replacement_is_not_a_union(self):
        catalogue = parse_anchors(SOURCE)
        self.assertEqual(anchors_for_n(catalogue, 8), [17, 97, 113])
        self.assertEqual(anchors_for_n(catalogue, 16), [17, 97, 113, 241])
        self.assertEqual(anchors_for_n(catalogue, 32), [17, 97, 193, 257])
        self.assertEqual(anchors_for_n(catalogue, 64), [17, 97, 113, 241])

    def test_unknown_or_unconsumed_rust_is_refused(self):
        for old, new in [
            ("primes.truncate(2);", "primes.reverse();"),
            ("if n == 32", "if n % 32 == 0"),
            ("primes\n", "primes.sort();\n        primes\n"),
            ("[193, 257]", "[193 + 257]"),
        ]:
            with self.subTest(new=new), self.assertRaises(AssertionError):
                parse_anchors(SOURCE.replace(old, new))

    def test_real_catalogue_preserves_dimension_specific_sets(self):
        catalogue = parse_anchors(RNS.read_text())
        small = anchors_for_n(catalogue, 8192)
        native = anchors_for_n(catalogue, 16384)
        doubled = anchors_for_n(catalogue, 32768)
        self.assertEqual((len(small), len(native), len(doubled)), (7, 10, 10))
        self.assertEqual(native[:7], small)
        self.assertEqual(doubled[:6], small[:6])
        self.assertNotIn(small[6], doubled)
        self.assertTrue(all((p - 1) % 65536 == 0 for p in doubled))

    def test_commented_function_and_literal_digits_do_not_change_the_catalogue(self):
        fake = "/* pub fn canonical_anchor_primes_for_n(n: usize) -> Vec<u64> { 13 } */\n"
        self.assertEqual(parse_anchors(fake + SOURCE), parse_anchors(SOURCE))

    @unittest.skipUnless(shutil.which("rustc"), "runtime cross-check requires rustc")
    def test_parser_agrees_with_compiled_rust_function(self):
        source = RNS.read_text()
        catalogue = parse_anchors(source)
        self.assertEqual(
            verify_runtime_catalogue(source, catalogue, SUPPORTED_N),
            {str(n): anchors_for_n(catalogue, n) for n in SUPPORTED_N},
        )

    @unittest.skipUnless(shutil.which("rustc"), "runtime cross-check requires rustc")
    def test_runtime_cross_check_rejects_a_wrong_catalogue(self):
        catalogue = parse_anchors(SOURCE)
        catalogue["base"][0] = 19
        with self.assertRaises(AssertionError):
            verify_runtime_catalogue(SOURCE, catalogue, [8, 16, 32])

    def test_audit_cross_check_fails_closed_without_rustc(self):
        with patch("audit_modulus_classes.shutil.which", return_value=None):
            with self.assertRaisesRegex(AssertionError, "rustc is required"):
                verify_runtime_catalogue(SOURCE, parse_anchors(SOURCE), [8])

    @unittest.skipUnless(shutil.which("rustc"), "runtime cross-check requires rustc")
    def test_empty_or_duplicate_runtime_basis_is_rejected(self):
        for replacement in ("[]", "[193, 193]"):
            source = SOURCE.replace("primes.truncate(2);", "primes.truncate(0);")
            source = source.replace("[193, 257]", replacement)
            with self.subTest(replacement=replacement), self.assertRaisesRegex(
                AssertionError, "nonempty and contain distinct"
            ):
                verify_runtime_catalogue(source, parse_anchors(source), [32])


if __name__ == "__main__":
    unittest.main()
