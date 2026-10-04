#!/usr/bin/env python3
"""Regression tests for F01's source-derived parameter and depth evidence."""

from __future__ import annotations

import copy
import json
import pathlib
import sys
import unittest
from math import prod

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
REGISTRY_PATH = ROOT / "artifacts" / "execution" / "parameter_registry.json"
sys.path.insert(0, str(SCRIPTS))

import generate_depth_correctness_matrix as depth  # noqa: E402
import verify_wr1_transient_exact as wr1  # noqa: E402

EXPECTED_CURRENT_TUPLES = {
    "secure_128": (
        8192,
        (998244353, 985661441, 754974721, 469762049),
        65537,
        3,
    ),
    "secure_128_deep": (
        8192,
        (998244353, 985661441, 754974721, 469762049),
        65537,
        3,
    ),
    "secure_192": (
        16384,
        (998244353, 985661441, 754974721, 469762049, 167772161),
        65537,
        4,
    ),
    "secure_256": (
        16384,
        (
            998244353,
            985661441,
            754974721,
            469762049,
            167772161,
            595591169,
        ),
        65537,
        5,
    ),
}


def fingerprint(entry: dict) -> int:
    value = 0xCBF29CE484222325
    fnv_prime = 0x100000001B3

    def fold(scalar: int) -> None:
        nonlocal value
        for byte in scalar.to_bytes(8, "little"):
            value ^= byte
            value = (value * fnv_prime) & 0xFFFFFFFFFFFFFFFF

    fold(entry["ring_degree"])
    fold(len(entry["main_primes"]))
    for lane in entry["main_primes"]:
        fold(lane)
    fold(entry["plaintext_modulus"])
    fold(entry["eta"])
    return value


class ParameterRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        cls.entries = {
            entry["name"]: entry for entry in cls.document["configurations"]
        }

    def test_registry_pins_current_source_tuples(self) -> None:
        wr1.validate_registry_document(self.document)
        self.assertEqual(set(self.entries), set(EXPECTED_CURRENT_TUPLES))
        for name, expected in EXPECTED_CURRENT_TUPLES.items():
            n, primes, plaintext_modulus, eta = expected
            entry = self.entries[name]
            self.assertEqual(entry["ring_degree"], n)
            self.assertEqual(tuple(entry["main_primes"]), primes)
            self.assertEqual(entry["plaintext_modulus"], plaintext_modulus)
            self.assertEqual(entry["eta"], eta)
            self.assertEqual(entry["status"], "current")

    def test_registry_uses_exact_product_width_and_fingerprint(self) -> None:
        differing_widths = 0
        for name, entry in self.entries.items():
            modulus = prod(entry["main_primes"])
            self.assertEqual(int(entry["main_modulus_hex"], 16), modulus)
            self.assertEqual(entry["main_modulus_product_bits"], modulus.bit_length())
            differing_widths += entry["main_modulus_product_bits"] != sum(
                prime.bit_length() for prime in entry["main_primes"]
            )
            expected_fingerprint = fingerprint(entry)
            self.assertEqual(
                entry["context_fingerprint"]["value_hex"],
                f"0x{expected_fingerprint:016x}",
            )
        self.assertGreater(differing_widths, 0)

    def test_alias_relations_match_tuple_equality(self) -> None:
        secure_128 = self.entries["secure_128"]
        secure_128_deep = self.entries["secure_128_deep"]
        self.assertEqual(
            secure_128["context_fingerprint"],
            secure_128_deep["context_fingerprint"],
        )
        self.assertEqual(
            secure_128["alias_relation"],
            {
                "kind": "identical_current_tuple",
                "canonical_name": "secure_128",
                "aliases": ["secure_128_deep"],
            },
        )
        self.assertEqual(
            secure_128_deep["alias_relation"],
            {
                "kind": "identical_current_tuple",
                "canonical_name": "secure_128",
                "aliases": ["secure_128"],
            },
        )
        distinct = {
            name: entry["context_fingerprint"]["value_hex"]
            for name, entry in self.entries.items()
            if name not in {"secure_128", "secure_128_deep"}
        }
        self.assertEqual(len(set(distinct.values())), len(distinct))

    def test_routes_and_modulus_roles_remain_separate(self) -> None:
        roles = self.document["modulus_roles"]
        self.assertEqual(len(roles["priming_roots"]), 1)
        root = roles["priming_roots"][0]
        self.assertEqual(root["name"], "S8")
        self.assertIsNone(root["value"])
        self.assertEqual(root["ordered_factors"], [2, 3, 5, 7, 11, 13, 17, 19])
        self.assertIn("rlwe_ciphertext_modulus", root["must_not_substitute_for"])
        self.assertIn("rlwe_parameter", root["must_not_substitute_for"])

        payloads = {
            role["owner_config"]: role for role in roles["plaintext_payload_moduli"]
        }
        ciphertexts = {
            role["owner_config"]: role for role in roles["rlwe_ciphertext_moduli"]
        }
        dependent = {
            role["owner_config"]: role for role in roles["dependent_view_moduli"]
        }
        self.assertEqual(set(payloads), set(self.entries))
        self.assertEqual(set(ciphertexts), set(self.entries))
        self.assertEqual(set(dependent), set(self.entries))
        for name, entry in self.entries.items():
            self.assertEqual(payloads[name]["value"], entry["plaintext_modulus"])
            self.assertEqual(ciphertexts[name]["product_bits"], entry["main_modulus_product_bits"])
            self.assertFalse(ciphertexts[name]["is_plaintext_payload_modulus"])
            self.assertFalse(dependent[name]["is_rlwe_parameter"])
            self.assertFalse(dependent[name]["is_published_rlwe_ciphertext_modulus"])
            self.assertEqual(
                dependent[name]["operand_bound_over_q_squared"],
                entry["ring_degree"] // 2,
            )
            self.assertTrue(dependent[name]["auxiliary_moduli"])
            self.assertEqual(
                dependent[name]["auxiliary_product_bits"],
                prod(dependent[name]["auxiliary_moduli"]).bit_length(),
            )
            self.assertEqual(
                entry["route"]["exact_evaluator_route"],
                "DerivedTransientExact",
            )
            self.assertNotEqual(
                entry["route"]["automatic_rns_route"],
                entry["route"]["exact_evaluator_route"],
            )

    def test_historical_three_prime_fixture_is_rejected_as_current(self) -> None:
        self.assertTrue(hasattr(wr1, "HISTORICAL_MAIN_3"))
        self.assertFalse(hasattr(wr1, "MAIN_3"))
        self.assertNotEqual(
            self.entries["secure_128"]["main_primes"],
            list(wr1.HISTORICAL_MAIN_3),
        )

        injected = copy.deepcopy(self.document)
        historical = next(entry for entry in injected["configurations"] if entry["name"] == "secure_128")
        historical["main_primes"] = list(wr1.HISTORICAL_MAIN_3)
        historical["main_modulus_hex"] = hex(prod(wr1.HISTORICAL_MAIN_3))
        historical["main_modulus_product_bits"] = prod(
            wr1.HISTORICAL_MAIN_3
        ).bit_length()
        with self.assertRaisesRegex(AssertionError, "historical three-prime"):
            wr1.validate_registry_document(injected)

    def test_corrupted_dependent_view_is_rejected(self) -> None:
        injected = copy.deepcopy(self.document)
        injected["modulus_roles"]["dependent_view_moduli"][0][
            "auxiliary_product_bits"
        ] += 1
        with self.assertRaisesRegex(AssertionError, "dependent view exact product width"):
            wr1.validate_registry_document(injected)

    def test_wr1_d1_uses_n_over_2_bound(self) -> None:
        main = wr1.HISTORICAL_MAIN_3
        aux = wr1.AUX_10[:2]
        ring_n = 8
        modulus = prod(main)
        half = modulus // 2
        a0 = tuple([half] * ring_n)
        a1 = tuple([half] * ring_n)
        b0 = tuple([half] * ring_n)
        b1 = tuple([half] * ring_n)
        true_d1 = tuple(
            x + y
            for x, y in zip(
                wr1.negacyclic(a0, b1),
                wr1.negacyclic(a1, b0),
            )
        )
        max_d1 = max(abs(value) for value in true_d1)
        self.assertGreater(max_d1, (ring_n // 4) * modulus * modulus)
        self.assertLessEqual(max_d1, (ring_n // 2) * modulus * modulus)
        self.assertEqual(wr1.operand_bound_over_q_squared(ring_n), ring_n // 2)

        main_components, aux_components = wr1.transient_tensor_components(
            wr1.residue_limbs(a0, main),
            wr1.residue_limbs(a1, main),
            wr1.residue_limbs(b0, main),
            wr1.residue_limbs(b1, main),
            main,
            aux,
        )
        expected = wr1.residue_limbs(true_d1, main)
        self.assertEqual(main_components[1], expected)
        self.assertEqual(aux_components[1], wr1.residue_limbs(true_d1, aux))


class DepthEvidenceTests(unittest.TestCase):
    VALID_OUTPUT = """\
STEP step=1 got=49 expected=49 plaintext_equal=true
STEP step=2 got=343 expected=343 plaintext_equal=true
STEP step=3 got=2401 expected=2401 plaintext_equal=true
MAX DEPTH: 3
Total collapses: 99
Total time: 12 ms
Avg time/mul: 1 ms
"""

    def test_depth_parser_records_plaintext_equality(self) -> None:
        parsed = depth.parse_benchmark_output(self.VALID_OUTPUT, "secure_128")
        self.assertTrue(parsed["correctness_verified"])
        self.assertEqual(parsed["max_depth_achieved"], 3)
        self.assertEqual(parsed["plaintext_check_count"], 3)
        self.assertEqual(
            [check["step"] for check in parsed["plaintext_checks"]],
            [1, 2, 3],
        )
        self.assertEqual(parsed["total_collapses"], 99)

    def test_depth_parser_fails_on_wrong_plaintext_with_unchanged_counters(self) -> None:
        injected = self.VALID_OUTPUT.replace(
            "STEP step=2 got=343 expected=343 plaintext_equal=true",
            "STEP step=2 got=343 expected=999 plaintext_equal=false",
        ).replace("Total collapses: 99", "Total collapses: 0")
        with self.assertRaisesRegex(depth.EvidenceError, "plaintext equality failed"):
            depth.parse_benchmark_output(injected, "secure_128")

    def test_depth_parser_fails_closed_on_missing_truncated_or_zero_output(self) -> None:
        cases = {
            "missing step": self.VALID_OUTPUT.replace(
                "STEP step=2 got=343 expected=343 plaintext_equal=true\n", ""
            ),
            "missing terminal marker": "\n".join(
                line
                for line in self.VALID_OUTPUT.splitlines()
                if not line.startswith("MAX DEPTH:")
            ),
            "zero executed cases": "MAX DEPTH: 0\nTotal collapses: 0\n",
            "no explicit checks": "MAX DEPTH: 1\nTotal collapses: 0\n",
            "asserted equality without values": (
                "STEP step=1 plaintext_equal=true\nMAX DEPTH: 1\n"
            ),
        }
        for label, output in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(depth.EvidenceError):
                    depth.parse_benchmark_output(output, "secure_128")


if __name__ == "__main__":
    unittest.main()
