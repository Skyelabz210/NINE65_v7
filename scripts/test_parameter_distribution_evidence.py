#!/usr/bin/env python3
"""Bounded exact-law checks and source/artifact drift rejection controls."""

import collections
import copy
import itertools
import json
import pathlib
import sys
import subprocess
import tempfile
import unittest
from fractions import Fraction

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import export_parameter_distribution_evidence as evidence


class ParameterDistributionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = {p: (evidence.ROOT / p).read_text() for p in evidence.FILES}
        saved = json.loads((evidence.ROOT / evidence.OUTPUT).read_text())
        cls.document = evidence.build_evidence(evidence.ROOT, cls.sources, source_ref=saved["source_sha"])

    def test_current_source_and_saved_artifact_agree(self):
        saved = json.loads((evidence.ROOT / evidence.OUTPUT).read_text())
        self.assertEqual(saved, self.document)
        self.assertFalse(saved["claims"]["production_admitted"])
        self.assertFalse(saved["claims"]["encrypted_execution"])
        evidence.validate_source_ref(evidence.ROOT, saved)

    def test_cbd_pmf_matches_exhaustive_two_eta_bit_producer(self):
        for eta in (3, 4, 5):
            # Exhaust all fair bit inputs to the actual sum(a_i-b_i) shape.
            observed = collections.Counter(
                sum(bits[0::2]) - sum(bits[1::2])
                for bits in itertools.product((0, 1), repeat=2 * eta)
            )
            law = self.document["distributions"][f"cbd_{eta}"]
            self.assertEqual([observed[k] for k in range(-eta, eta + 1)],
                             list(map(int, law["pmf_numerators"])))
            denominator = int(law["pmf_denominator"])
            self.assertEqual(sum(observed.values()), denominator)
            self.assertEqual(sum(k*v for k, v in observed.items()), 0)
            self.assertEqual(Fraction(sum(k*k*v for k, v in observed.items()), denominator),
                             Fraction(eta, 2))

    def test_modulo_three_exact_counts_and_distance(self):
        for bits in range(2, 13):
            observed = collections.Counter(value % 3 for value in range(1 << bits))
            self.assertEqual([observed[k] for k in range(3)],
                             [(1 << bits) // 3 + (k < (1 << bits) % 3) for k in range(3)])
        law = self.document["distributions"]["word_mod3_ternary"]
        denominator = int(law["pmf_denominator"])
        probabilities = [Fraction(int(v), denominator) for v in law["pmf_numerators"]]
        self.assertEqual(sum(probabilities), 1)
        tv = sum(abs(p - Fraction(1, 3)) for p in probabilities) / 2
        self.assertEqual(tv, Fraction(2, 3 * (1 << 64)))
        self.assertEqual(law["total_variation_from_uniform_per_coefficient"], evidence.rational(tv))
        legacy = self.document["distributions"]["word_mod3_minus_one_heavy_ternary"]
        self.assertEqual(legacy["pmf_numerators"][0], law["pmf_numerators"][1])

    def test_rejection_mask_uniformity_bounded_exact_controls(self):
        # SecureRng's threshold uses MAX, so even divisors may reject an
        # extra full block. Accepted residues still have identical counts.
        for bits in range(2, 10):
            maximum = (1 << bits) - 1
            for bound in range(2, maximum + 1):
                threshold = maximum - maximum % bound
                observed = collections.Counter(v % bound for v in range(threshold))
                self.assertEqual(len(observed), bound)
                self.assertEqual(set(observed.values()), {threshold // bound})

    def test_balanced_support_has_joint_constraint(self):
        # Once repeats are rejected the accepted order is a uniform sample
        # without replacement. Every sign support has (H/2)!^2 preimages.
        observed = collections.Counter()
        n, weight = 6, 4
        for order in itertools.permutations(range(n), weight):
            observed[tuple(sorted(order[:2])), tuple(sorted(order[2:]))] += 1
        self.assertEqual(len(observed), 90)
        self.assertEqual(set(observed.values()), {4})
        source = next(d for d in self.document["public_refresh_domains"] if d["domain"] == "Source")
        self.assertEqual((source["positive_count"], source["negative_count"], source["zero_count"]),
                         (48, 48, 8096))
        self.assertTrue(source["coefficient_marginals_do_not_imply_independence"])

    def test_native_return_and_legacy_geometry_are_distinct(self):
        domains = {d["domain"]: d for d in self.document["public_refresh_domains"]}
        self.assertEqual([domains[d]["exact_q_bits"] for d in ("Work", "Source", "Outer", "ReturnDestination")],
                         [119, 60, 650, 119])
        returned = domains["ReturnDestination"]
        self.assertEqual((returned["n"], returned["effective_secret_degree"], returned["embedding_stride"]),
                         (32768, 8192, 4))
        self.assertFalse(returned["fresh_independent_secret"])
        legacy = self.document["legacy_clockwork_bootstrap_profiles"]
        self.assertEqual([d["exact_q_bits"] for d in legacy], [146, 146, 177, 206])
        self.assertTrue(all(not d["legacy_refresh_gate_enabled"] for d in legacy))

    def test_tuple_drift_is_rejected_against_existing_registry(self):
        sources = dict(self.sources)
        path = evidence.RUST + "params/secure_configs.rs"
        body = evidence.function(sources[path], "secure_128")
        sources[path] = sources[path].replace(body, body.replace("8192", "4096", 1), 1)
        with self.assertRaisesRegex(evidence.EvidenceError, "source/registry tuple mismatch"):
            evidence.build_evidence(evidence.ROOT, sources)

    def test_distribution_producer_drift_controls(self):
        mutations = [
            ("ops/rns_fhe.rs", "let r = rng.next_u64() % 3;", "let r = rng.next_u64() % 4;"),
            ("ops/rns_fhe.rs", "rng.uniform_vector(self.n, prime)", "rng.uniform_vector(self.n, 17)"),
            ("entropy/secure.rs", "if r < 3", "if r < 2"),
            ("ops/public_refresh_circuit.rs", "rng.ternary_vector(high.n)", "rng.cbd_vector(high.n, 3)"),
            ("ops/public_refresh_source_kernels.rs", "if trits[index] == 0", "if true"),
            ("ops/public_refresh_return.rs", "reduced_config.n = boot.n", "reduced_config.n = work.n"),
            ("ops/bootstrap.rs", "let min_for_modswitch = work_config.primes.len() + 1;",
             "let min_for_modswitch = work_config.primes.len() + 2;"),
            ("ops/bootstrap.rs", "0 => -1i8", "0 => 0i8"),
        ]
        for path, old, new in mutations:
            with self.subTest(path=path, old=old):
                sources = dict(self.sources)
                full = evidence.RUST + path
                self.assertIn(old, sources[full])
                sources[full] = sources[full].replace(old, new, 1)
                with self.assertRaises(evidence.EvidenceError):
                    evidence.build_evidence(evidence.ROOT, sources)

    def test_artifact_mutations_are_detectable(self):
        saved = copy.deepcopy(self.document)
        saved["public_refresh_domains"][2]["secret_distribution"] = "word_mod3_ternary"
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "mutated.json"
            path.write_text(json.dumps(saved, indent=2, sort_keys=True) + "\n")
            result = subprocess.run([sys.executable, str(evidence.ROOT / "scripts" /
                                    "export_parameter_distribution_evidence.py"),
                                    "--check", "--output", str(path)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("artifact differs from inspected sources", result.stderr)

    def test_recorded_commit_cannot_bypass_source_hash_validation(self):
        saved = copy.deepcopy(self.document)
        saved["source_files_sha256"][evidence.RUST + "ops/rns_fhe.rs"] = "0" * 64
        with self.assertRaisesRegex(evidence.EvidenceError, "recorded hashes do not match"):
            evidence.validate_source_ref(evidence.ROOT, saved)


if __name__ == "__main__":
    unittest.main(verbosity=2)
