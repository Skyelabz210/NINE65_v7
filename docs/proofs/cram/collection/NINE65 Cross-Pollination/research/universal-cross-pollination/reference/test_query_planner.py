"""Independent finite oracles for the public-parameter research planner."""

from dataclasses import replace
from itertools import combinations
from math import gcd, lcm
import unittest

from query_planner import (Candidate, LinearQuery, QuotientQuery,
                           choose_available, minimal_extra_anchor,
                           observation_period, plan_queries)


def evaluate(q, x):
    if isinstance(q, LinearQuery):
        return (q.coefficient * x + q.offset) % q.modulus
    return (x // q.divisor) % q.modulus


class PlannerTests(unittest.TestCase):
    def test_linear_periods_against_signed_oracle(self):
        for b in range(1, 19):
            for a in range(-9, 10):
                q = LinearQuery(a, b, -7)
                for p in range(1, 25):
                    actual = all(evaluate(q, x) == evaluate(q, x + p)
                                 for x in range(-2 * b, 2 * b + 1))
                    self.assertEqual(actual, p % q.period == 0, (q, p))

    def test_quotient_periods_against_signed_oracle(self):
        for d in range(1, 10):
            for b in range(1, 10):
                q = QuotientQuery(d, b)
                for p in range(1, 35):
                    actual = all(evaluate(q, x) == evaluate(q, x + p)
                                 for x in range(-2 * d * b, 2 * d * b + 1))
                    self.assertEqual(actual, p % q.period == 0, (q, p))

    def test_minimal_anchor_exhaustive_divisibility(self):
        # Independently enumerate anchors, not the gcd-saturation algorithm.
        for p in range(1, 81):
            for d in range(1, 81):
                got = minimal_extra_anchor(p, d)
                self.assertEqual(lcm(p, got) % d, 0)
                for a in range(1, 161):
                    if lcm(p, a) % d == 0:
                        self.assertEqual(a % got, 0, (p, d, a, got))

    def test_large_prime_powers_and_overlap(self):
        p = 2**150 * 3**20 * 5**50
        d = 2**151 * 3**10 * 7**3
        self.assertEqual(minimal_extra_anchor(p, d), 2**151 * 7**3)
        self.assertEqual(minimal_extra_anchor(12, 18), 9)
        self.assertNotEqual(lcm(12, 18 // gcd(12, 18)) % 18, 0)
        self.assertEqual(observation_period([4, 6, 6]), 12)

    def test_affine_pullback(self):
        for a in range(-3, 4):
            for s in range(-3, 4):
                for b in range(1, 13):
                    q = LinearQuery(a, b, -2)
                    pulled = q.before_affine(s, 5)
                    self.assertEqual(q.period % pulled.period, 0)
                    for x in range(-20, 21):
                        self.assertEqual(evaluate(pulled, x),
                                         evaluate(q, s * x + 5))

    def test_plan_certificate_and_tampering(self):
        p = plan_queries([4, 6], [LinearQuery(1, 18), QuotientQuery(2, 5)])
        self.assertTrue(p.verifies())
        self.assertEqual(p.demand, 90)
        self.assertEqual(p.extra_anchor, 45)
        for field in ("source_period", "demand", "extra_anchor", "combined_period"):
            self.assertFalse(replace(p, **{field: getattr(p, field) + 1}).verifies())

    def test_available_selection_matches_subset_oracle(self):
        candidates = (Candidate("a", 4, 3), Candidate("b", 9, 2),
                      Candidate("c", 6, 1), Candidate("d", 25, 5),
                      Candidate("e", 18, 4), Candidate("f", 7, 2))
        for p in range(1, 21):
            for d in range(1, 61):
                options = []
                for n in range(len(candidates) + 1):
                    for subset in combinations(candidates, n):
                        period = lcm(p, *(c.modulus for c in subset))
                        if period % d == 0:
                            names = tuple(sorted(c.name for c in subset))
                            options.append((sum(c.cost for c in subset), n, names))
                got = choose_available([p], [LinearQuery(1, d)], candidates)
                if not options:
                    self.assertIsNone(got)
                else:
                    expected = min(options)
                    self.assertEqual((got.cost, len(got.selected), got.selected), expected)
                    self.assertEqual(got.combined_period % d, 0)

    def test_no_queries_and_impossible_candidates(self):
        p = plan_queries([], [])
        self.assertEqual((p.source_period, p.demand, p.extra_anchor), (1, 1, 1))
        self.assertTrue(p.verifies())
        self.assertIsNone(choose_available([12], [LinearQuery(1, 18)],
                                         [Candidate("overlap", 3, 1)]))
        self.assertEqual(choose_available([12], [], []).selected, ())

    def test_invalid_inputs(self):
        for bad in (0, -1, True, 2.5):
            with self.assertRaises(ValueError):
                plan_queries([bad], [])
            with self.assertRaises(ValueError):
                LinearQuery(1, bad)
            with self.assertRaises(ValueError):
                QuotientQuery(bad, 3)
            with self.assertRaises(ValueError):
                Candidate("bad", 2, bad)
        with self.assertRaises(ValueError):
            choose_available([], [], [Candidate("x", 2, 1), Candidate("x", 3, 1)])

    def test_information_and_transition_negative_controls(self):
        # A new reading cannot be manufactured from an insufficient old one.
        self.assertEqual(0 % 12, 12 % 12)
        self.assertNotEqual(0 % 9, 12 % 9)
        # Exact sign on all integers has no finite observation period.
        for p in range(2, 50):
            self.assertEqual((-1) % p, (p - 1) % p)
            self.assertNotEqual(-1 < 0, p - 1 < 0)
        # A recoverable observation is not automatically closed under division.
        self.assertEqual(0 % 2, 2 % 2)
        self.assertNotEqual((0 // 2) % 2, (2 // 2) % 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
