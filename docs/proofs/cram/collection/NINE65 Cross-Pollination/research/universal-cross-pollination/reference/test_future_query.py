from itertools import product
import unittest

from future_query import classify, compile_future_queries


class FutureQueryTests(unittest.TestCase):
    def test_affine_modular_dynamics_keep_small_query(self):
        n = 16
        transitions = {
            "triple_add_one": tuple((3*x + 1) % n for x in range(n)),
            "negate": tuple((-x) % n for x in range(n)),
        }
        model = compile_future_queries([(x % 4,) for x in range(n)], transitions)
        self.assertEqual(model.classes, tuple(x % 4 for x in range(n)))
        self.assertEqual(model.strict_refinements, 0)
        for x in range(n):
            for word in product(transitions, repeat=5):
                state, small = x, model.classes[x]
                for op in word:
                    state = transitions[op][state]
                    small = model.quotient_transitions[op][small]
                self.assertEqual(model.quotient_outputs[small], (state % 4,))

    def test_halving_makes_future_parity_reveal_all_bits(self):
        n = 16
        model = compile_future_queries([(x % 2,) for x in range(n)],
                                       {"halve": tuple(x // 2 for x in range(n))})
        self.assertEqual(model.classes, tuple(range(n)))
        self.assertEqual(model.strict_refinements, 3)

    def test_no_future_operations_and_empty_consumers(self):
        model = compile_future_queries([(1,), (1,), (2,)], {})
        self.assertEqual(model.classes, (0, 0, 1))
        empty = compile_future_queries([(), (), ()], {"cycle": (1, 2, 0)})
        self.assertEqual(empty.classes, (0, 0, 0))

    def test_exhaustive_minimality_against_all_small_partitions(self):
        # Independent oracle: enumerate every candidate partition of 4 states.
        n = 4
        partitions = set(classify(labels) for labels in product(range(n), repeat=n))
        for transition in product(range(n), repeat=n):
            output = tuple(x % 2 for x in range(n))
            model = compile_future_queries([(v,) for v in output], {"f": transition})
            for candidate in partitions:
                sufficient = all(
                    candidate[x] != candidate[y] or
                    (output[x] == output[y] and
                     candidate[transition[x]] == candidate[transition[y]])
                    for x in range(n) for y in range(n))
                if sufficient:
                    self.assertTrue(all(candidate[x] != candidate[y] or
                                        model.classes[x] == model.classes[y]
                                        for x in range(n) for y in range(n)))
            self.assertLessEqual(model.strict_refinements, n - len(set(output)))

    def test_invalid_or_nonclosed_models_refused(self):
        for outputs, transitions in (([], {}), ([(0,), ()], {}),
                                     ([(0,), (1,)], {"escape": (0, 2)}),
                                     ([(0,), (1,)], {"partial": (0,)}),
                                     ([(True,)], {})):
            with self.assertRaises(ValueError):
                compile_future_queries(outputs, transitions)


if __name__ == "__main__":
    unittest.main(verbosity=2)
