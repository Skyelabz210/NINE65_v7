"""Independent reproducible model checks, separate from implementation tests."""
from pathlib import Path
import hashlib
import itertools
import json
import math
import random
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "reference"))
from query_planner import Candidate, LinearQuery, choose_available, minimal_extra_anchor
from future_query import compile_future_queries


def factor(n):
    factors = {}
    p = 2
    while p * p <= n:
        while n % p == 0:
            factors[p] = factors.get(p, 0) + 1
            n //= p
        p += 1
    if n > 1:
        factors[n] = factors.get(n, 0) + 1
    return factors


def main():
    rng = random.Random(651211)
    for _ in range(5000):
        p, d = rng.randrange(1, 100000), rng.randrange(1, 100000)
        fp, fd = factor(p), factor(d)
        expected = math.prod(q ** e for q, e in fd.items() if e > fp.get(q, 0))
        assert minimal_extra_anchor(p, d) == expected, (p, d, expected)
    for _ in range(1500):
        p, d = rng.randrange(1, 151), rng.randrange(1, 151)
        candidates = [Candidate(str(j), rng.randrange(1, 121), rng.randrange(1, 12))
                      for j in range(rng.randrange(0, 9))]
        rng.shuffle(candidates)
        got = choose_available([p], [LinearQuery(1, d)], candidates)
        feasible = []
        for n in range(len(candidates) + 1):
            for subset in itertools.combinations(candidates, n):
                if math.lcm(p, *(c.modulus for c in subset)) % d == 0:
                    feasible.append((sum(c.cost for c in subset), len(subset),
                                     tuple(sorted(c.name for c in subset))))
        if feasible:
            assert got is not None
            assert (got.cost, len(got.selected), got.selected) == min(feasible)
        else:
            assert got is None
    for _ in range(2000):
        n = rng.randrange(1, 21)
        outputs = [(rng.randrange(3), rng.randrange(2)) for _ in range(n)]
        transitions = {str(i): tuple(rng.randrange(n) for _ in range(n))
                       for i in range(rng.randrange(4))}
        got = compile_future_queries(outputs, transitions)
        # Independent pair-graph oracle: a pair is distinguishable iff its
        # current output differs or a finite transition word reaches such a pair.
        distinguished = {(x, y) for x in range(n) for y in range(n)
                         if outputs[x] != outputs[y]}
        while True:
            enlarged = distinguished | {
                (x, y) for x in range(n) for y in range(n)
                if any((t[x], t[y]) in distinguished for t in transitions.values())}
            if enlarged == distinguished:
                break
            distinguished = enlarged
        for x in range(n):
            for y in range(n):
                assert (got.classes[x] != got.classes[y]) == ((x, y) in distinguished)
        assert got.strict_refinements <= n - len(set(outputs))
    files = ["reference/query_planner.py", "reference/future_query.py",
             "evidence/reviewer_oracles.py"]
    report = {
        "status": "PASS", "seed": 651211,
        "factorization_oracle_cases": 5000,
        "random_subset_oracle_cases": 1500,
        "pair_graph_future_query_oracle_cases": 2000,
        "scope": "Public finite mathematical models; no ciphertext execution",
        "sha256": {f: hashlib.sha256((ROOT / f).read_bytes()).hexdigest() for f in files},
    }
    (ROOT / "evidence/reviewer_oracles.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
