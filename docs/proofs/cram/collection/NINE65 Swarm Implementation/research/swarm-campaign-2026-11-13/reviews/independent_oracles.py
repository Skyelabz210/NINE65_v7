"""Independent campaign boundary witnesses; no production or ciphertext code.

These finite exact oracles test the specifications and deliberately record
obstructions. They do not replace review of the implementation under test.
"""
from datetime import datetime, timezone
from itertools import product
from math import gcd, lcm
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parent


def partitions(n):
    seen = set()
    for word in product(range(n), repeat=n):
        names = {}
        normalized = tuple(names.setdefault(v, len(names)) for v in word)
        seen.add(normalized)
    return tuple(sorted(seen))


def future_relation(q, f):
    """Independent pair reachability, not signature/partition refinement."""
    n = len(q)
    pairs = {(i, j) for i in range(n) for j in range(n) if q[i] != q[j]}
    while True:
        nxt = pairs | {(i, j) for i in range(n) for j in range(n)
                       if (f[i], f[j]) in pairs}
        if nxt == pairs:
            return {(i, j) for i in range(n) for j in range(n)
                    if (i, j) not in pairs}
        pairs = nxt


def main():
    results = {}
    # Full legal window; target projections evaluated without reconstructing X.
    queries = 0
    for x in range(36 * 37):
        r, s = x % 36, x % 37
        k = (r - s) % 37
        assert k == x // 36
        for b in range(1, 101):
            out = (r % b + (36 % b) * (k % b)) % b
            assert out == x % b
            queries += 1
    results["adjacent_window"] = {"sources": 1332, "target_projections": queries}

    # All same-bound low-input operations fit in the frame. Metadata need not
    # equal either actual operand: every operand has common public bound 35.
    operations = 0
    for a, b in product(range(36), repeat=2):
        for result in (a + b, a * b):
            r, s = result % 36, result % 37
            assert (r - s) % 37 == result // 36
            operations += 1
    results["bounded_operations"] = {"operand_bound": 35, "cases": operations}

    # The universal query condition for an integer source with period M*R.
    condition_cases = 0
    for m, r, b in product(range(1, 21), repeat=3):
        observed_period = m * r
        target_constant_on_fibers = all((x + observed_period) % b == x % b
                                       for x in range(b))
        assert target_constant_on_fibers == (observed_period % b == 0)
        condition_cases += 1
    results["target_period_condition"] = {"parameter_triples": condition_cases}

    # Independently test the coarsest stable relation against every partition.
    models = 0
    comparisons = 0
    for q in product(range(2), repeat=3):
        for f in product(range(3), repeat=3):
            relation = future_relation(q, f)
            assert all(q[x] == q[y] and (f[x], f[y]) in relation
                       for x, y in relation)
            for partition in partitions(3):
                candidate = {(x, y) for x in range(3) for y in range(3)
                             if partition[x] == partition[y]}
                admissible = all(q[x] == q[y] and (f[x], f[y]) in candidate
                                 for x, y in candidate)
                if admissible:
                    assert candidate <= relation
                comparisons += 1
            models += 1
    results["future_query_maximality"] = {"models": models, "partition_checks": comparisons}

    gcd_cases = 0
    for w in range(1, 9):
        for a, b in product(range(1 << w), repeat=2):
            x, y = a, b
            for _ in range(2 * w):
                before = gcd(x, y)
                if y:
                    x, y = y, x % y
                assert gcd(x, y) == before
            assert y == 0 and x == gcd(a, b)
            gcd_cases += 1
    results["fixed_schedule_euclid"] = {"widths": [1, 8], "input_pairs": gcd_cases}

    negative = [
        {"name": "capacity_alias", "x": 0, "y": 1332,
         "observations": [0, 0], "quotients": [0, 37]},
        {"name": "mixed_source_valid_arithmetic", "main_source": 0,
         "anchor_source": 1, "mixed_readings": [0, 1],
         "compatible_third_source": 1296,
         "lesson": "Arithmetic validity alone cannot prove common-source origin."},
        {"name": "overlap_not_product", "moduli": [4, 6, 6],
         "actual_period": lcm(4, 6, 6), "false_product": 144},
        {"name": "missing_prime_power", "old_period": 12, "demand": 18,
         "failed_extra": 3, "sufficient_extra": 9},
        {"name": "halving_breaks_parity", "x": 0, "y": 2,
         "same_parity": True, "output_parities": [0, 1]},
        {"name": "sign_not_finite_period", "period": 1332,
         "x": -1, "y": 1331, "equal_residues": True},
    ]
    assert (0 % 36, 0 % 37) == (1332 % 36, 1332 % 37)
    assert (0 % 36, 1 % 37) == (1296 % 36, 1296 % 37)
    assert lcm(12, 3) % 18 != 0 and lcm(12, 9) % 18 == 0
    results["negative_witnesses"] = negative
    report = {
        "status": "PASS", "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "Independent mathematical finite witnesses; not Rust or ciphertext execution",
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "results": results,
    }
    (ROOT / "independent_oracles.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
