#!/usr/bin/env python3
"""Finite exact oracle for dependent CRAM sister views.

This is test/reference code. It enumerates source integers and compatible pairs
explicitly; it is not a residue-native production producer or a formal proof.
Only integer arithmetic is used in the mathematical checks.
"""

import argparse
import hashlib
import json
import platform
from math import gcd, lcm
from pathlib import Path


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def multiplicative_order(value, modulus):
    require(gcd(value, modulus) == 1, "Order requires a unit")
    product = 1
    for exponent in range(1, modulus + 1):
        product = product * value % modulus
        if product == 1:
            return exponent
    raise RuntimeError("Finite unit order was not found")


def run():
    left, right, shared = 77, 143, 11
    period = lcm(left, right)
    require(period == 1001 and gcd(left, right) == shared, "Wrong frame")

    # Whole integers are deliberately an independent test oracle, not runtime
    # state for the proposed dependent-sister implementation.
    image = {}
    for source in range(period):
        pair = (source % left, source % right)
        require(pair not in image, "Two admitted source integers alias")
        image[pair] = source
    require(len(image) == 1001, "Wrong image size")

    compatible = set()
    pair_checks = 0
    for a in range(left):
        for b in range(right):
            matches_shadow = a % shared == b % shared
            require(matches_shadow == ((a, b) in image), "Fiber product mismatch")
            if matches_shadow:
                compatible.add((a, b))
            pair_checks += 1
    require(pair_checks == 77 * 143, "Incomplete pair enumeration")
    require(compatible == set(image), "Missing compatible pair")

    # The same integer polynomial descends compatibly to all three rings.
    def polynomial(x):
        return x * x + 3 * x + 7

    phase_checks = 0
    for a, b in compatible:
        output = (polynomial(a) % left, polynomial(b) % right)
        require(output[0] % shared == output[1] % shared,
                "Common-polynomial output lost compatibility")
        source = image[(a, b)]
        expected = (polynomial(source) % left, polynomial(source) % right)
        require(output == expected, "Lane output disagrees with integer oracle")
        require(image[output] == polynomial(source) % period,
                "Output has wrong canonical joint representative")
        phase_checks += 1

    before, after = (0, 0), (0, 1)
    require(before in compatible, "Negative-control source is invalid")
    require(after not in compatible, "Mismatched update was not rejected")
    require(after[0] % shared != after[1] % shared,
            "Negative-control phase defect vanished")

    order_4_11 = multiplicative_order(4, 11)
    order_4_121 = multiplicative_order(4, 121)
    require(order_4_11 == 5, "Unexpected mod-11 order")
    require(order_4_121 == 55, "Unexpected mod-121 order")
    candidates = list(range(4, 121, 11))
    lifts = [a for a in candidates if pow(a, 5, 121) == 1]
    require(lifts == [81], "Fifth-root lift is not unique")
    order_81_121 = multiplicative_order(81, 121)
    require(order_81_121 == 5, "Lift did not retain order five")

    # For unit a, roots of r*(a*r+b) are 0 and -b/a. They coincide exactly
    # when b=0 modulo p. Exhaust over several small prime fields.
    primes = [3, 5, 7, 11, 13]
    linear_cases = 0
    one_root_cases = 0
    two_root_cases = 0
    for prime in primes:
        for a in range(1, prime):
            inverse = pow(a, -1, prime)
            for b in range(prime):
                roots = {r for r in range(prime) if r * (a * r + b) % prime == 0}
                require(roots == {0, (-b * inverse) % prime}, "Wrong roots")
                expected_count = 1 if b == 0 else 2
                require(len(roots) == expected_count, "Wrong exclusion count")
                one_root_cases += expected_count == 1
                two_root_cases += expected_count == 2
                linear_cases += 1

    return {
        "status": "PASS",
        "scope": "Finite exact test/oracle only; no production producer or formal verification claim",
        "arithmetic": "integer-only mathematical checks",
        "fiber_product": {
            "carrier_moduli": [left, right],
            "shared_modulus": shared,
            "joint_period": period,
            "all_pairs_checked": pair_checks,
            "compatible_pairs": len(compatible),
            "incompatible_pairs": pair_checks - len(compatible),
            "unique_sources_checked": len(image),
            "compatibility": "a mod 11 = b mod 11",
        },
        "phase_preservation": {
            "operator": "F(x) = x^2 + 3*x + 7",
            "compatible_inputs_checked": phase_checks,
            "lane_results_match_integer_oracle": True,
            "negative_control": {"before": list(before), "after": list(after), "rejected": True},
            "limitation": "Only this common polynomial was evaluated; arbitrary heterogeneous maps need their own compatibility proof",
        },
        "shadow_unit_orders": {
            "order_4_mod_11": order_4_11,
            "order_4_mod_121": order_4_121,
            "lift_candidates_checked": len(candidates),
            "fifth_roots_mod_121_congruent_to_4_mod_11": lifts,
            "order_81_mod_121": order_81_121,
        },
        "linear_pair_roots": {
            "prime_fields": primes,
            "unit_a_and_b_cases_checked": linear_cases,
            "one_excluded_class_cases": one_root_cases,
            "two_excluded_class_cases": two_root_cases,
            "condition": "one iff b=0 mod p; otherwise two, assuming a is a unit",
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path,
                        default=Path(__file__).with_name("dependent_sister_probe_results.json"))
    args = parser.parse_args()
    result = run()
    result["reproducibility"] = {
        "python": platform.python_version(),
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
