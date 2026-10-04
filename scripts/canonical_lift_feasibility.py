#!/usr/bin/env python3
"""Check the public Rust probe and assess the existing polynomial certificate.

Uses Python arbitrary-precision integers only. The complete-circuit lower
bound drops positive quadratic, rounding, constant-encoding, and switch terms
from the certificate. It bounds that certificate, not actual ciphertext error
or every possible bootstrap. No candidate in this report is admitted for refresh.
"""

import argparse
import hashlib
import json
import math
import re
import sys
from functools import cache
from pathlib import Path


class NoiseRefusal(Exception):
    def __init__(self, stage, count, error, half):
        self.result = {
            "stage": stage,
            "product_factors": count,
            "depth": (count - 1).bit_length(),
            "error_bits": error.bit_length(),
            "half_delta_bits": half.bit_length(),
            "error_bound": str(error),
        }


def ceil_div(numerator, denominator):
    return (numerator + denominator - 1) // denominator


def assess(record, base_bits):
    n, p, eta = record["n"], record["base"], record["eta"]
    primes = record["primes"]
    if n < 2 or n & (n - 1) or p < 3 or p % 2 == 0 or eta < 1:
        raise ValueError(f"invalid probe parameters: {record['name']}")
    modulus = math.prod(primes)
    expanded = p * p
    half = modulus // expanded // 2
    if half == 0:
        raise ValueError("probe has no high-encoding scale")
    digits = [ceil_div(q.bit_length(), base_bits) for q in primes]
    switch = eta * n * ((1 << base_bits) - 1) * sum(digits)
    remainder = modulus % expanded
    phase = (
        eta * (2 * n + 1) * n * ((expanded - 1) // 2)
        + remainder * (n + 1)
        + ceil_div(remainder, 2)
    )
    projection = n * phase + (n - 1) * switch
    factor = (expanded - 1) // 2 + expanded * n * (n // 2 + 1)
    leaf = projection + ceil_div(remainder * (p - 1), expanded)
    rounding = ceil_div(1 + n + n * n, 2)

    exact_plan = record["exact_multiply"]
    if "refusal" not in exact_plan:
        if exact_plan["q_bits"] != modulus.bit_length() or exact_plan["digits_per_lane"] != digits:
            raise ValueError("Rust exact-multiply metadata disagrees with independent integers")
    screen = record["security_screen"]
    if "refusal" not in screen and screen["q_bits"] != modulus.bit_length():
        raise ValueError("Rust security screen reports the wrong modulus width")
    for field, expected in [("phase_error_bound_hex", phase), ("half_delta_hex", half)]:
        if field in record and int(record[field], 16) != expected:
            raise ValueError(f"Rust {field} disagrees with independent integers")

    nodes_checked = 0

    def admit(stage, count, error):
        if error >= half:
            raise NoiseRefusal(stage, count, error, half)
        return error

    @cache
    def product(count):
        nonlocal nodes_checked
        if count == 1:
            return admit("affine factor", count, leaf)
        left = product(count // 2)
        right = product(count - count // 2)
        # Independently compare the production dyadic ceiling against the
        # exact arbitrary-precision rational ceiling at every reachable node.
        numerator = n * expanded * left * right
        exact_quadratic = ceil_div(numerator, modulus)
        if left == 0 or right == 0:
            dyadic = 0
        else:
            exponent = max(
                0,
                left.bit_length() + right.bit_length() + (n * expanded).bit_length()
                - (modulus.bit_length() - 1),
            )
            dyadic = 1 << exponent
        if dyadic < exact_quadratic:
            raise ValueError("production quadratic ceiling underestimates the exact term")
        nodes_checked += 1
        return admit("polynomial multiply", count, factor * (left + right) + dyadic + rounding + switch)

    first_refusal = None
    try:
        admit("input", 1, phase)
        admit("coefficient projection", 1, projection)
        bound = product(p)
        coefficient = admit("canonical section", p, projection + bound)
        lifted = admit("coefficient reassembly", p, n * coefficient)
    except NoiseRefusal as error:
        first_refusal = error.result
        lifted = None

    # Closed-form linear-only bound, independent of the recursive schedule
    # above. Balanced p-leaf trees have leaves at depths k and k+1, where
    # k=floor(log2 p). Each leaf contributes projection * factor^depth.
    k = p.bit_length() - 1
    shallow_leaves = (1 << (k + 1)) - p
    deep_leaves = 2 * p - (1 << (k + 1))
    optimistic_product = projection * factor**k * (shallow_leaves + factor * deep_leaves)
    optimistic_lift = n * (projection + optimistic_product)
    production = record["production_lift"]
    matched = False
    if production["stage"] == "canonical_lift" and "refusal" not in exact_plan:
        if production.get("admitted", False):
            if lifted is None or int(production["lifted_error_bound_hex"], 16) != lifted:
                raise ValueError("Rust admitted a lift that the independent certificate refuses")
        else:
            pattern = r"needs (\d+) error bits; high encoding has (\d+) half-Delta bits"
            match = re.search(pattern, production["refusal"])
            if first_refusal is None or match is None:
                raise ValueError("unrecognized or inconsistent Rust canonical-lift refusal")
            if (
                first_refusal["stage"] not in production["refusal"]
                or tuple(map(int, match.groups()))
                != (first_refusal["error_bits"], first_refusal["half_delta_bits"])
            ):
                raise ValueError("Rust canonical-lift refusal disagrees with independent integers")
        matched = True

    return {
        "name": record["name"],
        "n": n,
        "base": p,
        "eta": eta,
        "primes": primes,
        "q_bits": modulus.bit_length(),
        "phase_error_bits": phase.bit_length(),
        "projection_error_bits": projection.bit_length(),
        "half_delta_bits": half.bit_length(),
        "polynomial_degree": p,
        "multiplicative_depth": (p - 1).bit_length(),
        "automorphism_count": n * (n.bit_length() - 1),
        "ciphertext_multiplication_count": n * (p - 1),
        "key_main_bytes_if_plan_admitted": n.bit_length() * sum(digits) * 2 * len(primes) * n * 8,
        "optimistic_certificate_error_bits": optimistic_lift.bit_length(),
        "certificate_lower_bound_already_exceeds_half_delta": optimistic_lift >= half,
        "first_noise_refusal": first_refusal,
        "exact_quadratic_nodes_checked": nodes_checked,
        "production_lift": production,
        "production_noise_result_cross_checked": matched,
        "exact_multiply": exact_plan,
        "security_screen": screen,
        "complete_refresh_admitted": False,
    }


def verify(probe):
    if probe.get("schema") != "nine65-canonical-lift-probe-v1":
        raise ValueError("unsupported Rust probe schema")
    successful_plans = [
        record["exact_multiply"] for record in probe["records"]
        if "refusal" not in record["exact_multiply"]
    ]
    widths = {plan["base_bits"] for plan in successful_plans}
    if len(widths) != 1:
        raise ValueError("probe needs a consistent production gadget width")
    base_bits = widths.pop()
    if not 1 <= base_bits <= 63:
        raise ValueError("invalid gadget width")
    names = [record["name"] for record in probe["records"]]
    if not names or len(set(names)) != len(names):
        raise ValueError("probe record names must be nonempty and unique")
    rows = [assess(record, base_bits) for record in probe["records"]]
    return {
        "schema": "nine65-canonical-lift-feasibility-v1",
        "base_commit": probe["base_commit"],
        "probe_source_sha256": probe["source_sha256"],
        "oracle_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "scope": "Lower bounds on the existing polynomial noise certificate, not necessary actual noise or a general bootstrap impossibility theorem.",
        "checks": {
            "records": len(rows),
            "production_noise_results_cross_checked": sum(row["production_noise_result_cross_checked"] for row in rows),
            "exact_quadratic_nodes_checked": sum(row["exact_quadratic_nodes_checked"] for row in rows),
            "all_certificate_lower_bounds_refuse": all(row["certificate_lower_bound_already_exceeds_half_delta"] for row in rows),
        },
        "records": rows,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("probe", type=Path, help="JSON emitted by the Rust public-metadata probe")
    parser.add_argument("--output", type=Path, help="write the checked JSON report to this path")
    args = parser.parse_args()
    try:
        report = verify(json.loads(args.probe.read_text()))
        report["probe_sha256"] = hashlib.sha256(args.probe.read_bytes()).hexdigest()
        encoded = json.dumps(report, indent=2) + "\n"
        if args.output:
            args.output.write_text(encoded)
        else:
            sys.stdout.write(encoded)
    except (KeyError, ValueError, TypeError, OSError) as error:
        print(f"canonical-lift feasibility check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
