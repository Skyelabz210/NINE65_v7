#!/usr/bin/env python3
"""Exact-integer audit of current CLASS-F main lanes and field-backed anchors.

The script reads the Rust sources, extracts the named parameter chains and
canonical anchors, and checks primality, NTT compatibility, distinctness, and
main/anchor coprimality. It records that the current FHE anchor path is CLASS-A:
field-backed polynomial convolution plus CLASS-R K-Elimination extraction.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECURE_CONFIGS = ROOT / "crates/nine65/src/params/secure_configs.rs"
RNS = ROOT / "crates/nine65/src/arithmetic/rns.rs"
OUTPUT = ROOT / "artifacts/security/modulus_class_audit_2026-07-13.json"

PROFILE_NAMES = (
    "secure_128",
    "secure_128_deep",
    "secure_192",
    "secure_256",
    "hardware_opt",
)
SUPPORTED_N = (1024, 2048, 8192, 16384)
MR_BASES = (2, 325, 9375, 28178, 450775, 9780504, 1795265022)


def is_prime(value: int) -> bool:
    if value < 2:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if value == small:
            return True
        if value % small == 0:
            return False

    odd_part = value - 1
    shifts = 0
    while odd_part % 2 == 0:
        odd_part //= 2
        shifts += 1

    for base in MR_BASES:
        if base % value == 0:
            continue
        witness = pow(base, odd_part, value)
        if witness in (1, value - 1):
            continue
        for _ in range(shifts - 1):
            witness = witness * witness % value
            if witness == value - 1:
                break
        else:
            return False
    return True


def parse_integer_list(text: str) -> list[int]:
    return [int(token.replace("_", "")) for token in re.findall(r"\b[0-9][0-9_]*\b", text)]


def function_body(source: str, name: str) -> str:
    marker = f"pub fn {name}() -> Self"
    start = source.find(marker)
    if start < 0:
        raise AssertionError(f"missing profile function {name}")
    next_function = source.find("\n    pub fn ", start + len(marker))
    if next_function < 0:
        next_function = source.find("\n}", start)
    if next_function < 0:
        raise AssertionError(f"unterminated profile function {name}")
    return source[start:next_function]


def parse_profile(source: str, name: str) -> dict[str, object]:
    body = function_body(source, name)
    call = re.search(
        r"Self::new_verified\(\s*([0-9_]+),\s*vec!\[(.*?)\],\s*([0-9_]+),",
        body,
        re.DOTALL,
    )
    if call is None:
        raise AssertionError(f"unable to parse profile {name}")
    n = int(call.group(1).replace("_", ""))
    primes = parse_integer_list(call.group(2))
    plaintext_modulus = int(call.group(3).replace("_", ""))
    return {"n": n, "primes": primes, "plaintext_modulus": plaintext_modulus}


def parse_anchors(source: str) -> list[int]:
    marker = "pub fn canonical_anchor_primes_for_n"
    start = source.find(marker)
    if start < 0:
        raise AssertionError("missing canonical anchor function")
    tail = source[start:]
    match = re.search(r"vec!\[(.*?)\]", tail, re.DOTALL)
    if match is None:
        raise AssertionError("unable to parse canonical anchor list")
    return parse_integer_list(match.group(1))


def pairwise_coprime(values: list[int]) -> bool:
    return all(
        math.gcd(left, right) == 1
        for index, left in enumerate(values)
        for right in values[index + 1 :]
    )


def main() -> int:
    secure_source = SECURE_CONFIGS.read_text(encoding="utf-8")
    rns_source = RNS.read_text(encoding="utf-8")

    profiles = {name: parse_profile(secure_source, name) for name in PROFILE_NAMES}
    anchors = parse_anchors(rns_source)

    all_main = [
        prime
        for profile in profiles.values()
        for prime in profile["primes"]  # type: ignore[index]
    ]

    all_main_prime = all(is_prime(prime) for prime in all_main)
    all_main_ntt_compatible = all(
        (prime - 1) % (2 * int(profile["n"])) == 0
        for profile in profiles.values()
        for prime in profile["primes"]  # type: ignore[index]
    )
    all_profile_lanes_pairwise_coprime = all(
        pairwise_coprime(list(profile["primes"]))  # type: ignore[arg-type]
        for profile in profiles.values()
    )
    all_plaintext_moduli_valid = all(
        2 <= int(profile["plaintext_modulus"])
        and all(
            int(profile["plaintext_modulus"]) < prime
            for prime in profile["primes"]  # type: ignore[index]
        )
        for profile in profiles.values()
    )

    all_anchors_prime = all(is_prime(anchor) for anchor in anchors)
    anchors_ntt_compatible = {
        str(n): all((anchor - 1) % (2 * n) == 0 for anchor in anchors)
        for n in SUPPORTED_N
    }
    anchors_pairwise_coprime = pairwise_coprime(anchors)
    main_anchor_disjoint_and_coprime = all(
        math.gcd(prime, anchor) == 1 for prime in all_main for anchor in anchors
    )

    checks = (
        all_main_prime,
        all_main_ntt_compatible,
        all_profile_lanes_pairwise_coprime,
        all_plaintext_moduli_valid,
        all_anchors_prime,
        all(anchors_ntt_compatible.values()),
        anchors_pairwise_coprime,
        main_anchor_disjoint_and_coprime,
    )
    if not all(checks):
        raise AssertionError("one or more modulus-class checks failed")

    result: dict[str, object] = {
        "schema": 1,
        "status": "PASS",
        "arithmetic": "exact_integer_only",
        "main_lane_class": "CLASS-F",
        "current_anchor_execution_class": (
            "CLASS-A_FIELD_BACKED_NTT_PLUS_CLASS-R_K-ELIM"
        ),
        "profiles": profiles,
        "canonical_anchors": anchors,
        "all_main_prime": all_main_prime,
        "all_main_ntt_compatible": all_main_ntt_compatible,
        "all_profile_lanes_pairwise_coprime": all_profile_lanes_pairwise_coprime,
        "all_plaintext_moduli_valid": all_plaintext_moduli_valid,
        "all_anchors_prime": all_anchors_prime,
        "anchors_ntt_compatible_for_supported_n": anchors_ntt_compatible,
        "anchors_pairwise_coprime": anchors_pairwise_coprime,
        "main_anchor_disjoint_and_coprime": main_anchor_disjoint_and_coprime,
        "ring_only_composite_anchor_fast_path_available": False,
    }
    canonical = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    result["evidence_sha256"] = hashlib.sha256(canonical).hexdigest()

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
