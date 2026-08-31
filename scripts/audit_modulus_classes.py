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
)
SUPPORTED_N = (1024, 2048, 8192, 16384)
MR_BASES = (2, 325, 9375, 28178, 450775, 9780504, 1795265022)

# Shape of `DualRNSContext::canonical_anchor_primes_for_n`
# (crates/nine65/src/arithmetic/rns.rs): 5 anchors for n <= 8192, plus 5 more
# for n >= 16384. Asserted during parsing so a regex regression fails loudly
# instead of silently auditing the wrong set.
ANCHOR_EXTENSION_N = 16384
EXPECTED_BASE_ANCHORS = 7
EXPECTED_EXTENDED_ANCHORS = 10


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


def strip_line_comments(text: str) -> str:
    """Drop `//`-style comment bodies, preserving line structure.

    `DualRNSContext::canonical_anchor_primes_for_n` annotates every anchor with
    an inline comment (`// 15 x 2^27 + 1 (~31 bits)`). Those digits are not
    anchors; scraping them was what made `all_anchors_prime` and
    `pairwise_coprime` fail. String literals are not stripped because the
    parsed region is a numeric literal list.
    """

    return "\n".join(line.split("//", 1)[0] for line in text.splitlines())


def balanced_block(text: str, open_index: int, opener: str, closer: str) -> str:
    """Return the contents between `opener` at `open_index` and its match.

    Non-greedy `.*?` stops at the first `]`, which is why the previous parser
    never saw the extra `n >= 16384` anchors appended after the initial
    `vec![...]`. Depth counting reads the whole nested block instead.
    """

    depth = 0
    for index in range(open_index, len(text)):
        char = text[index]
        if char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return text[open_index + 1 : index]
    raise AssertionError(f"unbalanced '{opener}' block while parsing anchors")


def anchor_function_body(source: str) -> str:
    marker = "pub fn canonical_anchor_primes_for_n"
    start = source.find(marker)
    if start < 0:
        raise AssertionError("missing canonical anchor function")
    brace = source.find("{", start)
    if brace < 0:
        raise AssertionError("unterminated canonical anchor function")
    return balanced_block(source, brace, "{", "}")


def parse_anchors(source: str) -> dict[str, list[int]]:
    """Parse the base and n >= 16384 extension anchor sets.

    Mirrors `DualRNSContext::canonical_anchor_primes_for_n`: a `vec![...]`
    literal holding the base anchors for n <= 8192, then an
    `extend_from_slice(&[...])` inside `if n >= 16384` adding the rest.
    """

    body = strip_line_comments(anchor_function_body(source))

    base_at = body.find("vec![")
    if base_at < 0:
        raise AssertionError("unable to locate canonical anchor vec! literal")
    base = parse_integer_list(balanced_block(body, body.index("[", base_at), "[", "]"))

    extended: list[int] = []
    for match in re.finditer(r"extend_from_slice\s*\(\s*&", body):
        bracket = body.find("[", match.end())
        if bracket < 0:
            raise AssertionError("unable to parse anchor extension slice")
        extended.extend(parse_integer_list(balanced_block(body, bracket, "[", "]")))

    if not base or not extended:
        raise AssertionError(
            f"anchor parse produced base={len(base)} extended={len(extended)}; "
            "canonical_anchor_primes_for_n shape drifted"
        )

    # The Rust source documents 7 anchors for n <= 8192 and 10 for n >= 16384.
    # Assert the parse matches so a silent regex regression cannot pass again.
    if len(base) != EXPECTED_BASE_ANCHORS:
        raise AssertionError(
            f"expected {EXPECTED_BASE_ANCHORS} base anchors, parsed {len(base)}: {base}"
        )
    if len(base) + len(extended) != EXPECTED_EXTENDED_ANCHORS:
        raise AssertionError(
            f"expected {EXPECTED_EXTENDED_ANCHORS} anchors for n >= "
            f"{ANCHOR_EXTENSION_N}, parsed {len(base) + len(extended)}"
        )

    return {"base": base, "extended": extended}


def anchors_for_n(anchors: dict[str, list[int]], n: int) -> list[int]:
    if n >= ANCHOR_EXTENSION_N:
        return anchors["base"] + anchors["extended"]
    return list(anchors["base"])


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
    anchor_sets = parse_anchors(rns_source)
    # The n >= 16384 basis is a strict superset of the n <= 8192 basis, so the
    # full set is what primality/coprimality must hold over.
    anchors = anchors_for_n(anchor_sets, ANCHOR_EXTENSION_N)
    canonical_anchors_by_n = {
        str(n): anchors_for_n(anchor_sets, n) for n in SUPPORTED_N
    }

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
    # NTT compatibility is evaluated against the anchor set actually used at
    # that ring dimension, not the union.
    anchors_ntt_compatible = {
        str(n): all((anchor - 1) % (2 * n) == 0 for anchor in canonical_anchors_by_n[str(n)])
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
        "canonical_anchors_by_n": canonical_anchors_by_n,
        "canonical_anchor_base_count": len(anchor_sets["base"]),
        "canonical_anchor_extended_count": len(anchors),
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
