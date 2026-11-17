#!/usr/bin/env python3
"""Reproduce the finite examples in DISPARATE_DOMAIN_CONNECTIONS.md.

Standard library only. These checks are finite mathematical witnesses, not
Lean proofs, benchmarks, ciphertext execution, or tests of production APIs.
Run from any directory; --output selects a different JSON evidence path.
"""

from __future__ import annotations

import argparse
import hashlib
from itertools import product
import json
from pathlib import Path
import re
import subprocess


PACKET = Path(__file__).resolve().parents[1]


def check_floor_division() -> dict:
    """Test quotient periodicity across exactly 4,096 parameter triples.

    For a fixed c,b,P, the difference floor((x+P)/c)-floor(x/c)
    is c-periodic in x. Checking x=0,...,c-1 therefore checks every
    possible quotient increment for that parameter triple, including
    negative integer x by periodicity. This does not enumerate every c,b,P.
    """
    parameter_triples = 0
    residue_positions = 0
    for divisor, target_modulus, observation_period in product(
        range(1, 9), range(1, 9), range(1, 65)
    ):
        increments = [
            ((x + observation_period) // divisor - x // divisor)
            % target_modulus
            for x in range(divisor)
        ]
        observed_periodicity = all(value == 0 for value in increments)
        predicted_periodicity = (
            target_modulus == 1
            or observation_period % (divisor * target_modulus) == 0
        )
        if observed_periodicity != predicted_periodicity:
            raise AssertionError(
                (divisor, target_modulus, observation_period, increments)
            )
        parameter_triples += 1
        residue_positions += len(increments)
    if parameter_triples != 4096:
        raise AssertionError(parameter_triples)
    return {
        "status": "PASS",
        "parameter_triples": parameter_triples,
        "residue_positions_evaluated": residue_positions,
        "divisor_range_inclusive": [1, 8],
        "target_modulus_range_inclusive": [1, 8],
        "observation_period_range_inclusive": [1, 64],
        "criterion": "b == 1 or P % (c*b) == 0",
    }


def check_query_error_code() -> dict:
    """At most one F_5 target lies within one error of any received word.

    The target is s=a+b modulo 5, encoded as (s,s,s). There are five
    target codewords and 125 received words, not 125 independent codes.
    """
    received_words = 0
    decodable_words = 0
    for word in product(range(5), repeat=3):
        compatible_targets = {
            target
            for target in range(5)
            if sum(symbol != target for symbol in word) <= 1
        }
        if len(compatible_targets) > 1:
            raise AssertionError((word, compatible_targets))
        if compatible_targets:
            decodable_words += 1
        received_words += 1
    if received_words != 125:
        raise AssertionError(received_words)
    return {
        "status": "PASS",
        "alphabet_size": 5,
        "codeword_length": 3,
        "distinct_target_codewords": 5,
        "allowed_symbol_errors": 1,
        "received_words": received_words,
        "received_words_with_one_compatible_target": decodable_words,
        "received_words_with_no_compatible_target": received_words - decodable_words,
    }


def check_merge_obstruction() -> dict:
    modulus, source, alternate_source, other = 5, 0, 5, 3
    if source % modulus != alternate_source % modulus:
        raise AssertionError("The source observation must be identical")
    left = max(source, other) % modulus
    right = max(alternate_source, other) % modulus
    if left == right:
        raise AssertionError("The projected merges must differ")
    return {
        "status": "PASS",
        "negative_controls": 1,
        "modulus": modulus,
        "indistinguishable_sources": [source, alternate_source],
        "merge_operand": other,
        "projected_max_results": [left, right],
    }


def check_relative_links() -> dict:
    checked = 0
    for name in ["DISPARATE_DOMAIN_CONNECTIONS.md", "SOURCES.md"]:
        contents = (PACKET / name).read_text(encoding="utf-8")
        for target in re.findall(r"\]\(([^)]+)\)", contents):
            if target.startswith(("https:", "http:", "#")):
                continue
            if not (PACKET / target).exists():
                raise AssertionError((name, target))
            checked += 1
    return {"status": "PASS", "relative_link_occurrences_checked": checked}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=PACKET / "evidence" / "domain_witness.json",
    )
    args = parser.parse_args()
    try:
        source_commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=PACKET, text=True
        ).strip()
    except (FileNotFoundError, subprocess.CalledProcessError):
        source_commit = None
    results = {
        "status": "PASS",
        "scope": "Finite mathematical witnesses and document links; not general formal proof or production execution",
        "repository_head": source_commit,
        "witness_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "floor_division": check_floor_division(),
        "query_error_code": check_query_error_code(),
        "modular_max_merge": check_merge_obstruction(),
        "document_links": check_relative_links(),
    }
    encoded = json.dumps(results, indent=2, sort_keys=True) + "\n"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")


if __name__ == "__main__":
    main()
