#!/usr/bin/env python3
"""Validate forced real-refresh evidence; missing or contradictory data fails."""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import sys


def validate_report(report, *, requested_operations=1, trials=100,
                    operations_per_trial=80, config="secure_128_deep"):
    errors = []

    def require(condition, message):
        if not condition:
            errors.append(message)

    def mapping(value, path):
        require(isinstance(value, dict), f"{path}: missing object")
        return value if isinstance(value, dict) else {}

    def integer(value):
        return type(value) is int and value >= 0

    def no_float(value, path):
        if isinstance(value, float):
            errors.append(f"{path}: floating-point report value")
        elif isinstance(value, dict):
            for key, item in value.items():
                no_float(item, f"{path}.{key}")
        elif isinstance(value, list):
            for index, item in enumerate(value):
                no_float(item, f"{path}[{index}]")

    report = mapping(report, "report")
    no_float(report, "report")
    require(report.get("schema") == "nine65-real-refresh-evidence-v1", "report: unsupported schema")
    require(report.get("overall_correct") is True, "report: overall correctness failed")
    metadata = mapping(report.get("metadata"), "metadata")
    require(metadata.get("integer_only_reporting") is True, "metadata: integer reporting not declared")
    require(type(metadata.get("simulated_refreshes")) is int
            and metadata["simulated_refreshes"] == 0, "metadata: simulated refreshes")
    require(type(metadata.get("trigger_pct")) is int and metadata["trigger_pct"] == 100,
            "metadata: forced 100% refresh trigger required")
    require(metadata.get("bootstrap_mode") == "real", "metadata: real bootstrap mode required")
    require(metadata.get("config") == config, "metadata: configuration mismatch")
    modulus = metadata.get("t")
    require(integer(modulus) and modulus >= 2, "metadata: invalid plaintext modulus")

    renewal = mapping(report.get("renewal_witness"), "renewal_witness")
    require(renewal.get("enabled") is True and renewal.get("passed") is True,
            "renewal_witness: stressed renewal did not pass")
    require(type(renewal.get("real_refreshes")) is int and renewal["real_refreshes"] == 1,
            "renewal_witness: exactly one real renewal required")

    def decimal(field):
        value = renewal.get(field)
        valid = isinstance(value, str) and value.isascii() and value.isdecimal()
        parsed = int(value) if valid else None
        require(valid and str(parsed) == value, f"renewal_witness.{field}: missing exact decimal magnitude")
        return parsed

    q = decimal("modulus_q")
    injected = decimal("injected_error")
    reserve = decimal("input_reserve_scaled")
    before = decimal("input_error_scaled")
    after = decimal("output_error_scaled")
    bound = decimal("refresh_error_bound_scaled")
    n, eta, primes = metadata.get("n"), metadata.get("eta"), metadata.get("rns_primes")
    valid_parameters = (integer(n) and n >= 2 and n & (n - 1) == 0 and integer(eta)
                        and integer(modulus) and modulus >= 2 and isinstance(primes, list)
                        and len(primes) > 0 and all(integer(p) and p > modulus for p in primes))
    require(valid_parameters, "renewal_witness: invalid observer parameters")
    if valid_parameters:
        expected_q = math.prod(primes)
        noise_bits = modulus.bit_length() + 2 * (n.bit_length() - 1) + max(eta.bit_length(), 1) + 2
        expected_bound = modulus * ((1 << noise_bits) + n + modulus + 1)
        require(q == expected_q and expected_q < 1 << 128, "renewal_witness: checked Q mismatch")
        require(injected == expected_q // (8 * n * modulus) and injected > 0,
                "renewal_witness: incorrect public stress injection")
        require(reserve == expected_q // (2 * n), "renewal_witness: incorrect refresh-input reserve")
        require(type(renewal.get("declared_refresh_noise_mb")) is int
                and renewal["declared_refresh_noise_mb"] == 1000 * noise_bits,
                "renewal_witness: declared output bound mismatch")
        require(bound == expected_bound, "renewal_witness: scaled output bound mismatch")
        for field in ("input_coefficients_checked", "output_coefficients_checked"):
            require(type(renewal.get(field)) is int and renewal[field] == n,
                    f"renewal_witness.{field}: every coefficient must be observed")
    if None not in (before, after, bound, reserve):
        require(0 <= before < reserve, "renewal_witness: input outside refresh corridor")
        require(before > 2 * bound, "renewal_witness: input is not stressed enough to reject a no-op")
        require(0 <= after < bound, "renewal_witness: output did not contract below refresh bound")
    for field in ("input_decrypted", "output_decrypted"):
        require(integer(renewal.get("expected")) and integer(renewal.get(field))
                and integer(modulus) and renewal["expected"] < modulus
                and renewal[field] == renewal["expected"],
                f"renewal_witness.{field}: plaintext mismatch")
    require(renewal.get("input_admitted") is True, "renewal_witness: input was not admitted")

    def oracle(value, path):
        value = mapping(value, path)
        expected, decrypted = value.get("expected"), value.get("decrypted")
        valid = (integer(expected) and integer(decrypted) and integer(modulus)
                 and expected < modulus and decrypted < modulus)
        require(valid, f"{path}: missing/out-of-range plaintext oracle")
        require(valid and expected == decrypted, f"{path}: plaintext mismatch")
        require(value.get("correct") is True, f"{path}: correctness check failed")

    def chain(value, path, operations):
        value = mapping(value, path)
        for field in ("requested_operations", "operations_achieved", "real_refreshes"):
            require(integer(value.get(field)) and value[field] == operations,
                    f"{path}.{field}: every requested operation must run and refresh")
        require(value.get("completed_requested") is True, f"{path}: incomplete chain")
        require(value.get("achieved_chain_correct") is True, f"{path}: final correctness failed")
        oracle({"expected": value.get("expected_result"),
                "decrypted": value.get("decrypted_result"),
                "correct": value.get("achieved_chain_correct")}, f"{path}.final")
        for field in ("entries", "refresh_checks"):
            entries = value.get(field)
            require(isinstance(entries, list) and len(entries) == operations,
                    f"{path}.{field}: missing operation/refresh oracle checks")
            if isinstance(entries, list):
                for index, item in enumerate(entries, start=1):
                    oracle(item, f"{path}.{field}[{index}]")
                    item = item if isinstance(item, dict) else {}
                    require(type(item.get("operation_index")) is int
                            and item["operation_index"] == index,
                            f"{path}.{field}[{index}]: non-sequential operation index")

    chain(report.get("operation_chain"), "operation_chain", requested_operations)
    statistical = mapping(report.get("statistical_test"), "statistical_test")
    require(statistical.get("enabled") is True, "statistical_test: not enabled")
    for field, expected in (("successes", trials), ("trials", trials),
                            ("operations_per_trial", operations_per_trial),
                            ("real_refreshes", trials * operations_per_trial)):
        require(integer(statistical.get(field)) and statistical[field] == expected,
                f"statistical_test.{field}: incomplete verification")
    entries = statistical.get("entries")
    require(isinstance(entries, list) and len(entries) == trials,
            "statistical_test.entries: missing trials")
    if isinstance(entries, list):
        for index, entry in enumerate(entries, start=1):
            chain(entry, f"statistical_test.entries[{index}]", operations_per_trial)
            require(isinstance(entry, dict) and type(entry.get("trial_index")) is int
                    and entry["trial_index"] == index, "statistical_test: non-sequential trial index")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--config", default="secure_128_deep")
    parser.add_argument("--requested-operations", type=int, default=1)
    args = parser.parse_args()
    try:
        payload = json.loads(args.report.read_text())
    except (OSError, ValueError) as error:
        print(f"Real-refresh evidence FAILED: {error}", file=sys.stderr)
        return 1
    errors = validate_report(payload, config=args.config,
                             requested_operations=args.requested_operations)
    if errors:
        print("Real-refresh evidence FAILED:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print("Real-refresh evidence PASSED: every operation and refresh has a matching plaintext oracle")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
