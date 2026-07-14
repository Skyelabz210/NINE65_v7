#!/usr/bin/env python3
"""Normalize and compare CRAM/NINE65 and external FHE benchmark results.

Only exactly compatible records are ranked. All statistics are integer or exact
rational values.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import pathlib
from collections import Counter, defaultdict
from itertools import combinations
from typing import Any, Iterable

COMPATIBILITY_FIELDS = (
    "scheme",
    "plaintext_semantics",
    "target_security_bits",
    "security_estimator",
    "n",
    "log_q_bits",
    "plaintext_modulus",
    "slots",
    "refresh_kind",
    "hardware_fingerprint",
    "threads",
    "build_profile",
    "sample_policy",
)


def canonical_hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def load_json(path: pathlib.Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"top-level JSON must be an object: {path}")
    return value


def exact_median(values: list[int]) -> dict[str, int]:
    ordered = sorted(values)
    count = len(ordered)
    if count == 0:
        return {"numerator": 0, "denominator": 1}
    midpoint = count // 2
    if count % 2:
        return {"numerator": ordered[midpoint], "denominator": 1}
    numerator = ordered[midpoint - 1] + ordered[midpoint]
    divisor = math.gcd(numerator, 2)
    return {"numerator": numerator // divisor, "denominator": 2 // divisor}


def nearest_rank(values: list[int], percentile: int) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    rank = (percentile * len(ordered) + 99) // 100
    return ordered[max(0, rank - 1)]


def metrics(samples: list[int], correctness: dict[str, int]) -> dict[str, object]:
    return {
        "samples": len(samples),
        "min_ns": min(samples) if samples else 0,
        "max_ns": max(samples) if samples else 0,
        "median_ns": exact_median(samples),
        "p95_ns": nearest_rank(samples, 95),
        "correctness": correctness,
    }


def reduced_ratio(left: dict[str, int], right: dict[str, int]) -> dict[str, int] | None:
    left_num = left["numerator"]
    left_den = left["denominator"]
    right_num = right["numerator"]
    right_den = right["denominator"]
    numerator = left_num * right_den
    denominator = left_den * right_num
    if denominator == 0:
        return None
    divisor = math.gcd(numerator, denominator)
    return {"numerator": numerator // divisor, "denominator": denominator // divisor}


def compatibility_key(record: dict[str, Any]) -> tuple[object, ...]:
    compatibility = record["compatibility"]
    return (record["operation"],) + tuple(compatibility[field] for field in COMPATIBILITY_FIELDS)


def validate_normalized(record: dict[str, Any], source: pathlib.Path) -> dict[str, Any]:
    if record.get("schema") != "fhe-comparison-record-v1":
        raise ValueError(f"unsupported comparison record schema: {source}")
    samples = record.get("samples_ns")
    if not isinstance(samples, list) or any(not isinstance(value, int) or value < 0 for value in samples):
        raise ValueError(f"samples_ns must contain nonnegative integers: {source}")
    compatibility = record.get("compatibility")
    if not isinstance(compatibility, dict):
        raise ValueError(f"compatibility object missing: {source}")
    missing = [field for field in COMPATIBILITY_FIELDS if field not in compatibility]
    if missing:
        raise ValueError(f"compatibility fields missing {missing}: {source}")
    record = dict(record)
    record["source_file"] = str(source)
    return record


def normalize_probe_manifest(path: pathlib.Path, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    hardware_fingerprint = canonical_hash(manifest.get("hardware", {}))
    commit = str(manifest.get("commit", "unknown"))
    records: list[dict[str, Any]] = []
    for matrix_record in manifest.get("records", []):
        relative = matrix_record.get("result_path")
        if not relative:
            continue
        result_path = path.parent / relative
        if not result_path.exists():
            continue
        result = load_json(result_path)
        if result.get("schema") != "nine65-cram-exploratory-probe-v1":
            continue
        metadata = result["metadata"]
        grouped_samples: dict[str, list[int]] = defaultdict(list)
        grouped_trials: Counter[str] = Counter()
        grouped_failures: Counter[str] = Counter()
        for trace in result.get("trace", []):
            operation = trace.get("operation")
            timing = trace.get("operation_ns")
            if not isinstance(operation, str) or not isinstance(timing, int):
                continue
            grouped_samples[operation].append(timing)
            grouped_trials[operation] += 1
            if trace.get("correct") is False or trace.get("operation_error"):
                grouped_failures[operation] += 1
        for operation, samples in grouped_samples.items():
            records.append(
                {
                    "schema": "fhe-comparison-record-v1",
                    "implementation": "NINE65",
                    "version": commit,
                    "operation": operation,
                    "samples_ns": samples,
                    "correctness": {
                        "trials": grouped_trials[operation],
                        "failures": grouped_failures[operation],
                    },
                    "compatibility": {
                        "scheme": "BFV-DualRNS",
                        "plaintext_semantics": "scalar-mod-t",
                        "target_security_bits": metadata.get("claimed_security_bits"),
                        "security_estimator": "config-claim-only",
                        "n": metadata.get("n"),
                        "log_q_bits": metadata.get("full_log_q_bits_upper_sum"),
                        "plaintext_modulus": metadata.get("plaintext_modulus"),
                        "slots": 1,
                        "refresh_kind": metadata.get("refresh_kind"),
                        "hardware_fingerprint": hardware_fingerprint,
                        "threads": 1,
                        "build_profile": "release",
                        "sample_policy": (
                            f"chain:{metadata.get('workload')}:"
                            f"refresh={metadata.get('refresh_mode')}:"
                            f"timing={metadata.get('refresh_timing')}"
                        ),
                    },
                    "provenance": {
                        "repository": manifest.get("repository"),
                        "commit": commit,
                        "command": matrix_record.get("command"),
                        "raw_artifact": str(result_path),
                        "matrix_manifest": str(path),
                    },
                    "source_file": str(result_path),
                }
            )
    return records


def load_records(path: pathlib.Path) -> list[dict[str, Any]]:
    payload = load_json(path)
    schema = payload.get("schema")
    if schema == "fhe-comparison-record-v1":
        return [validate_normalized(payload, path)]
    if schema == "nine65-cram-exploratory-matrix-v1":
        return normalize_probe_manifest(path, payload)
    if schema == "fhe-comparison-record-set-v1":
        records = payload.get("records", [])
        if not isinstance(records, list):
            raise ValueError(f"records must be a list: {path}")
        return [validate_normalized(record, path) for record in records]
    raise ValueError(f"unsupported input schema {schema!r}: {path}")


def differences(left: dict[str, Any], right: dict[str, Any]) -> list[str]:
    fields: list[str] = []
    if left["operation"] != right["operation"]:
        fields.append("operation")
    left_compatibility = left["compatibility"]
    right_compatibility = right["compatibility"]
    for field in COMPATIBILITY_FIELDS:
        if left_compatibility[field] != right_compatibility[field]:
            fields.append(field)
    return fields


def group_report(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[object, ...], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[compatibility_key(record)].append(record)
    reports: list[dict[str, Any]] = []
    for key, members in grouped.items():
        entries = []
        for record in members:
            entries.append(
                {
                    "implementation": record["implementation"],
                    "version": record["version"],
                    "source_file": record.get("source_file"),
                    "metrics": metrics(record["samples_ns"], record["correctness"]),
                    "provenance": record.get("provenance", {}),
                }
            )
        comparisons = []
        for left, right in combinations(entries, 2):
            left_median = left["metrics"]["median_ns"]
            right_median = right["metrics"]["median_ns"]
            ratio = reduced_ratio(left_median, right_median)
            comparisons.append(
                {
                    "left": f"{left['implementation']}@{left['version']}",
                    "right": f"{right['implementation']}@{right['version']}",
                    "left_over_right_median": ratio,
                    "ranking_allowed": True,
                    "correctness_gate": (
                        left["metrics"]["correctness"].get("failures", 0) == 0
                        and right["metrics"]["correctness"].get("failures", 0) == 0
                    ),
                }
            )
        compatibility = {field: key[index + 1] for index, field in enumerate(COMPATIBILITY_FIELDS)}
        reports.append(
            {
                "operation": key[0],
                "compatibility": compatibility,
                "record_count": len(members),
                "entries": entries,
                "comparisons": comparisons,
            }
        )
    return reports


def incompatibility_summary(records: list[dict[str, Any]]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for left, right in combinations(records, 2):
        for field in differences(left, right):
            counts[field] += 1
    return dict(sorted(counts.items()))


def discover_inputs(paths: Iterable[pathlib.Path]) -> list[pathlib.Path]:
    discovered: list[pathlib.Path] = []
    for path in paths:
        if path.is_dir():
            discovered.extend(sorted(path.rglob("*.json")))
        else:
            discovered.append(path)
    return discovered


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("inputs", nargs="+", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()

    input_files = discover_inputs(args.inputs)
    records: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for path in input_files:
        try:
            records.extend(load_records(path))
        except (OSError, ValueError, json.JSONDecodeError) as error:
            errors.append({"path": str(path), "error": str(error)})

    output = {
        "schema": "fhe-comparison-analysis-v1",
        "record_count": len(records),
        "input_errors": errors,
        "compatibility_rule": ["operation", *COMPATIBILITY_FIELDS],
        "groups": group_report(records),
        "incompatibility_dimension_counts": incompatibility_summary(records),
        "ranking_rule": "Only records in the same compatibility group may be ranked.",
    }
    rendered = json.dumps(output, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
