#!/usr/bin/env python3
"""Normalize repeated `nine65_bench` JSON files into strict comparison records."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
from collections import defaultdict
from typing import Any

OPERATION_MAP = {
    "encrypt_us": "encrypt",
    "decrypt_us": "decrypt",
    "add_us": "add_ct",
    "sub_us": "sub_ct",
    "negate_us": "negate_ct",
    "add_plain_us": "add_plain",
    "mul_plain_us": "mul_plain",
    "mul_us": "mul_ct",
}


def load(path: pathlib.Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON object required: {path}")
    return value


def canonical_hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("inputs", nargs="+", type=pathlib.Path)
    parser.add_argument("--implementation", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--scheme", required=True)
    parser.add_argument("--plaintext-semantics", default="scalar-mod-t")
    parser.add_argument("--security-estimator", required=True)
    parser.add_argument("--log-q-bits", type=int, required=True)
    parser.add_argument("--hardware-json", type=pathlib.Path, required=True)
    parser.add_argument("--threads", type=int, required=True)
    parser.add_argument("--build-profile", default="release")
    parser.add_argument("--sample-policy", default="repeated-nine65-bench-reported-average")
    parser.add_argument("--slots", type=int, default=1)
    parser.add_argument("--repository", default="")
    parser.add_argument("--commit", default="")
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()

    hardware = load(args.hardware_json)
    hardware_fingerprint = canonical_hash(hardware)
    samples: dict[str, list[int]] = defaultdict(list)
    trials: dict[str, int] = defaultdict(int)
    failures: dict[str, int] = defaultdict(int)
    config_signature: tuple[object, ...] | None = None
    sources: list[str] = []

    for path in args.inputs:
        payload = load(path)
        metadata = payload.get("metadata", {})
        signature = (
            metadata.get("config"),
            metadata.get("n"),
            metadata.get("t"),
            metadata.get("security_bits"),
        )
        if config_signature is None:
            config_signature = signature
        elif signature != config_signature:
            raise ValueError(f"input configuration mismatch: {path}: {signature} != {config_signature}")
        operations = payload.get("operations", {})
        depth_correct = bool(payload.get("depth_chain", {}).get("correct", False))
        for source_name, normalized_name in OPERATION_MAP.items():
            value = operations.get(source_name)
            if not isinstance(value, int) or value < 0:
                continue
            samples[normalized_name].append(value * 1000)
            trials[normalized_name] += 1
            if not depth_correct:
                failures[normalized_name] += 1
        sources.append(str(path))

    if config_signature is None:
        raise ValueError("no inputs")
    config_name, n, plaintext_modulus, target_security_bits = config_signature
    records = []
    for operation in sorted(samples):
        records.append(
            {
                "schema": "fhe-comparison-record-v1",
                "implementation": args.implementation,
                "version": args.version,
                "operation": operation,
                "samples_ns": samples[operation],
                "correctness": {
                    "trials": trials[operation],
                    "failures": failures[operation],
                    "scope": "depth-chain-final-check-per-benchmark-run",
                },
                "compatibility": {
                    "scheme": args.scheme,
                    "plaintext_semantics": args.plaintext_semantics,
                    "target_security_bits": target_security_bits,
                    "security_estimator": args.security_estimator,
                    "n": n,
                    "log_q_bits": args.log_q_bits,
                    "plaintext_modulus": plaintext_modulus,
                    "slots": args.slots,
                    "refresh_kind": "none",
                    "hardware_fingerprint": hardware_fingerprint,
                    "threads": args.threads,
                    "build_profile": args.build_profile,
                    "sample_policy": args.sample_policy,
                },
                "provenance": {
                    "repository": args.repository,
                    "commit": args.commit,
                    "config": config_name,
                    "raw_artifacts": sources,
                    "normalization_note": (
                        "Each sample is an integer microsecond average reported by one nine65_bench run, converted to nanoseconds."
                    ),
                },
            }
        )

    output = {
        "schema": "fhe-comparison-record-set-v1",
        "records": records,
        "hardware": hardware,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "records": len(records)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
