#!/usr/bin/env python3
"""Run a pinned, integer-only external FHE benchmark matrix.

Each implementation command must print one JSON object with:
  implementation, commit, parameter_id, mode, records
where every record contains operation, median_ns, p95_ns, bytes, and trials.

Missing commands are recorded as unavailable. No comparison value is fabricated.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
from pathlib import Path
from typing import Any

IMPLEMENTATIONS = (
    ("nine65", "NINE65_BENCH_CMD"),
    ("microsoft-seal", "SEAL_BENCH_CMD"),
    ("openfhe", "OPENFHE_BENCH_CMD"),
    ("lattigo", "LATTIGO_BENCH_CMD"),
    ("tfhe-rs", "TFHERS_BENCH_CMD"),
)

INTEGER_FIELDS = ("median_ns", "p95_ns", "bytes", "trials")
REQUIRED_RECORD_FIELDS = ("operation", *INTEGER_FIELDS)


def validate_record(record: dict[str, Any]) -> None:
    for field in REQUIRED_RECORD_FIELDS:
        if field not in record:
            raise ValueError(f"missing record field: {field}")
    if not isinstance(record["operation"], str) or not record["operation"]:
        raise ValueError("operation must be a non-empty string")
    for field in INTEGER_FIELDS:
        value = record[field]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"{field} must be a nonnegative integer")


def validate_payload(payload: dict[str, Any], expected_name: str) -> None:
    required = ("implementation", "commit", "parameter_id", "mode", "records")
    for field in required:
        if field not in payload:
            raise ValueError(f"missing payload field: {field}")
    if payload["implementation"] != expected_name:
        raise ValueError(
            f"implementation mismatch: expected {expected_name}, got {payload['implementation']}"
        )
    for field in ("commit", "parameter_id", "mode"):
        if not isinstance(payload[field], str) or not payload[field]:
            raise ValueError(f"{field} must be a non-empty string")
    if not isinstance(payload["records"], list) or not payload["records"]:
        raise ValueError("records must be a non-empty list")
    for record in payload["records"]:
        if not isinstance(record, dict):
            raise ValueError("each record must be an object")
        validate_record(record)


def run_command(name: str, command: str, timeout_seconds: int) -> dict[str, Any]:
    completed = subprocess.run(
        shlex.split(command),
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
    )
    if completed.returncode != 0:
        return {
            "implementation": name,
            "status": "failed",
            "returncode": completed.returncode,
            "stderr": completed.stderr[-4096:],
        }
    try:
        payload = json.loads(completed.stdout)
        if not isinstance(payload, dict):
            raise ValueError("top-level JSON must be an object")
        validate_payload(payload, name)
    except (json.JSONDecodeError, ValueError) as exc:
        return {
            "implementation": name,
            "status": "invalid",
            "error": str(exc),
            "stdout": completed.stdout[-4096:],
        }
    return {"implementation": name, "status": "ok", "payload": payload}


def self_test_payload() -> dict[str, Any]:
    payload = {
        "implementation": "nine65",
        "commit": "self-test",
        "parameter_id": "test-only",
        "mode": "public-evaluator",
        "records": [
            {
                "operation": "add",
                "median_ns": 1,
                "p95_ns": 1,
                "bytes": 1,
                "trials": 1,
            }
        ],
    }
    validate_payload(payload, "nine65")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="artifacts/external_fhe_matrix.json")
    parser.add_argument("--timeout-seconds", type=int, default=3600)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.timeout_seconds < 1:
        raise SystemExit("timeout must be positive")

    if args.self_test:
        print(json.dumps(self_test_payload(), sort_keys=True))
        return 0

    results: list[dict[str, Any]] = []
    for name, env_name in IMPLEMENTATIONS:
        command = os.environ.get(env_name)
        if not command:
            results.append(
                {
                    "implementation": name,
                    "status": "unavailable",
                    "required_env": env_name,
                }
            )
            continue
        results.append(run_command(name, command, args.timeout_seconds))

    output = {
        "schema": 1,
        "unit_policy": {
            "latency": "integer nanoseconds",
            "size": "integer bytes",
            "floating_point_allowed": False,
        },
        "results": results,
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    failures = [r for r in results if r["status"] in {"failed", "invalid"}]
    print(json.dumps(output, sort_keys=True))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
