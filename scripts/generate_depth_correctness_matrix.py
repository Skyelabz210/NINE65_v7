#!/usr/bin/env python3
"""
Generate depth-correctness matrix from depth benchmark output.

This script parses the output from depth benchmark tests and generates
a structured JSON matrix showing correctness at each depth level.
"""

import json
import pathlib
import re
import subprocess
import sys
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]


class EvidenceError(RuntimeError):
    """Raised when depth evidence is absent, contradictory, or truncated."""


def run_depth_benchmarks():
    """Run benchmarks and fail if any configuration lacks complete evidence."""
    commands = {
        "secure_128": [
            "cargo", "test", "--locked", "--offline", "--release", "-p", "nine65",
            "ops::gso_fhe::depth_benchmarks::benchmark_symmetric_max_depth_secure_128",
            "--", "--nocapture",
        ],
        "secure_192": [
            "cargo", "test", "--locked", "--offline", "--release", "-p", "nine65",
            "ops::gso_fhe::depth_benchmarks::benchmark_symmetric_max_depth_secure_192",
            "--", "--nocapture",
        ],
    }
    results = {}
    failures = []

    for config, command in commands.items():
        print(f"Running depth benchmark for {config}...")
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                check=False,
            )
        except OSError as error:
            failures.append(f"{config}: could not execute benchmark: {error}")
            continue

        if result.returncode != 0:
            failures.append(
                f"{config}: benchmark exited {result.returncode}: "
                f"{result.stderr.strip()}"
            )
            continue
        try:
            results[config] = parse_benchmark_output(result.stdout, config)
        except EvidenceError as error:
            failures.append(str(error))

    if failures:
        raise EvidenceError("depth evidence failed closed:\n- " + "\n- ".join(failures))
    if set(results) != set(commands):
        raise EvidenceError("depth benchmark executed zero of the required configurations")
    return results


def _parse_explicit_plaintext_check(line: str, config: str):
    lower = line.lower()
    if "plaintext" not in lower:
        return None

    step_match = re.search(r"\bstep\s*(?:=|:|\s)\s*(\d+)\b", lower)
    if not step_match:
        return None

    got_match = re.search(
        r"\b(?:got|actual|observed|plaintext)\s*(?:=|:)\s*(-?\d+)\b",
        lower,
    )
    expected_match = re.search(
        r"\bexpected\s*(?:=|:)\s*(-?\d+)\b",
        lower,
    )
    equal_match = re.search(
        r"\b(?:plaintext_equal|equal)\s*(?:=|:)\s*(true|false)\b",
        lower,
    )

    if got_match and expected_match:
        got = int(got_match.group(1))
        expected = int(expected_match.group(1))
        equal = got == expected
        if equal_match is not None:
            marker = equal_match.group(1) == "true"
            if marker != equal:
                raise EvidenceError(
                    f"{config}: step {step_match.group(1)} equality marker contradicts "
                    "its explicit plaintext values"
                )
    else:
        raise EvidenceError(
            f"{config}: step {step_match.group(1)} needs actual and expected plaintext values"
        )

    return {
        "step": int(step_match.group(1)),
        "got": got,
        "expected": expected,
        "plaintext_equal": equal,
    }


def parse_benchmark_output(output, config):
    """Require one explicit plaintext-equality record for every reported step."""
    max_depth = None
    total_collapses = None
    total_time = ""
    avg_time_per_mul = ""
    checks = {}

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        depth_match = re.search(r"MAX DEPTH:\s*(\d+)\b", line, re.IGNORECASE)
        if depth_match:
            parsed_depth = int(depth_match.group(1))
            if max_depth is not None and max_depth != parsed_depth:
                raise EvidenceError(f"{config}: contradictory MAX DEPTH markers")
            max_depth = parsed_depth

        collapse_match = re.search(r"Total collapses:\s*(\d+)\b", line)
        if collapse_match:
            total_collapses = int(collapse_match.group(1))

        time_match = re.search(r"Total time:\s*(.*)", line)
        if time_match:
            total_time = time_match.group(1).strip()

        average_match = re.search(r"Avg time/mul:\s*(.*)", line)
        if average_match:
            avg_time_per_mul = average_match.group(1).strip()

        check = _parse_explicit_plaintext_check(line, config)
        if check is not None:
            step = check["step"]
            if step < 1:
                raise EvidenceError(f"{config}: plaintext check has non-positive step {step}")
            previous = checks.get(step)
            if previous is not None and previous != check:
                raise EvidenceError(f"{config}: contradictory plaintext checks at step {step}")
            checks[step] = check

    if max_depth is None:
        raise EvidenceError(f"{config}: missing terminal MAX DEPTH marker")
    if max_depth <= 0:
        raise EvidenceError(f"{config}: benchmark executed zero plaintext-checkable cases")
    if not checks:
        raise EvidenceError(f"{config}: no explicit per-step plaintext checks were emitted")

    expected_steps = set(range(1, max_depth + 1))
    actual_steps = set(checks)
    if actual_steps != expected_steps:
        missing = sorted(expected_steps - actual_steps)
        unexpected = sorted(actual_steps - expected_steps)
        raise EvidenceError(
            f"{config}: truncated or overlong plaintext evidence; "
            f"missing={missing}, unexpected={unexpected}"
        )

    failed = [step for step in sorted(checks) if not checks[step]["plaintext_equal"]]
    if failed:
        raise EvidenceError(
            f"{config}: plaintext equality failed at steps {failed}; "
            "depth and collapse counters cannot override per-step results"
        )

    return {
        "max_depth_achieved": max_depth,
        "plaintext_check_count": len(checks),
        "plaintext_checks": [checks[step] for step in sorted(checks)],
        "correctness_verified": True,
        "total_collapses": total_collapses,
        "total_time": total_time,
        "avg_time_per_mul_ms": avg_time_per_mul,
    }


def generate_markdown_table(results):
    """Generate a table backed only by explicit plaintext checks."""
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    md_content = f"""# Depth-Correctness Matrix

Generated on {generated}

## Symmetric Mode Depth Verification

Correctness is the conjunction of explicit per-step plaintext-equality records. Maximum-depth and collapse counters are telemetry and never substitute for those records.

| Config | Max Depth | Plaintext Checks | Correctness | Collapses | Avg Time/Mul |
|--------|-----------|------------------|-------------|-----------|--------------|
"""
    for config, data in results.items():
        md_content += (
            f"| {config} | {data['max_depth_achieved']} | "
            f"{data['plaintext_check_count']} | PASS | "
            f"{data['total_collapses'] if data['total_collapses'] is not None else 'N/A'} | "
            f"{data['avg_time_per_mul_ms'] or 'N/A'} |\n"
        )
    md_content += """

## Fail-Closed Policy

A report is rejected when the terminal depth marker is missing, the executed depth is zero, any reported step lacks an explicit plaintext check, checks are duplicated with contradictory values, or any check is false.
"""
    return md_content


def main():
    print("Generating depth-correctness matrix from explicit benchmark evidence...")
    results = run_depth_benchmarks()
    if not results:
        raise EvidenceError("no benchmark results were collected")

    generated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    json_data = {
        "schema": 1,
        "generated_at": generated_at,
        "benchmark_type": "symmetric_max_depth",
        "correctness_policy": "all_explicit_per_step_plaintext_equalities_true",
        "results": results,
    }

    output_dir = ROOT / "docs"
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "DEPTH_CORRECTNESS_MATRIX.json").write_text(
        json.dumps(json_data, indent=2) + "\n",
        encoding="utf-8",
    )
    (output_dir / "DEPTH_CORRECTNESS_MATRIX.md").write_text(
        generate_markdown_table(results),
        encoding="utf-8",
    )

    print("Depth-correctness matrix generated:")
    print("- docs/DEPTH_CORRECTNESS_MATRIX.json")
    print("- docs/DEPTH_CORRECTNESS_MATRIX.md")
    for config, data in results.items():
        print(
            f"- {config}: depth={data['max_depth_achieved']}, "
            f"plaintext_checks={data['plaintext_check_count']}, PASS"
        )


if __name__ == '__main__':
    main()
