#!/usr/bin/env python3
"""Run NINE65 v6 and v7 on one machine under an explicit shared tuple.

The runner compares the v6 `secure_128` tuple against v7's comparison-only
`v6_compat_4096` tuple:

    N = 4096
    primes = [998244353, 985661441, 754974721]
    t = 65537
    eta = 3

Security ranking is disabled for this tuple. The purpose is implementation-path
regression analysis under identical arithmetic dimensions, not a production
security claim. All timings and statistics remain integer nanoseconds.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import platform
import subprocess
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable

V7_ROOT = pathlib.Path(__file__).resolve().parents[1]
PARAMETERS = {
    "n": 4096,
    "primes": [998_244_353, 985_661_441, 754_974_721],
    "plaintext_modulus": 65_537,
    "eta": 3,
}
V6_OPERATION_MAP = {
    "encrypt_us": "encrypt",
    "decrypt_us": "decrypt",
    "add_us": "add_ct",
    "sub_us": "sub_ct",
    "negate_us": "negate_ct",
    "add_plain_us": "add_plain",
    "mul_plain_us": "mul_plain",
    "mul_us": "mul_ct",
}


@dataclass(frozen=True)
class RunResult:
    label: str
    repetition: int
    command: list[str]
    returncode: int
    duration_ns: int
    stdout_path: str
    stderr_path: str
    json_path: str
    parsed: dict[str, Any] | None
    parse_error: str | None


def run(command: list[str], cwd: pathlib.Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)


def command_output(command: list[str], cwd: pathlib.Path) -> str:
    try:
        return subprocess.check_output(
            command,
            cwd=cwd,
            text=True,
            stderr=subprocess.STDOUT,
        ).strip()
    except (OSError, subprocess.CalledProcessError) as error:
        output = getattr(error, "output", "")
        return output.strip() if output else "unavailable"


def git_output(root: pathlib.Path, *arguments: str) -> str:
    return command_output(["git", *arguments], root)


def canonical_hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def hardware_metadata() -> dict[str, object]:
    memory_total = "unavailable"
    meminfo = pathlib.Path("/proc/meminfo")
    if meminfo.exists():
        for line in meminfo.read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                memory_total = line.split(":", 1)[1].strip()
                break
    return {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "logical_cpus": os.cpu_count(),
        "memory_total": memory_total,
        "kernel": command_output(["uname", "-a"], V7_ROOT),
        "lscpu": command_output(["lscpu"], V7_ROOT),
    }


def exact_log_q_bits(primes: Iterable[int]) -> int:
    product = 1
    for prime in primes:
        product *= prime
    return product.bit_length()


def build(
    label: str,
    root: pathlib.Path,
    command: list[str],
    output_dir: pathlib.Path,
) -> dict[str, object]:
    started = time.perf_counter_ns()
    completed = run(command, root)
    duration_ns = time.perf_counter_ns() - started
    log_dir = output_dir / "build"
    log_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = log_dir / f"{label}.stdout.log"
    stderr_path = log_dir / f"{label}.stderr.log"
    stdout_path.write_text(completed.stdout, encoding="utf-8")
    stderr_path.write_text(completed.stderr, encoding="utf-8")
    return {
        "label": label,
        "root": str(root),
        "command": command,
        "duration_ns": duration_ns,
        "returncode": completed.returncode,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
    }


def parse_json(path: pathlib.Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.exists():
        return None, "output JSON missing"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return None, str(error)
    if not isinstance(value, dict):
        return None, "top-level JSON is not an object"
    return value, None


def execute_case(
    label: str,
    repetition: int,
    root: pathlib.Path,
    command: list[str],
    result_path: pathlib.Path,
    output_dir: pathlib.Path,
) -> RunResult:
    log_dir = output_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    result_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter_ns()
    completed = run(command, root)
    duration_ns = time.perf_counter_ns() - started
    stdout_path = log_dir / f"{label}-{repetition:03d}.stdout.log"
    stderr_path = log_dir / f"{label}-{repetition:03d}.stderr.log"
    stdout_path.write_text(completed.stdout, encoding="utf-8")
    stderr_path.write_text(completed.stderr, encoding="utf-8")
    parsed, parse_error = parse_json(result_path)
    return RunResult(
        label=label,
        repetition=repetition,
        command=command,
        returncode=completed.returncode,
        duration_ns=duration_ns,
        stdout_path=str(stdout_path.relative_to(output_dir)),
        stderr_path=str(stderr_path.relative_to(output_dir)),
        json_path=str(result_path.relative_to(output_dir)),
        parsed=parsed,
        parse_error=parse_error,
    )


def verify_v6_metadata(payload: dict[str, Any]) -> list[str]:
    metadata = payload.get("metadata", {})
    failures: list[str] = []
    if metadata.get("n") != PARAMETERS["n"]:
        failures.append(f"v6 n={metadata.get('n')} expected {PARAMETERS['n']}")
    if metadata.get("t") != PARAMETERS["plaintext_modulus"]:
        failures.append(
            f"v6 t={metadata.get('t')} expected {PARAMETERS['plaintext_modulus']}"
        )
    return failures


def verify_v7_metadata(payload: dict[str, Any]) -> list[str]:
    metadata = payload.get("metadata", {})
    checks = {
        "n": PARAMETERS["n"],
        "rns_primes": PARAMETERS["primes"],
        "plaintext_modulus": PARAMETERS["plaintext_modulus"],
        "eta": PARAMETERS["eta"],
    }
    failures = []
    for field, expected in checks.items():
        if metadata.get(field) != expected:
            failures.append(f"v7 {field}={metadata.get(field)!r} expected {expected!r}")
    return failures


def bool_map(value: object) -> dict[str, bool]:
    if not isinstance(value, dict):
        return {}
    return {key: item for key, item in value.items() if isinstance(key, str) and isinstance(item, bool)}


def normalized_records(
    results: list[RunResult],
    hardware_fingerprint: str,
    v6_commit: str,
    v7_commit: str,
) -> list[dict[str, Any]]:
    samples: dict[tuple[str, str], list[int]] = defaultdict(list)
    trials: dict[tuple[str, str], int] = defaultdict(int)
    failures: dict[tuple[str, str], int] = defaultdict(int)
    sources: dict[tuple[str, str], list[str]] = defaultdict(list)

    for result in results:
        payload = result.parsed
        if payload is None:
            continue
        if result.label == "v6-legacy":
            operations = payload.get("operations", {})
            depth_correct = bool(payload.get("depth_chain", {}).get("correct", False))
            for source_name, operation in V6_OPERATION_MAP.items():
                value = operations.get(source_name)
                if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                    continue
                key = (result.label, operation)
                samples[key].append(value * 1000)
                trials[key] += 1
                failures[key] += 0 if depth_correct else 1
                sources[key].append(result.json_path)
        elif result.label == "v7-comparative":
            operations_by_path = payload.get("operations_ns", {})
            correctness_by_path = payload.get("correctness", {})
            for path_name in ("legacy", "dual_rns"):
                operations = operations_by_path.get(path_name, {})
                correctness = bool_map(correctness_by_path.get(path_name, {}))
                implementation = "v7-legacy" if path_name == "legacy" else "v7-dual-rns"
                for operation, value in operations.items():
                    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                        continue
                    key = (implementation, operation)
                    samples[key].append(value)
                    trials[key] += 1
                    failures[key] += 0 if correctness.get(operation, False) else 1
                    sources[key].append(result.json_path)

    records: list[dict[str, Any]] = []
    log_q_bits = exact_log_q_bits(PARAMETERS["primes"])
    for (implementation, operation), values in sorted(samples.items()):
        is_dual = implementation == "v7-dual-rns"
        version = v6_commit if implementation == "v6-legacy" else v7_commit
        records.append(
            {
                "schema": "fhe-comparison-record-v1",
                "implementation": implementation,
                "version": version,
                "operation": operation,
                "samples_ns": values,
                "correctness": {
                    "trials": trials[(implementation, operation)],
                    "failures": failures[(implementation, operation)],
                    "scope": "per-run operation check for v7; final-chain check for v6",
                },
                "compatibility": {
                    "scheme": "BFV-DualRNS" if is_dual else "BFV-legacy-single-modulus",
                    "plaintext_semantics": "scalar-mod-t",
                    "target_security_bits": 0,
                    "security_estimator": "comparison-only-parameter-shape",
                    "n": PARAMETERS["n"],
                    "log_q_bits": log_q_bits,
                    "plaintext_modulus": PARAMETERS["plaintext_modulus"],
                    "slots": 1,
                    "refresh_kind": "none",
                    "hardware_fingerprint": hardware_fingerprint,
                    "threads": 1,
                    "build_profile": "release",
                    "sample_policy": "repeated-process integer average",
                },
                "provenance": {
                    "raw_artifacts": sources[(implementation, operation)],
                    "parameter_tuple": PARAMETERS,
                    "security_ranking_allowed": False,
                    "note": (
                        "v6 and v7 legacy records are rankable for implementation regression. "
                        "The v7 DualRNS path is retained as a separate scheme group."
                    ),
                },
            }
        )
    return records


def serialize_run(result: RunResult) -> dict[str, object]:
    return {
        "label": result.label,
        "repetition": result.repetition,
        "command": result.command,
        "returncode": result.returncode,
        "duration_ns": result.duration_ns,
        "stdout_path": result.stdout_path,
        "stderr_path": result.stderr_path,
        "json_path": result.json_path,
        "parse_error": result.parse_error,
        "reported_schema": result.parsed.get("schema") if result.parsed else None,
        "reported_status": result.parsed.get("status") if result.parsed else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--v6-root", type=pathlib.Path, required=True)
    parser.add_argument("--v7-root", type=pathlib.Path, default=V7_ROOT)
    parser.add_argument("--output-dir", type=pathlib.Path, required=True)
    parser.add_argument("--repetitions", type=int, default=7)
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--mul-iterations", type=int, default=10)
    parser.add_argument("--ct-mul-depth", type=int, default=8)
    parser.add_argument("--v6-max-depth", type=int, default=8)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args()

    if min(
        args.repetitions,
        args.iterations,
        args.mul_iterations,
        args.ct_mul_depth,
        args.v6_max_depth,
    ) < 1:
        raise SystemExit("counts and depths must be positive")

    v6_root = args.v6_root.resolve()
    v7_root = args.v7_root.resolve()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    for root, label in ((v6_root, "v6"), (v7_root, "v7")):
        if not (root / "Cargo.toml").exists():
            raise SystemExit(f"{label} Cargo.toml missing under {root}")

    builds: list[dict[str, object]] = []
    if not args.skip_build:
        builds.append(
            build(
                "v6",
                v6_root,
                [
                    "cargo",
                    "build",
                    "--release",
                    "-p",
                    "nine65",
                    "--bin",
                    "nine65_bench",
                    "--features",
                    "serde",
                ],
                output_dir,
            )
        )
        builds.append(
            build(
                "v7",
                v7_root,
                [
                    "cargo",
                    "build",
                    "--release",
                    "-p",
                    "nine65",
                    "--bin",
                    "cram_comparative_probe",
                    "--features",
                    "serde,allow_insecure",
                ],
                output_dir,
            )
        )
        if any(item["returncode"] != 0 for item in builds):
            (output_dir / "build_manifest.json").write_text(
                json.dumps(builds, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            return 2

    v6_binary = v6_root / "target" / "release" / "nine65_bench"
    v7_binary = v7_root / "target" / "release" / "cram_comparative_probe"
    if not v6_binary.exists() or not v7_binary.exists():
        raise SystemExit("comparison binary missing after build")

    results: list[RunResult] = []
    metadata_failures: list[str] = []
    for repetition in range(args.repetitions):
        seed = args.seed + repetition
        v6_json = output_dir / "raw" / f"v6-{repetition:03d}.json"
        v6_command = [
            str(v6_binary),
            "--config",
            "secure_128",
            "--max-depth",
            str(args.v6_max_depth),
            "--a",
            "8",
            "--b",
            "8",
            "--output",
            str(v6_json),
        ]
        v6_result = execute_case(
            "v6-legacy",
            repetition,
            v6_root,
            v6_command,
            v6_json,
            output_dir,
        )
        results.append(v6_result)
        if v6_result.parsed:
            metadata_failures.extend(verify_v6_metadata(v6_result.parsed))

        v7_json = output_dir / "raw" / f"v7-{repetition:03d}.json"
        v7_command = [
            str(v7_binary),
            "--config",
            "v6_compat_4096",
            "--iterations",
            str(args.iterations),
            "--mul-iterations",
            str(args.mul_iterations),
            "--ct-mul-depth",
            str(args.ct_mul_depth),
            "--seed",
            str(seed),
            "--a",
            "8",
            "--b",
            "8",
            "--output",
            str(v7_json),
        ]
        v7_result = execute_case(
            "v7-comparative",
            repetition,
            v7_root,
            v7_command,
            v7_json,
            output_dir,
        )
        results.append(v7_result)
        if v7_result.parsed:
            metadata_failures.extend(verify_v7_metadata(v7_result.parsed))

    hardware = hardware_metadata()
    fingerprint = canonical_hash(hardware)
    v6_commit = git_output(v6_root, "rev-parse", "HEAD")
    v7_commit = git_output(v7_root, "rev-parse", "HEAD")
    records = normalized_records(results, fingerprint, v6_commit, v7_commit)
    record_set = {
        "schema": "fhe-comparison-record-set-v1",
        "records": records,
        "hardware": hardware,
        "parameter_contract": PARAMETERS,
    }
    record_path = output_dir / "comparison_records.json"
    record_path.write_text(
        json.dumps(record_set, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    comparator = v7_root / "scripts" / "cram_compare_results.py"
    comparison_path = output_dir / "comparison_analysis.json"
    comparison_process = run(
        [
            "python3",
            str(comparator),
            str(record_path),
            "--output",
            str(comparison_path),
        ],
        v7_root,
    )
    (output_dir / "comparison.stdout.log").write_text(
        comparison_process.stdout,
        encoding="utf-8",
    )
    (output_dir / "comparison.stderr.log").write_text(
        comparison_process.stderr,
        encoding="utf-8",
    )

    run_failures = [
        serialize_run(result)
        for result in results
        if result.returncode != 0 or result.parsed is None
    ]
    manifest = {
        "schema": "nine65-v6-v7-same-machine-comparison-v1",
        "v6_root": str(v6_root),
        "v7_root": str(v7_root),
        "v6_commit": v6_commit,
        "v7_commit": v7_commit,
        "hardware_fingerprint": fingerprint,
        "parameter_contract": PARAMETERS,
        "builds": builds,
        "runs": [serialize_run(result) for result in results],
        "metadata_failures": sorted(set(metadata_failures)),
        "run_failures": run_failures,
        "record_count": len(records),
        "comparison_returncode": comparison_process.returncode,
        "security_ranking_allowed": False,
    }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"manifest": str(manifest_path), "record_count": len(records)}, indent=2))

    if metadata_failures or run_failures or comparison_process.returncode != 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
