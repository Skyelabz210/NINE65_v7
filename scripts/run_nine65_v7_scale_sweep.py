#!/usr/bin/env python3
"""Run the exact NINE65 comparative probe across parameter and workload scale.

Depth stops and arithmetic mismatches are preserved per case. The runner fails
for missing artifacts, process failures, or failed single-operation correctness.
A depth stop is reported as an observation unless `--require-depth-complete` is
selected.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import platform
import shlex
import subprocess
import time
from dataclasses import asdict, dataclass
from itertools import product
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
BINARY = ROOT / "target" / "release" / "cram_comparative_probe"


@dataclass(frozen=True)
class Profile:
    configs: tuple[str, ...]
    seeds: tuple[int, ...]
    iterations: int
    mul_iterations: int
    ct_mul_depth: int


PROFILES = {
    "quick": Profile(
        configs=("v6_compat_4096", "secure_128"),
        seeds=(42,),
        iterations=2,
        mul_iterations=1,
        ct_mul_depth=2,
    ),
    "standard": Profile(
        configs=(
            "v6_compat_4096",
            "secure_128",
            "secure_128_deep",
            "secure_192",
            "secure_256",
        ),
        seeds=(1, 42, 99),
        iterations=20,
        mul_iterations=3,
        ct_mul_depth=8,
    ),
    "endurance": Profile(
        configs=(
            "v6_compat_4096",
            "secure_128",
            "secure_128_deep",
            "secure_192",
            "secure_256",
        ),
        seeds=(1, 7, 42, 99, 2026),
        iterations=100,
        mul_iterations=10,
        ct_mul_depth=16,
    ),
}


@dataclass(frozen=True)
class Case:
    case_id: str
    config: str
    seed: int
    iterations: int
    mul_iterations: int
    ct_mul_depth: int
    a: int
    b: int


def parse_csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


def parse_int_csv(value: str) -> tuple[int, ...]:
    return tuple(int(item.strip()) for item in value.split(",") if item.strip())


def command_output(command: list[str]) -> str:
    try:
        return subprocess.check_output(
            command,
            cwd=ROOT,
            text=True,
            stderr=subprocess.STDOUT,
        ).strip()
    except (OSError, subprocess.CalledProcessError) as error:
        output = getattr(error, "output", "")
        return output.strip() if output else "unavailable"


def git_output(*arguments: str) -> str:
    return command_output(["git", *arguments])


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
        "kernel": command_output(["uname", "-a"]),
        "lscpu": command_output(["lscpu"]),
    }


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def build_probe() -> dict[str, object]:
    command = [
        "cargo",
        "build",
        "--release",
        "-p",
        "nine65",
        "--bin",
        "cram_comparative_probe",
        "--features",
        "serde,allow_insecure",
    ]
    started = time.perf_counter_ns()
    completed = run(command)
    return {
        "command": command,
        "duration_ns": time.perf_counter_ns() - started,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def make_cases(args: argparse.Namespace) -> list[Case]:
    profile = PROFILES[args.profile]
    configs = parse_csv(args.configs) if args.configs else profile.configs
    seeds = parse_int_csv(args.seeds) if args.seeds else profile.seeds
    iterations = args.iterations or profile.iterations
    mul_iterations = args.mul_iterations or profile.mul_iterations
    depth = args.ct_mul_depth or profile.ct_mul_depth
    cases = []
    for index, (config, seed) in enumerate(product(configs, seeds)):
        case_id = f"{index:04d}-{config}-s{seed}-i{iterations}-m{mul_iterations}-d{depth}"
        cases.append(
            Case(
                case_id=case_id,
                config=config,
                seed=seed,
                iterations=iterations,
                mul_iterations=mul_iterations,
                ct_mul_depth=depth,
                a=args.a,
                b=args.b,
            )
        )
    return cases


def load_result(path: pathlib.Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.exists():
        return None, "result missing"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return None, str(error)
    if not isinstance(value, dict):
        return None, "top-level result is not an object"
    return value, None


def execute(case: Case, output_dir: pathlib.Path) -> dict[str, object]:
    result_path = output_dir / "cases" / f"{case.case_id}.json"
    stdout_path = output_dir / "logs" / f"{case.case_id}.stdout.log"
    stderr_path = output_dir / "logs" / f"{case.case_id}.stderr.log"
    result_path.parent.mkdir(parents=True, exist_ok=True)
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    command = [
        str(BINARY),
        "--config",
        case.config,
        "--iterations",
        str(case.iterations),
        "--mul-iterations",
        str(case.mul_iterations),
        "--ct-mul-depth",
        str(case.ct_mul_depth),
        "--seed",
        str(case.seed),
        "--a",
        str(case.a),
        "--b",
        str(case.b),
        "--output",
        str(result_path),
    ]
    started = time.perf_counter_ns()
    completed = run(command)
    duration_ns = time.perf_counter_ns() - started
    stdout_path.write_text(completed.stdout, encoding="utf-8")
    stderr_path.write_text(completed.stderr, encoding="utf-8")
    payload, parse_error = load_result(result_path)
    depth = payload.get("ct_mul_depth", {}) if payload else {}
    depth_complete = bool(
        isinstance(depth, dict)
        and depth.get("completed") == depth.get("requested")
        and depth.get("all_completed_entries_correct") is True
        and depth.get("first_error") is None
    )
    return {
        "case": asdict(case),
        "command": command,
        "command_display": shlex.join(command),
        "returncode": completed.returncode,
        "duration_ns": duration_ns,
        "result_path": str(result_path.relative_to(output_dir)),
        "stdout_path": str(stdout_path.relative_to(output_dir)),
        "stderr_path": str(stderr_path.relative_to(output_dir)),
        "parse_error": parse_error,
        "schema": payload.get("schema") if payload else None,
        "status": payload.get("status") if payload else None,
        "operation_correctness_pass": payload.get("status") == "PASS" if payload else False,
        "depth_complete": depth_complete,
        "depth_completed": depth.get("completed") if isinstance(depth, dict) else None,
        "depth_requested": depth.get("requested") if isinstance(depth, dict) else None,
        "depth_first_error": depth.get("first_error") if isinstance(depth, dict) else None,
    }


def summarize(records: list[dict[str, object]]) -> dict[str, int]:
    summary = {
        "cases": len(records),
        "process_failures": 0,
        "missing_or_invalid_results": 0,
        "operation_correctness_failures": 0,
        "depth_complete": 0,
        "depth_stops": 0,
    }
    for record in records:
        if record["returncode"] != 0:
            summary["process_failures"] += 1
        if record["parse_error"] or record["schema"] != "nine65-comparative-probe-v1":
            summary["missing_or_invalid_results"] += 1
        if not record["operation_correctness_pass"]:
            summary["operation_correctness_failures"] += 1
        if record["depth_complete"]:
            summary["depth_complete"] += 1
        else:
            summary["depth_stops"] += 1
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", choices=tuple(PROFILES), default="quick")
    parser.add_argument("--configs", default="")
    parser.add_argument("--seeds", default="")
    parser.add_argument("--iterations", type=int, default=0)
    parser.add_argument("--mul-iterations", type=int, default=0)
    parser.add_argument("--ct-mul-depth", type=int, default=0)
    parser.add_argument("--a", type=int, default=8)
    parser.add_argument("--b", type=int, default=8)
    parser.add_argument("--output-dir", type=pathlib.Path)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--require-depth-complete", action="store_true")
    args = parser.parse_args()

    for name in ("iterations", "mul_iterations", "ct_mul_depth"):
        value = getattr(args, name)
        if value < 0:
            raise SystemExit(f"--{name.replace('_', '-')} must be nonnegative")

    created = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_dir = args.output_dir or ROOT / "artifacts" / "v7_scale_sweep" / created
    output_dir.mkdir(parents=True, exist_ok=True)

    build: dict[str, object] = {"skipped": True}
    if not args.skip_build:
        build = build_probe()
        (output_dir / "build.json").write_text(
            json.dumps(build, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if build["returncode"] != 0:
            print(json.dumps(build, indent=2, sort_keys=True))
            return 2
    if not BINARY.exists():
        raise SystemExit(f"probe binary missing: {BINARY}")

    cases = make_cases(args)
    records = [execute(case, output_dir) for case in cases]
    summary = summarize(records)
    hardware = hardware_metadata()
    manifest = {
        "schema": "nine65-v7-scale-sweep-v1",
        "created_utc": created,
        "repository": git_output("config", "--get", "remote.origin.url"),
        "commit": git_output("rev-parse", "HEAD"),
        "branch": git_output("rev-parse", "--abbrev-ref", "HEAD"),
        "dirty": git_output("status", "--porcelain") != "",
        "profile": args.profile,
        "hardware": hardware,
        "hardware_fingerprint": canonical_hash(hardware),
        "build": build,
        "summary": summary,
        "records": records,
        "depth_policy": (
            "required" if args.require_depth_complete else "observational"
        ),
    }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"manifest": str(manifest_path), "summary": summary}, indent=2))

    hard_failure = (
        summary["process_failures"] > 0
        or summary["missing_or_invalid_results"] > 0
        or summary["operation_correctness_failures"] > 0
    )
    if args.require_depth_complete and summary["depth_stops"] > 0:
        hard_failure = True
    return 1 if hard_failure else 0


if __name__ == "__main__":
    raise SystemExit(main())
