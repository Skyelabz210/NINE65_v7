#!/usr/bin/env python3
"""Build and execute the CRAM/NINE65 exploratory probe matrix.

Failures are preserved as evidence. The runner does not stop after the first
nonzero probe exit and never converts a failed case into a successful average.
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
from typing import Iterable

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROBE = ROOT / "target" / "release" / "cram_exploratory_probe"


@dataclass(frozen=True)
class Case:
    case_id: str
    config: str
    workload: str
    depth: int
    seed: int
    initial: int
    rhs: int
    refresh: str
    refresh_timing: str
    trigger_permille: int
    candidate_wall: int


def command_output(command: list[str], cwd: pathlib.Path = ROOT) -> str:
    try:
        return subprocess.check_output(
            command, cwd=cwd, text=True, stderr=subprocess.STDOUT
        ).strip()
    except (OSError, subprocess.CalledProcessError) as error:
        output = getattr(error, "output", "")
        return output.strip() if output else "unavailable"


def git_output(*args: str) -> str:
    return command_output(["git", *args])


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


def parse_int_csv(value: str) -> tuple[int, ...]:
    return tuple(int(item.strip()) for item in value.split(",") if item.strip())


def default_depth(workload: str, profile: str) -> int:
    table = {
        "quick": {
            "add_only": 32,
            "mul_plain_only": 12,
            "mul_ct_only": 4,
            "interleaved": 8,
        },
        "standard": {
            "add_only": 256,
            "mul_plain_only": 80,
            "mul_ct_only": 12,
            "interleaved": 24,
        },
        "endurance": {
            "add_only": 4096,
            "mul_plain_only": 512,
            "mul_ct_only": 32,
            "interleaved": 128,
        },
    }
    return table[profile][workload]


def profile_defaults(profile: str) -> tuple[tuple[str, ...], tuple[str, ...], tuple[int, ...]]:
    if profile == "quick":
        return ("secure_128",), (
            "add_only",
            "mul_plain_only",
            "mul_ct_only",
            "interleaved",
        ), (42,)
    if profile == "standard":
        return (
            "secure_128",
            "secure_128_deep",
            "secure_192",
            "secure_256",
        ), (
            "add_only",
            "mul_plain_only",
            "mul_ct_only",
            "interleaved",
        ), (1, 42, 99)
    return (
        "secure_128",
        "secure_128_deep",
        "secure_192",
        "secure_256",
    ), (
        "add_only",
        "mul_plain_only",
        "mul_ct_only",
        "interleaved",
    ), (1, 7, 42, 99, 2026)


def make_cases(args: argparse.Namespace) -> list[Case]:
    default_configs, default_workloads, default_seeds = profile_defaults(args.profile)
    configs = parse_csv(args.configs) if args.configs else default_configs
    workloads = parse_csv(args.workloads) if args.workloads else default_workloads
    seeds = parse_int_csv(args.seeds) if args.seeds else default_seeds
    refresh_variants: list[tuple[str, str, int, int]] = [("none", "pre", 0, 0)]
    if args.include_bootstrap:
        refresh_variants.extend(
            [
                ("threshold", "pre", args.trigger_permille, 0),
                ("threshold", "post", args.trigger_permille, 0),
                ("exhaustion", "pre", args.trigger_permille, 0),
                ("exhaustion", "post", args.trigger_permille, 0),
            ]
        )
    for wall in parse_int_csv(args.candidate_walls):
        refresh_variants.append(("wall", "pre", args.trigger_permille, wall))
        refresh_variants.append(("wall", "post", args.trigger_permille, wall))

    cases: list[Case] = []
    index = 0
    for config, workload, seed, refresh_variant in product(
        configs, workloads, seeds, refresh_variants
    ):
        refresh, timing, trigger, wall = refresh_variant
        if refresh == "wall" and workload == "add_only":
            continue
        depth = args.depth if args.depth else default_depth(workload, args.profile)
        case_key = (
            f"{index:05d}-{config}-{workload}-d{depth}-s{seed}-"
            f"{refresh}-{timing}-t{trigger}-w{wall}"
        )
        cases.append(
            Case(
                case_id=case_key,
                config=config,
                workload=workload,
                depth=depth,
                seed=seed,
                initial=args.initial,
                rhs=args.rhs,
                refresh=refresh,
                refresh_timing=timing,
                trigger_permille=trigger,
                candidate_wall=wall,
            )
        )
        index += 1
    return cases


def hardware_metadata() -> dict[str, object]:
    mem_total = "unavailable"
    meminfo = pathlib.Path("/proc/meminfo")
    if meminfo.exists():
        for line in meminfo.read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                mem_total = line.split(":", 1)[1].strip()
                break
    return {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "logical_cpus": os.cpu_count(),
        "memory_total": mem_total,
        "kernel": command_output(["uname", "-a"]),
        "lscpu": command_output(["lscpu"]),
    }


def run(command: list[str], cwd: pathlib.Path = ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)


def build_probe() -> dict[str, object]:
    command = [
        "cargo",
        "build",
        "--release",
        "-p",
        "nine65",
        "--bin",
        "cram_exploratory_probe",
        "--features",
        "serde",
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


def run_case(case: Case, output_dir: pathlib.Path) -> dict[str, object]:
    result_path = output_dir / "cases" / f"{case.case_id}.json"
    stdout_path = output_dir / "logs" / f"{case.case_id}.stdout.log"
    stderr_path = output_dir / "logs" / f"{case.case_id}.stderr.log"
    result_path.parent.mkdir(parents=True, exist_ok=True)
    stdout_path.parent.mkdir(parents=True, exist_ok=True)

    command = [
        str(PROBE),
        "--config",
        case.config,
        "--workload",
        case.workload,
        "--depth",
        str(case.depth),
        "--seed",
        str(case.seed),
        "--initial",
        str(case.initial),
        "--rhs",
        str(case.rhs),
        "--refresh",
        case.refresh,
        "--refresh-timing",
        case.refresh_timing,
        "--trigger-permille",
        str(case.trigger_permille),
        "--candidate-wall",
        str(case.candidate_wall),
        "--output",
        str(result_path),
    ]
    started = time.perf_counter_ns()
    completed = run(command)
    duration_ns = time.perf_counter_ns() - started
    stdout_path.write_text(completed.stdout, encoding="utf-8")
    stderr_path.write_text(completed.stderr, encoding="utf-8")

    parsed: dict[str, object] | None = None
    parse_error: str | None = None
    if result_path.exists():
        try:
            parsed = json.loads(result_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            parse_error = str(error)

    return {
        "case": asdict(case),
        "command": command,
        "command_shell_display": shlex.join(command),
        "duration_ns": duration_ns,
        "returncode": completed.returncode,
        "result_path": str(result_path.relative_to(output_dir)),
        "stdout_path": str(stdout_path.relative_to(output_dir)),
        "stderr_path": str(stderr_path.relative_to(output_dir)),
        "result_sha256": sha256_file(result_path) if result_path.exists() else None,
        "reported_status": parsed.get("status") if parsed else None,
        "parse_error": parse_error,
    }


def summarize(records: Iterable[dict[str, object]]) -> dict[str, int]:
    summary = {"cases": 0, "process_zero": 0, "reported_pass": 0, "reported_fail": 0, "missing_result": 0}
    for record in records:
        summary["cases"] += 1
        if record["returncode"] == 0:
            summary["process_zero"] += 1
        status = record["reported_status"]
        if status == "PASS":
            summary["reported_pass"] += 1
        elif status == "FAIL":
            summary["reported_fail"] += 1
        else:
            summary["missing_result"] += 1
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", choices=("quick", "standard", "endurance"), default="quick")
    parser.add_argument("--configs", default="")
    parser.add_argument("--workloads", default="")
    parser.add_argument("--seeds", default="")
    parser.add_argument("--depth", type=int, default=0)
    parser.add_argument("--initial", type=int, default=3)
    parser.add_argument("--rhs", type=int, default=2)
    parser.add_argument("--include-bootstrap", action="store_true")
    parser.add_argument("--trigger-permille", type=int, default=120)
    parser.add_argument("--candidate-walls", default="")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--output-dir", type=pathlib.Path)
    args = parser.parse_args()

    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_dir = args.output_dir or ROOT / "artifacts" / "exploratory" / timestamp
    output_dir.mkdir(parents=True, exist_ok=True)

    build = {"skipped": True}
    if not args.skip_build:
        build = build_probe()
        (output_dir / "build.json").write_text(
            json.dumps(build, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        if build["returncode"] != 0:
            print(json.dumps(build, indent=2, sort_keys=True))
            return 2
    if not PROBE.exists():
        raise SystemExit(f"probe binary missing: {PROBE}")

    cases = make_cases(args)
    records = [run_case(case, output_dir) for case in cases]
    manifest = {
        "schema": "nine65-cram-exploratory-matrix-v1",
        "created_utc": timestamp,
        "repository": git_output("config", "--get", "remote.origin.url"),
        "commit": git_output("rev-parse", "HEAD"),
        "branch": git_output("rev-parse", "--abbrev-ref", "HEAD"),
        "dirty": git_output("status", "--porcelain") != "",
        "rustc": command_output(["rustc", "-Vv"]),
        "cargo": command_output(["cargo", "-V"]),
        "profile": args.profile,
        "hardware": hardware_metadata(),
        "build": build,
        "summary": summarize(records),
        "records": records,
    }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({"manifest": str(manifest_path), "summary": manifest["summary"]}, indent=2))
    return 0 if manifest["summary"]["reported_fail"] == 0 and manifest["summary"]["missing_result"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
