#!/usr/bin/env python3
"""Run the reference and retain its result, failures, resources and provenance."""

import argparse
import hashlib
import json
import pathlib
import platform
import resource
import subprocess
import sys
import time


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True)
    parser.add_argument("parameters", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not args.name or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for c in args.name):
        parser.error("name must contain only lowercase ASCII, digits, underscores or hyphens")
    parameters = args.parameters
    if parameters[:1] == ["--"]:
        parameters = parameters[1:]
    root = pathlib.Path(__file__).resolve().parent
    binary = root / "target/release/nine65-bfv-bootstrap-reference"
    directory = root.parents[1] / "artifacts/bootstrap"
    directory.mkdir(parents=True, exist_ok=True)
    prefix = directory / args.name
    paths = {kind: pathlib.Path(str(prefix) + suffix) for kind, suffix in {
        "result": ".json", "stderr": ".stderr.log", "run": ".run.json"
    }.items()}
    if any(path.exists() for path in paths.values()):
        parser.error("artifact name already exists; select a new name")
    hashes = {name: digest(root / name) for name in [
        "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "src/main.rs",
        "run_reference.py", "target/release/nine65-bfv-bootstrap-reference"
    ]}
    compiler = subprocess.check_output(["rustc", "-Vv"], cwd=root, text=True).strip()
    started = time.monotonic_ns()
    with paths["result"].open("x") as stdout, paths["stderr"].open("x") as stderr:
        process = subprocess.run([str(binary), *parameters], cwd=root, stdout=stdout, stderr=stderr)
    elapsed = time.monotonic_ns() - started
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    result_valid = False
    result_error = None
    try:
        result = json.loads(paths["result"].read_text())
        result_valid = (result["schema"] == "nine65-bfv-bootstrap-reference-v1"
                        and result["evaluator_debug_secret"] is False
                        and result["native_nine65_refresh_enabled"] is False
                        and bool(result["rounds"]))
    except (ValueError, KeyError, TypeError) as error:
        result_error = str(error)
    record = {
        "schema": "nine65-reference-execution-v1",
        "command": ["target/release/nine65-bfv-bootstrap-reference", *parameters],
        "exit_code": process.returncode,
        "successful_result": process.returncode == 0 and result_valid,
        "result_parse_error": result_error,
        "wall_ns": elapsed,
        "max_child_rss_kib_linux": usage.ru_maxrss,
        "compiler": compiler,
        "platform": platform.platform(),
        "sha256": hashes,
        "artifacts": {kind: {"file": path.name, "sha256": digest(path)}
                      for kind, path in paths.items() if kind != "run"},
    }
    with paths["run"].open("x") as stream:
        json.dump(record, stream, indent=2)
        stream.write("\n")
    print(json.dumps(record, indent=2))
    return 0 if record["successful_result"] else 1


if __name__ == "__main__":
    sys.exit(main())
