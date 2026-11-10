#!/usr/bin/env python3
"""Run six bounded, exact-name graph/setup regressions; never a native rerun."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time

from run_public_refresh_research_gates import command_for, validate_result


ROOT = Path(__file__).resolve().parents[1]
TESTS = [
    "ops::public_refresh_circuit::key_graph::tests::native_inventory_is_exact_and_requires_joint_key_review",
    "ops::public_refresh_circuit::key_graph::tests::publication_fingerprint_binds_order_and_key_schedule",
    "ops::public_refresh_circuit::key_graph::tests::breaking_return_cycle_still_leaves_self_key_dependencies",
    "ops::rns_galois::tests::prepared_galois_is_bit_identical_and_reusable_across_plaintext_trays",
    "ops::public_refresh_circuit::tests::public_refresh_conforms_on_full_polynomials_histories_and_forks_across_seeds",
    "ops::public_refresh_return::tests::public_return_restores_dense_work_and_preserves_history",
]


def source_snapshot():
    """Bind tracked Rust/manifests and the reused gate helper before/after."""
    try:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
        paths = [path for path in tracked if path.endswith((".rs", ".toml", "Cargo.lock"))
                 or path == "scripts/run_public_refresh_research_gates.py"]
        hashes = {path: hashlib.sha256((ROOT/path).read_bytes()).hexdigest() for path in paths}
        clean = subprocess.run(["git", "diff", "--quiet", "HEAD", "--", *paths], cwd=ROOT).returncode == 0
        return {"commit": commit, "tracked_inputs_match_commit": clean,
                "tracked_input_sha256": hashes,
                "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "error": None}
    except (OSError, subprocess.CalledProcessError) as exc:
        return {"commit": None, "error": f"{type(exc).__name__}: {exc}"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=300)
    args = parser.parse_args()
    if args.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be positive")
    try:
        args.output_dir.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        parser.error("--output-dir already exists; preserve previous evidence and choose a new directory")
    before = source_snapshot()
    results = []
    for index, name in enumerate(TESTS, 1):
        command = command_for(("--lib", None, name, False))
        command[command.index("--locked") + 1:command.index("--locked") + 1] = ["--offline", "--no-fail-fast"]
        log_path = args.output_dir / f"test-{index:02d}.log"
        started = time.monotonic()
        error = None
        error_type = None
        output, returncode = "", None
        try:
            with log_path.open("x") as output_file:
                process = subprocess.Popen(command, cwd=ROOT, text=True, stdout=output_file,
                                           stderr=subprocess.STDOUT, start_new_session=True)
                try:
                    returncode = process.wait(timeout=args.timeout_seconds)
                except subprocess.TimeoutExpired:
                    if os.name == "posix":
                        os.killpg(process.pid, signal.SIGKILL)
                    else:
                        process.kill()
                    process.wait()
                    raise
        except subprocess.TimeoutExpired:
            returncode, error = None, f"timed out after {args.timeout_seconds} seconds"
            error_type = "timeout"
        except ValueError as exc:
            error = str(exc)
            error_type = "result_validation"
        except OSError as exc:
            error = str(exc)
            error_type = type(exc).__name__
        try:
            output = log_path.read_text()
            log_hash = hashlib.sha256(output.encode()).hexdigest()
            if error is None:
                validate_result(output, returncode, name)
        except ValueError as exc:
            error = str(exc)
            error_type = "result_validation"
        except OSError as exc:
            error = str(exc)
            error_type = type(exc).__name__
            log_hash = None
        result = {"test": name, "command": command, "exit_code": returncode,
                  "elapsed_seconds": round(time.monotonic()-started, 6),
                  "log": log_path.name, "log_sha256": log_hash,
                  "validation": "pass" if error is None else "fail", "error": error, "error_type": error_type}
        results.append(result)
        print(f"{result['validation'].upper()}: {name} ({result['elapsed_seconds']}s)", flush=True)
    after = source_snapshot()
    source_matches = (before.get("error") is None and after.get("error") is None
                      and before == after and before["tracked_inputs_match_commit"])
    try:
        toolchain = subprocess.check_output(["rustc", "--version"], text=True).strip()
        toolchain_error = None
    except (OSError, subprocess.CalledProcessError) as exc:
        toolchain, toolchain_error = None, f"{type(exc).__name__}: {exc}"
    manifest = {
        "schema": "nine65-public-key-graph-tests-v1",
        "source_commit": before["commit"],
        "source_snapshot_before": before, "source_snapshot_after": after,
        "tracked_source_clean_and_stable_before_after": source_matches,
        "scope": "three key-free graph tests; reduced encrypted Galois, N8/N32 circuit, and return tests; no native encrypted run",
        "toolchain": toolchain, "toolchain_error": toolchain_error,
        "environment_paths": {key: os.environ.get(key) for key in ("CARGO_HOME", "RUSTUP_HOME", "CARGO_TARGET_DIR")},
        "tests": results, "all_passed": source_matches and all(r["validation"] == "pass" for r in results),
    }
    with (args.output_dir / "test-manifest.json").open("x") as manifest_file:
        manifest_file.write(json.dumps(manifest, indent=2)+"\n")
    return 0 if manifest["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
