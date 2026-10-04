#!/usr/bin/env python3
"""Run one reproducible check and retain its output and exit status."""

import hashlib
import json
import pathlib
import subprocess
import sys
import time


def main() -> int:
    if len(sys.argv) < 4 or sys.argv[2] != "--":
        print("usage: record_execution_check.py NAME -- COMMAND [ARG ...]", file=sys.stderr)
        return 2

    name = sys.argv[1]
    if not name or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for c in name):
        print("check name must use lowercase letters, digits, hyphens or underscores", file=sys.stderr)
        return 2

    command = sys.argv[3:]
    log_dir = pathlib.Path("artifacts/execution/2026-10-03-s02/S02/logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"{name}.log"
    result_path = log_dir / f"{name}.json"
    if log_path.exists() or result_path.exists():
        print(f"check already recorded: {name}", file=sys.stderr)
        return 2

    started = time.monotonic()
    with log_path.open("wb") as output:
        try:
            status = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, check=False).returncode
        except OSError as error:
            output.write(f"unable to start command: {error}\n".encode())
            status = 127

    result = {
        "command": command,
        "cwd": str(pathlib.Path.cwd()),
        "exit_code": status,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "log": str(log_path),
        "log_sha256": hashlib.sha256(log_path.read_bytes()).hexdigest(),
    }
    result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))
    print(log_path.read_text(errors="replace")[-4000:])
    return status


if __name__ == "__main__":
    sys.exit(main())
