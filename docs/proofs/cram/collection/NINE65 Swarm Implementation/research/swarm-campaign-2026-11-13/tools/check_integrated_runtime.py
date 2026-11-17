#!/usr/bin/env python3
"""Execute focused tests on the combined runtime tree, not worker branches."""
from pathlib import Path
from datetime import datetime, timezone
import argparse
import hashlib
import json
import os
import re
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo", default="cargo")
    args = parser.parse_args()
    cases = [
        ("core", 29, ["-p", "cram-core", "--no-fail-fast"]),
        ("adapter-serial", 3, ["-p", "nine65", "--no-default-features", "--features", "residue-query", "--test", "residue_query_adapter", "--no-fail-fast"]),
        ("adapter-accelerated", 3, ["-p", "nine65", "--no-default-features", "--features", "residue-query,accelerated", "--test", "residue_query_adapter", "--no-fail-fast"]),
        ("gcd", 7, ["-p", "nine65", "--lib", "division::gcd_tests::", "--no-fail-fast", "--", "--nocapture"]),
        ("private-feedback", 1, ["-p", "private-feedback-nine65", "public_adapter_encrypts_and_aggregates_live_dual_rns_slots", "--no-fail-fast", "--", "--nocapture"]),
    ]
    runs = []
    for name, expected, tail in cases:
        cmd = [args.cargo, "test", "--locked", *tail]
        log = ROOT / "evidence" / f"integrated-{name}.log"
        start = time.monotonic()
        print(f"Running {name}", flush=True)
        with log.open("w") as stream:
            result = subprocess.run(cmd, cwd=REPO, stdout=stream, stderr=subprocess.STDOUT)
        contents = log.read_text()
        passed = sum(map(int, re.findall(r"test result: ok\. (\d+) passed;", contents)))
        failed = sum(map(int, re.findall(r"(\d+) failed;", contents)))
        row = {"name": name, "command": cmd, "exit_code": result.returncode,
               "passed": passed, "failed": failed, "expected_passed": expected,
               "elapsed_seconds": round(time.monotonic()-start, 3),
               "log": str(log.relative_to(ROOT)),
               "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest()}
        runs.append(row)
        print(json.dumps(row), flush=True)
        if result.returncode or passed != expected or failed:
            raise RuntimeError(f"Integrated {name} failed or did not execute expected tests")
    sources = {}
    for manifest in ("runtime-residue/adapter-tests.json", "runtime-gcd/evidence/verification.json"):
        for name, digest in json.loads((ROOT / manifest).read_text())["source_sha256"].items():
            actual = hashlib.sha256((REPO / name).read_bytes()).hexdigest()
            if actual != digest:
                raise RuntimeError(f"Integrated source differs from reviewed worker source: {name}")
            sources[name] = actual
    report = {"status": "PASS", "executed_at_utc": datetime.now(timezone.utc).isoformat(),
              "repo": str(REPO), "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
              "scope": "Focused combined-tree execution; separate feature sets as listed; not all-feature or whole-workspace testing",
              "cargo_version": subprocess.check_output([args.cargo, "--version"], cwd=REPO, text=True).strip(),
              "target_dir": os.environ.get("CARGO_TARGET_DIR"), "runs": runs,
              "source_sha256": sources}
    (ROOT / "evidence/integrated-runtime.json").write_text(json.dumps(report, indent=2)+"\n")


if __name__ == "__main__":
    main()
