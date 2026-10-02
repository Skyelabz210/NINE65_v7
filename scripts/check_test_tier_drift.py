#!/usr/bin/env python3
"""Test-tier drift gate for issue #78 (fast/medium/slow test categorization).

WHAT THIS CHECKS
    The FAST tier (scripts/run_tests_fast.sh, i.e. `cargo test --lib`) is
    fast only because nothing slow lives inside it *today*. Nothing enforces
    that boundary as the suite grows — a new unit test that happens to
    encrypt/multiply under a heavy config would silently make the fast tier
    slow again, with no attribute anywhere marking it as such (this repo's
    only two existing markers for "expensive test" are the `slow_tests`
    Cargo feature in crates/nine65/Cargo.toml and per-test `#[ignore]`, and
    a test living inside `--lib` is by definition using neither).

    This script builds the compiled `--lib` test binary for each requested
    package (default: every workspace package, matching run_tests_fast.sh),
    lists every test in it, times each one individually by invoking the
    already-built binary directly with `--exact` (bypassing `cargo test`'s
    own per-invocation overhead), and flags any test whose wall time exceeds
    `--threshold-secs` (default 2.0).

WHY WALL-CLOCK VIA REPEATED INVOCATION, NOT `--report-time`
    libtest's built-in per-test timing (`-Z unstable-options --report-time`)
    needs a nightly toolchain or RUSTC_BOOTSTRAP=1. This repo's CI
    (dtolnay/rust-toolchain@stable) and this environment both run stable
    only (see CLAUDE.md: no nightly toolchain is documented anywhere in this
    project). Timing each test as a separate direct-binary invocation is the
    stable-compatible equivalent: after the one `cargo test --no-run` build,
    each individual run is just an OS process spawn plus that one test's own
    work, so a workspace-wide pass costs one compile plus O(test count)
    process-spawn overhead — seconds, not another full recompile per test.

WHAT A FLAGGED TEST MEANS
    The categorization scheme (docs/TEST_TIERS.md) never touches individual
    `#[ignore]`/`#[cfg]` attributes — it composes existing Cargo target/
    feature boundaries. So a flagged test is not "broken"; it is a signal
    for a human to decide, same as this repo's other advisory gates
    (scripts/check_no_panics.sh, scripts/regression_scan.sh): move the slow
    test out of `--lib` (into crates/nine65/tests/, which is already
    "medium" tier), gate it behind the existing `slow_tests` feature (see
    crates/nine65/src/ops/rns_fhe.rs's one existing use), or accept it and
    widen the FAST tier's documented budget in docs/TEST_TIERS.md.

MODE — advisory (default) vs enforced
    Advisory: report findings, exit 0 regardless (matches
    scripts/check_no_panics.sh / scripts/regression_scan.sh's convention for
    a gate whose remediation is a judgment call, not a mechanical fix).
    Enforced (`--mode enforced`): exit 1 if any test exceeds the threshold.
    Nothing in ci.yml invokes enforced mode yet — see docs/TEST_TIERS.md.

USAGE
    python3 scripts/check_test_tier_drift.py
    python3 scripts/check_test_tier_drift.py --package nine65 --threshold-secs 1.0
    python3 scripts/check_test_tier_drift.py --mode enforced
    python3 scripts/check_test_tier_drift.py --list-only   # inventory only, no timing
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_THRESHOLD_SECS = 2.0
DEFAULT_EXCLUDE = ["nine65-python", "nine65-wasm"]


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=ROOT, text=True, **kwargs)


def build_lib_test_binaries(packages: list[str] | None) -> list[tuple[str, Path]]:
    """Build (or reuse the cached build of) every --lib test binary and
    return (package_name, executable_path) pairs, via cargo's own
    --message-format=json artifact reporting (no path guessing)."""
    cmd = ["cargo", "test", "--release", "--lib", "--no-run", "--message-format=json"]
    if packages:
        for pkg in packages:
            cmd += ["-p", pkg]
    else:
        cmd += ["--workspace"]
        for pkg in DEFAULT_EXCLUDE:
            cmd += ["--exclude", pkg]

    print(f"$ {' '.join(cmd)}", file=sys.stderr)
    proc = run(cmd, capture_output=True)
    if proc.returncode != 0:
        print(proc.stdout, file=sys.stderr)
        print(proc.stderr, file=sys.stderr)
        raise SystemExit(f"cargo test --no-run failed with exit {proc.returncode}")

    binaries: list[tuple[str, Path]] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        msg = json.loads(line)
        if msg.get("reason") != "compiler-artifact":
            continue
        if not msg.get("profile", {}).get("test"):
            continue
        executable = msg.get("executable")
        if not executable:
            continue
        target = msg.get("target", {})
        if target.get("kind") != ["lib"]:
            continue
        pkg_id = msg.get("package_id", "")
        pkg_name = pkg_id.split(" ")[0] if pkg_id else target.get("name", "?")
        binaries.append((pkg_name, Path(executable)))
    return binaries


def list_tests(executable: Path) -> list[str]:
    proc = run([str(executable), "--list", "--format=terse"], capture_output=True)
    names = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line or ": test" not in line:
            continue
        names.append(line.split(": test")[0])
    return names


def time_test(executable: Path, name: str) -> float:
    start = time.monotonic()
    run(
        [str(executable), name, "--exact", "--test-threads=1"],
        capture_output=True,
    )
    return time.monotonic() - start


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--package",
        "-p",
        action="append",
        dest="packages",
        help="Limit to this package's --lib tests (repeatable). Default: "
        "every workspace package (matches run_tests_fast.sh).",
    )
    parser.add_argument(
        "--threshold-secs",
        type=float,
        default=DEFAULT_THRESHOLD_SECS,
        help=f"Flag any individual test slower than this (default {DEFAULT_THRESHOLD_SECS}).",
    )
    parser.add_argument(
        "--mode",
        choices=["advisory", "enforced"],
        default="advisory",
        help="advisory (default): report and exit 0. enforced: exit 1 on any finding.",
    )
    parser.add_argument(
        "--list-only",
        action="store_true",
        help="Only inventory tests (name + package count); do not time them.",
    )
    args = parser.parse_args()

    print("=== Test Tier Drift Check (fast tier: --lib) ===")
    binaries = build_lib_test_binaries(args.packages)
    if not binaries:
        print("ERROR: no --lib test binaries found", file=sys.stderr)
        return 1

    total_tests = 0
    slow: list[tuple[str, str, float]] = []

    for pkg, exe in binaries:
        if not exe.exists():
            print(f"  (skip) {pkg}: executable not found at {exe}")
            continue
        names = list_tests(exe)
        total_tests += len(names)
        print(f"  {pkg}: {len(names)} lib tests" + (" (listed only)" if args.list_only else ""))
        if args.list_only:
            continue
        for name in names:
            elapsed = time_test(exe, name)
            if elapsed > args.threshold_secs:
                slow.append((pkg, name, elapsed))

    print()
    print(f"Total fast-tier (--lib) tests inventoried: {total_tests}")

    if args.list_only:
        return 0

    print(f"Threshold: {args.threshold_secs:.2f}s per test")
    if not slow:
        print("PASS: no fast-tier test exceeded the threshold.")
        return 0

    slow.sort(key=lambda row: row[2], reverse=True)
    print(f"FOUND {len(slow)} test(s) over threshold (fast tier is drifting slow):")
    for pkg, name, elapsed in slow:
        print(f"  {elapsed:7.3f}s  {pkg}::{name}")
    print()
    print(
        "Remediation: move the test into crates/*/tests/ (medium tier), gate it\n"
        "behind nine65's `slow_tests` feature (slow tier), or widen the FAST\n"
        "tier's documented budget in docs/TEST_TIERS.md if this is intentional."
    )

    if args.mode == "enforced":
        return 1
    print("(advisory mode: not failing the build)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
