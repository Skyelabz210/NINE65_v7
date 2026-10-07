#!/usr/bin/env python3
"""Inventory Cargo targets and reconcile a complete --no-fail-fast sweep log.

This records discovery and execution separately. Cargo metadata can name a
feature-gated target without proving that its tests compiled or ran.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import re
import subprocess
from pathlib import Path


RESULT = re.compile(
    r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; "
    r"(\d+) ignored; (\d+) measured; (\d+) filtered out;"
)
RUN = re.compile(r"^\s+Running (?:unittests src/|tests/).+\(target/[^/]+/deps/([\w-]+)-[0-9a-f]+\)", re.M)
DOC = re.compile(r"^\s+Doc-tests ([\w-]+)$", re.M)
INTEGRATION = re.compile(r"^\s+Running tests/([^/]+)\.rs ", re.M)
IGNORED = re.compile(r"^test .+ \.\.\. ignored(?:, (.+))?$")


def inventory(root: Path, log_path: Path | None, exit_code: int | None,
              sweep_source_commit: str | None) -> dict:
    raw = subprocess.check_output(
        ["cargo", "metadata", "--locked", "--offline", "--no-deps", "--format-version", "1"],
        cwd=root,
        text=True,
        stderr=subprocess.DEVNULL,
    )
    metadata = json.loads(raw)
    packages = []
    test_targets = []
    for package in metadata["packages"]:
        targets = []
        for target in package["targets"]:
            required_features = target.get("required-features", [])
            if "test" in target["kind"]:
                execution_class = "feature_gated" if required_features else "default_release"
            elif "lib" in target["kind"] or "bin" in target["kind"]:
                execution_class = "unit_target"
            else:
                execution_class = "outside_default_test_sweep"
            record = {
                "name": target["name"],
                "kind": target["kind"],
                "source": str(Path(target["src_path"]).relative_to(root)),
                "required_features": required_features,
                "execution_class": execution_class,
                "resource_class": "unmeasured",
                "test": target["test"],
                "doctest": target["doctest"],
            }
            targets.append(record)
            if "test" in target["kind"]:
                test_targets.append((package["name"], record))
        packages.append({"name": package["name"], "features": package["features"], "targets": targets})

    output = {
        "schema": "nine65-cargo-test-inventory-v1",
        "source_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=root, text=True
        ).strip(),
        "toolchain": subprocess.check_output(["cargo", "--version"], cwd=root, text=True).strip(),
        "metadata_command": "cargo metadata --locked --offline --no-deps --format-version 1",
        "counts": {
            "packages": len(packages),
            "targets": sum(len(p["targets"]) for p in packages),
            "declared_integration_targets": len(test_targets),
        },
        "packages": packages,
    }
    if log_path is None:
        return output

    data = log_path.read_bytes()
    lines = data.decode("utf-8", errors="replace").splitlines()
    run_names = RUN.findall("\n".join(lines))
    doc_names = DOC.findall("\n".join(lines))
    integration_names = INTEGRATION.findall("\n".join(lines))
    summaries = [tuple(map(int, match.groups()[1:])) for line in lines if (match := RESULT.match(line))]
    if len(summaries) != len(run_names) + len(doc_names):
        raise ValueError("test-result blocks do not reconcile with executed targets")
    if len(integration_names) != len(set(integration_names)):
        raise ValueError("integration target names are ambiguous in the sweep log")
    declared_names = [record["name"] for _, record in test_targets]
    if len(declared_names) != len(set(declared_names)):
        raise ValueError("metadata contains duplicate integration target names")
    if not set(integration_names).issubset(set(declared_names)):
        raise ValueError("sweep log names an integration target absent from Cargo metadata")

    selected = set(integration_names)
    unexecuted = [
        {"package": package, "name": record["name"], "required_features": record["required_features"]}
        for package, record in test_targets
        if record["name"] not in selected
    ]
    reasons = collections.Counter(
        match.group(1) or "no reason in log"
        for line in lines
        if (match := IGNORED.match(line))
    )
    output["sweep"] = {
        "source_commit": sweep_source_commit,
        "command": "cargo test --locked --offline --release --workspace --exclude nine65-python --exclude nine65-wasm --no-fail-fast -j1",
        "exit_code": exit_code,
        "log": str(log_path.relative_to(root)),
        "log_sha256": hashlib.sha256(data).hexdigest(),
        "result_blocks": len(summaries),
        "executed_unit_targets": len(run_names) - len(integration_names),
        "executed_integration_targets": len(integration_names),
        "executed_doctest_targets": len(doc_names),
        "test_totals": dict(zip(("passed", "failed", "ignored", "measured", "filtered_out"),
                                (sum(row[i] for row in summaries) for i in range(5)))),
        "unexecuted_integration_targets": unexecuted,
        "ignored_reasons_from_log": dict(sorted(reasons.items())),
        "failed_target_count": sum("test result: FAILED." in line for line in lines),
    }
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path)
    parser.add_argument("--exit-code", type=int)
    parser.add_argument("--sweep-source-commit")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.log and (args.exit_code is None or not args.sweep_source_commit):
        parser.error("--log requires --exit-code and --sweep-source-commit")
    root = Path(__file__).resolve().parent.parent
    log = args.log.resolve() if args.log else None
    result = inventory(root, log, args.exit_code, args.sweep_source_commit)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"counts": result["counts"], "sweep": result.get("sweep", {}).get("test_totals")}))


if __name__ == "__main__":
    main()
