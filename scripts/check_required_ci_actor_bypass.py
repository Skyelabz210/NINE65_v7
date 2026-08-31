#!/usr/bin/env python3
"""Fail if required mechanical CI jobs are conditional on GitHub actor identity.

No workflow job may be actor-specific. Required deterministic correctness/security
jobs additionally may not inspect fork origin or PR head-branch names.
"""

from __future__ import annotations

import pathlib
import sys

REQUIRED_JOBS = {"fast-gate", "static-analysis", "full-test"}
FORBIDDEN_REQUIRED_CONTEXTS = (
    "github.head_ref",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.repo",
    "github.event.pull_request.head.label",
)


def job_blocks(text: str) -> dict[str, str]:
    lines = text.splitlines()
    in_jobs = False
    current: str | None = None
    blocks: dict[str, list[str]] = {}

    for line in lines:
        if line == "jobs:":
            in_jobs = True
            current = None
            continue
        if not in_jobs:
            continue

        if line and not line.startswith(" "):
            break

        if line.startswith("  ") and not line.startswith("    "):
            stripped = line.strip()
            if stripped.endswith(":") and not stripped.startswith("#"):
                current = stripped[:-1]
                blocks.setdefault(current, [])
                continue

        if current is not None:
            blocks[current].append(line)

    return {name: "\n".join(body) for name, body in blocks.items()}


def main() -> int:
    workflow = pathlib.Path(
        sys.argv[1] if len(sys.argv) > 1 else ".github/workflows/ci.yml"
    )
    text = workflow.read_text(encoding="utf-8")
    blocks = job_blocks(text)

    missing = sorted(REQUIRED_JOBS - blocks.keys())
    if missing:
        print(f"ERROR: required CI jobs missing: {', '.join(missing)}", file=sys.stderr)
        return 1

    actor_failures = sorted(
        name for name, block in blocks.items() if "github.actor" in block
    )
    context_failures: list[str] = []
    for name in sorted(REQUIRED_JOBS):
        block = blocks[name]
        if any(context in block for context in FORBIDDEN_REQUIRED_CONTEXTS):
            context_failures.append(name)

    if actor_failures:
        print(
            "ERROR: actor-dependent workflow job(s) found: "
            + ", ".join(actor_failures),
            file=sys.stderr,
        )
        return 1
    if context_failures:
        print(
            "ERROR: branch/fork-dependent bypass found in required mechanical CI job(s): "
            + ", ".join(context_failures),
            file=sys.stderr,
        )
        return 1

    print("PASS: required mechanical CI jobs are actor-independent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
