#!/usr/bin/env python3
"""Fail if required mechanical CI jobs are conditional on GitHub actor identity.

Optional review/notification jobs may remain actor-specific. Required deterministic
correctness/security jobs may not skip execution solely because the author is a bot.
"""

from __future__ import annotations

import pathlib
import sys

REQUIRED_JOBS = {"fast-gate", "static-analysis", "full-test"}


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
    workflow = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".github/workflows/ci.yml")
    text = workflow.read_text(encoding="utf-8")
    blocks = job_blocks(text)

    missing = sorted(REQUIRED_JOBS - blocks.keys())
    if missing:
        print(f"ERROR: required CI jobs missing: {', '.join(missing)}", file=sys.stderr)
        return 1

    failures: list[str] = []
    for name in sorted(REQUIRED_JOBS):
        block = blocks[name]
        if "github.actor" in block:
            failures.append(name)

    if failures:
        print(
            "ERROR: actor-dependent bypass found in required mechanical CI job(s): "
            + ", ".join(failures),
            file=sys.stderr,
        )
        return 1

    print("PASS: required mechanical CI jobs are actor-independent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
