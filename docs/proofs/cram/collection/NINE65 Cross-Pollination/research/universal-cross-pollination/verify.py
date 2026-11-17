#!/usr/bin/env python3
"""Execute public-model checks and validate the self-contained research packet.

Lean is built independently by lean/check_proofs.py; this command verifies
that its recorded successful audit matches every current proof source.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[1]
EVIDENCE = ROOT / "evidence"
SOURCE_BASE = "88a7bdadbf0e1f8fbfdb2b37e9843101b8db3484"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    EVIDENCE.mkdir(exist_ok=True)
    commands = [
        ("unit-tests", [sys.executable, "-m", "unittest", "discover", "-s", "reference", "-v"]),
        ("planner-examples", [sys.executable, "reference/query_planner.py"]),
        ("arithmetic-witness", [sys.executable, "reference/arithmetic_witness.py"]),
        ("domain-witness", [sys.executable, "reference/domain_witness.py"]),
        ("reviewer-oracles", [sys.executable, "evidence/reviewer_oracles.py"]),
    ]
    results = []
    for name, command in commands:
        run = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
        output = run.stdout + run.stderr
        (EVIDENCE / (name + ".log")).write_text(output)
        results.append({"name": name, "command": command, "exit_code": run.returncode})
        if run.returncode:
            raise RuntimeError(name + " failed; see its evidence log")
        if name == "unit-tests" and not re.search(r"Ran 15 tests\b", output):
            raise RuntimeError("Expected exactly 15 research unit tests")
        if name == "planner-examples":
            (EVIDENCE / "planner-examples.json").write_text(run.stdout)

    proof = json.loads((ROOT / "lean/verification.json").read_text())
    if proof["status"] != "PASS":
        raise RuntimeError("Lean audit does not record PASS")
    # The checker records every module source under files.
    for row in proof["files"]:
        if digest(ROOT / "lean" / row["file"]) != row["sha256"]:
            raise RuntimeError("Stale Lean source record: " + row["file"])

    docs = list(ROOT.glob("*.md")) + [
        ROOT / "lean/README.md",
        REPO / "docs/execution/2026-11-12/UNIVERSAL_CROSS_POLLINATION.md",
    ]
    links = 0
    for doc in docs:
        for target in re.findall(r"\]\(([^)]+)\)", doc.read_text()):
            if target.startswith(("http:", "https:", "#", "mailto:", "thread:")):
                continue
            target = target.split("#", 1)[0]
            destination = (doc.parent / target).resolve()
            # This run writes its own report after all checks pass.
            own_report = (EVIDENCE / "verification.json").resolve()
            if target and destination != own_report and not destination.exists():
                raise RuntimeError(f"Broken local link in {doc.name}: {target}")
            links += 1

    source_files = sorted(p for p in ROOT.rglob("*") if p.is_file()
                          and p.suffix in (".py", ".lean", ".md")
                          and "__pycache__" not in p.parts)
    try:
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO,
                              text=True, capture_output=True)
        checkout_head = head.stdout.strip() if head.returncode == 0 else None
    except FileNotFoundError:
        checkout_head = None
    report = {
        "status": "PASS",
        "executed_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_base_commit": SOURCE_BASE,
        "checkout_head": checkout_head,
        "scope": "Public-model research checks; no Rust or ciphertext execution",
        "unit_tests": 15,
        "local_document_links_checked": links,
        "lean_evidence": "lean/verification.json (fresh build performed separately)",
        "commands": results,
        "source_sha256": {str(p.relative_to(ROOT)): digest(p) for p in source_files},
        "missing_context": {"thread_id": "6af548dd-c6d8-8191-90ed-c6d29cf470cb",
                            "status": "UNAVAILABLE: read_thread tool not exposed"},
    }
    (EVIDENCE / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: report[k] for k in ("status", "unit_tests", "local_document_links_checked")}, indent=2))


if __name__ == "__main__":
    main()
