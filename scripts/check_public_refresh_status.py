#!/usr/bin/env python3
"""Check refresh documentation routing and immutable evidence, not security."""

import argparse
import hashlib
import json
from pathlib import Path
import tempfile


def check(root, manifest):
    errors = []
    status = root / manifest["current_status"]
    if not status.is_file() or not status.read_text().strip():
        errors.append("missing current refresh status")
    forbidden = (
        "public refresh is disabled on every config.",
        "native public refresh is currently blocked.",
        "native nine65 public refresh remains disabled.",
        "secret-dependent phase-1 carry is still missing on every config.",
    )
    for group in ("live_entry_points", "historical_snapshots"):
        for name in manifest[group]:
            path = root / name
            if not path.is_file():
                errors.append("missing routed document: " + name)
                continue
            text = path.read_text()
            if "PUBLIC_REFRESH_STATUS.md" not in text:
                errors.append("missing current-status route: " + name)
            if group == "historical_snapshots":
                if "Historical refresh scope" not in "\n".join(text.splitlines()[:16]):
                    errors.append("missing historical scope banner: " + name)
            elif any(phrase in text.lower() for phrase in forbidden):
                errors.append("unscoped legacy diagnosis in live guidance: " + name)
    for name, expected in manifest["immutable_evidence_sha256"].items():
        path = root / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            errors.append("historical evidence changed: " + name)
    return errors


def self_test():
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        (root / "PUBLIC_REFRESH_STATUS.md").write_text("Current scoped status.")
        (root / "live.md").write_text("Read PUBLIC_REFRESH_STATUS.md.")
        historical = "Historical refresh scope\nRead PUBLIC_REFRESH_STATUS.md."
        (root / "old.md").write_text(historical)
        (root / "evidence.log").write_bytes(b"original recorded result")
        manifest = {"current_status": "PUBLIC_REFRESH_STATUS.md",
                    "live_entry_points": ["live.md"], "historical_snapshots": ["old.md"],
                    "immutable_evidence_sha256": {"evidence.log": hashlib.sha256(
                        (root / "evidence.log").read_bytes()).hexdigest()}}
        assert not check(root, manifest)
        (root / "live.md").write_text("PUBLIC_REFRESH_STATUS.md\nPublic refresh is disabled on every config.")
        assert any("unscoped" in error for error in check(root, manifest))
        (root / "live.md").write_text("missing routing")
        assert any("missing current-status route" in error for error in check(root, manifest))
        (root / "live.md").write_text("Read PUBLIC_REFRESH_STATUS.md.")
        (root / "old.md").write_text("Read PUBLIC_REFRESH_STATUS.md.")
        assert any("historical scope" in error for error in check(root, manifest))
        (root / "old.md").write_text(historical)
        (root / "evidence.log").write_bytes(b"rewritten history")
        assert any("historical evidence changed" in error for error in check(root, manifest))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / "docs/public_refresh_status_sources.json").read_text())
    errors = check(root, manifest)
    for error in errors:
        print("ERROR:", error)
    if not errors:
        print("Refresh status routing and historical evidence checks passed.")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
