#!/usr/bin/env python3
"""Verify the archived source snapshots and replay the recorded probe."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    artifact = Path(__file__).resolve().parent
    recorded = json.loads((artifact / "add-benchmark.json").read_text())
    rows = []
    with tempfile.TemporaryDirectory(prefix="nine65-add-replay-") as tmp:
        root = Path(tmp)
        for label, source in recorded["sources"].items():
            directory = root / label
            directory.mkdir()
            for name, expected in source["source_hashes"].items():
                data = (artifact / "sources" / label / name).read_bytes()
                if hashlib.sha256(data).hexdigest() != expected:
                    raise RuntimeError(f"Source hash mismatch: {label}/{name}")
                (directory / name).write_bytes(data)
            shutil.copyfile(artifact / "add-benchmark.rs", directory / "bench.rs")
            subprocess.run(
                ["rustc", "--edition", "2021", "--cfg", 'feature="std"',
                 "-C", "opt-level=3", "-C", "lto=fat", "-C", "codegen-units=1",
                 str(directory / "bench.rs"), "-o", str(directory / "bench")],
                check=True,
            )
        for run in range(1, 4):
            for label in recorded["sources"]:
                output = subprocess.check_output([str(root / label / "bench")], text=True)
                rows.extend({"run": run, "version": label, **json.loads(line)}
                            for line in output.splitlines())
    print(json.dumps({"source_record": "add-benchmark.json", "records": rows}, indent=2))


if __name__ == "__main__":
    main()
