#!/usr/bin/env python3
"""Verify the archived source snapshots and replay the recorded probe."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    artifact = Path(__file__).resolve().parent
    recorded = json.loads((artifact / "add-benchmark.json").read_text())
    compiler = ["rustup", "run", "1.89.0", "rustc"]
    actual_version = subprocess.check_output([*compiler, "--version"], text=True).strip()
    if actual_version != recorded["toolchain"]:
        raise RuntimeError("Recorded compiler differs from the pinned compiler")
    expected_profile = {"opt_level": 3, "lto": "fat", "codegen_units": 1, "feature": "std"}
    if recorded["profile"] != expected_profile:
        raise RuntimeError("Unsupported recorded benchmark profile")
    compiler_details = subprocess.check_output([*compiler, "-vV"], text=True).strip()
    driver = (artifact / recorded["driver_file"]).read_bytes()
    if hashlib.sha256(driver).hexdigest() != recorded["driver_sha256"]:
        raise RuntimeError("Benchmark driver hash mismatch")
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
            (directory / "bench.rs").write_bytes(driver)
            subprocess.run(
                [*compiler, "--edition", "2021", "--cfg", 'feature="std"',
                 "-C", "opt-level=3", "-C", "lto=fat", "-C", "codegen-units=1",
                 str(directory / "bench.rs"), "-o", str(directory / "bench")],
                check=True,
            )
        for run in range(1, 4):
            for label in recorded["sources"]:
                output = subprocess.check_output([str(root / label / "bench")], text=True)
                rows.extend({"run": run, "version": label, **json.loads(line)}
                            for line in output.splitlines())
    print(json.dumps({"source_record": "add-benchmark.json", "toolchain": actual_version,
                      "compiler_command": compiler, "compiler_details": compiler_details,
                      "driver_sha256": recorded["driver_sha256"],
                      "profile": expected_profile, "records": rows}, indent=2))


if __name__ == "__main__":
    main()
