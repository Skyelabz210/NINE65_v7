#!/usr/bin/env python3
"""Capture named timing functions from the actual Cargo-built test binary.

This is diagnostic evidence, not a constant-time verifier. Loop branches,
inlining and compiler-selected instructions still require manual review.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def test_binary(manifest: Path) -> Path:
    candidates = set()
    for line in manifest.read_text().splitlines():
        item = json.loads(line)
        if (
            item.get("reason") == "compiler-artifact"
            and item.get("target", {}).get("name") == "nine65"
            and item.get("profile", {}).get("test") is True
            and item.get("executable")
        ):
            candidates.add(Path(item["executable"]))
    if len(candidates) != 1:
        raise ValueError(f"expected one nine65 test binary, found {len(candidates)}")
    binary = candidates.pop()
    if not binary.is_file():
        raise ValueError(f"test binary is missing: {binary}")
    return binary


def capture(manifest: Path, output: Path) -> None:
    binary = test_binary(manifest)
    digest = hashlib.sha256()
    with binary.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    symbols = subprocess.check_output(
        ["nm", "-S", "--defined-only", str(binary)], text=True
    )
    targets = []
    for line in symbols.splitlines():
        fields = line.split()
        if len(fields) == 4 and "test_ct_dudect_" in fields[3]:
            address, size, kind, name = fields
            if kind.lower() == "t" and int(size, 16):
                targets.append((int(address, 16), int(size, 16), name))
    with output.open("w") as report:
        report.write(f"Binary: {binary}\nSHA256: {digest.hexdigest()}\n")
        report.write("Actual timing-function assembly; not constant-time admission.\n")
        for address, size, name in targets:
            report.write(f"\nSymbol: {name}\n")
            report.flush()
            subprocess.run(
                [
                    "objdump", "-d", "-C",
                    f"--start-address={address}",
                    f"--stop-address={address + size}", str(binary),
                ], stdout=report, check=True,
            )
        if not targets:
            report.write("No named timing functions found.\n")
    if not targets:
        raise ValueError("no named timing functions found in the test binary")
    print(f"Captured {len(targets)} timing symbols in {output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo-json", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    capture(args.cargo_json, args.output)
