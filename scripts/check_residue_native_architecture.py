#!/usr/bin/env python3
"""Fail closed when prohibited mechanisms enter residue-native production paths."""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
PRODUCTION_TARGETS = (
    ROOT / "crates" / "cram-core" / "src",
    ROOT / "crates" / "cram-poly" / "src",
    ROOT / "crates" / "cram-fhe" / "src",
    ROOT / "crates" / "nine65" / "src" / "cram_ct_wrap.rs",
    ROOT / "crates" / "nine65" / "src" / "ops" / "rns_fhe.rs",
)

PROHIBITED = {
    "garner": re.compile(r"\b" + "gar" + "ner" + r"\b", re.IGNORECASE),
    "mixed_radix": re.compile(r"mixed[_ -]?" + "radix", re.IGNORECASE),
    "crt_reconstruct": re.compile(r"\bcrt_" + "reconstruct\b", re.IGNORECASE),
    "hidden_big_integer": re.compile(r"\b(Big" + r"Int|BigUint)\b"),
    "floating_type": re.compile(r"\bf(?:32|64)\b|\bas\s+f(?:32|64)\b"),
}

ALLOWED_PATH_PARTS = {"tests", "test_oracle", "oracle", "legacy", "archive", "docs"}


def is_allowed(path: pathlib.Path) -> bool:
    return any(part in ALLOWED_PATH_PARTS for part in path.parts)


def scan_file(path: pathlib.Path) -> list[str]:
    if is_allowed(path):
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return []
    failures: list[str] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for name, pattern in PROHIBITED.items():
            if pattern.search(line):
                failures.append(f"{path.relative_to(ROOT)}:{line_number}: {name}: {line.strip()}")
    return failures


def iter_files(target: pathlib.Path):
    if target.is_file():
        yield target
    elif target.is_dir():
        for path in target.rglob("*"):
            if path.suffix in {".rs", ".toml"} and path.is_file():
                yield path


def main() -> int:
    failures: list[str] = []
    for target in PRODUCTION_TARGETS:
        if target.exists():
            for path in iter_files(target):
                failures.extend(scan_file(path))
    if failures:
        print("Residue-native architecture gate FAILED", file=sys.stderr)
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    print("Residue-native architecture gate PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
