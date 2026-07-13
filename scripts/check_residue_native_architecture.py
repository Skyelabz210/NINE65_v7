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

# Match executable identifiers and type usage, not explanatory documentation.
PROHIBITED = {
    "garner_symbol": re.compile(r"\b" + "gar" + "ner" + r"(?:_|::|\s*\()", re.IGNORECASE),
    "mixed_radix_symbol": re.compile(r"\bmixed_" + "radix\b", re.IGNORECASE),
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
    in_block_comment = False
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if in_block_comment:
            if "*/" in stripped:
                in_block_comment = False
            continue
        if stripped.startswith("/*") or stripped.startswith("//") or stripped.startswith("#"):
            if stripped.startswith("/*") and "*/" not in stripped:
                in_block_comment = True
            continue
        for name, pattern in PROHIBITED.items():
            if pattern.search(line):
                failures.append(f"{path.relative_to(ROOT)}:{line_number}: {name}: {stripped}")
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
