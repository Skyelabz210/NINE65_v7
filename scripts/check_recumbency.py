#!/usr/bin/env python3
"""Report reconstruction debt; never treat a baseline of violations as a pass.

This is a source-level lexical gate, not a proof of residue-native arithmetic.
Test-gated items are excluded using the repository's existing scanner. The
products-only mode verifies the independently actionable T4.2 gate.
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

from check_residue_native_architecture import executable_fragment, production_lines

PATTERNS = {
    "reconstruction": re.compile(
        r"\b(?:to_int|extract_k_rns(?:_\w+)?|crt_reconstruct(?:_\w+)?|"
        r"garner\w*|mixed_radix\w*|incremental_crt_lift)\b", re.I
    ),
    "unchecked_rns_product": re.compile(r"\.\s*rns_product\s*\("),
}


def findings(root: Path, products_only: bool = False) -> list[str]:
    source = root / "crates/nine65/src"
    paths = sorted(source.rglob("*.rs"))
    if not paths:
        return [f"{source}: missing production source tree"]
    results = []
    for path in paths:
        # Standalone test modules have no production entry point; the full
        # compiler/feature matrix remains a separate acceptance obligation.
        if path.name.endswith("_tests.rs") or "tests" in path.relative_to(source).parts:
            continue
        for number, line in production_lines(path.read_text()):
            code = executable_fragment(line)
            for name, pattern in PATTERNS.items():
                if products_only and name != "unchecked_rns_product":
                    continue
                if pattern.search(code):
                    results.append(f"{path.relative_to(root)}:{number}: {name}")
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--products-only", action="store_true")
    args = parser.parse_args()
    violations = findings(args.root, args.products_only)
    for violation in violations:
        print(violation)
    print(f"{'FAIL' if violations else 'PASS'}: {len(violations)} source-gate violations")
    return bool(violations)


if __name__ == "__main__":
    raise SystemExit(main())
