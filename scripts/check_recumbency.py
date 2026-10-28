#!/usr/bin/env python3
"""Reject synthetic-emission mechanisms and unchecked product calls.

The user clarified that reconstruction itself is not prohibited; Garner and
mixed-radix emissions are. This lexical gate cannot establish independence or
reversibility: those require operation-level arrow checks on a declared domain.
Test-gated items are excluded using the repository's existing scanner. The
products-only mode verifies the independently actionable T4.2 gate. The former
blanket reconstruction inventory remains an explicitly optional historical audit.
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

from check_residue_native_architecture import executable_fragment, production_lines

PATTERNS = {
    "synthetic_emission": re.compile(
        r"\b(?:garner\w*|mixed[_ -]?radix\w*)\s*(?:::|\()", re.I
    ),
    "unchecked_rns_product": re.compile(r"\.\s*rns_product\s*\("),
}

LEGACY_RECONSTRUCTION = re.compile(
    r"\b(?:to_int|extract_k_rns(?:_\w+)?|crt_reconstruct(?:_\w+)?|"
    r"garner\w*|mixed_radix\w*|incremental_crt_lift)\b", re.I
)


def findings(
    root: Path,
    products_only: bool = False,
    legacy_reconstruction_audit: bool = False,
) -> list[str]:
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
            if (
                legacy_reconstruction_audit
                and not products_only
                and LEGACY_RECONSTRUCTION.search(code)
            ):
                results.append(
                    f"{path.relative_to(root)}:{number}: legacy_reconstruction_audit"
                )
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--products-only", action="store_true")
    modes.add_argument(
        "--legacy-reconstruction-audit", action="store_true",
        help="also inventory names forbidden by the superseded blanket-reconstruction policy",
    )
    args = parser.parse_args()
    violations = findings(args.root, args.products_only, args.legacy_reconstruction_audit)
    for violation in violations:
        print(violation)
    scope = (
        "legacy reconstruction audit"
        if args.legacy_reconstruction_audit
        else "emission/product source gate"
    )
    print(f"{'FAIL' if violations else 'PASS'}: {len(violations)} {scope} findings")
    return bool(violations)


if __name__ == "__main__":
    raise SystemExit(main())
