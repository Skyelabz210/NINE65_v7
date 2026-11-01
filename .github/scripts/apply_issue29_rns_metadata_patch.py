#!/usr/bin/env python3
"""Check the issue #29 exact RNS context metadata contract.

The old source transformer targeted a historical file layout and cannot safely
migrate later changes. --apply is retained as an idempotent compatibility mode;
it refuses to rewrite a source file that does not already meet the contract.
"""
from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "crates/nine65/src/ops/rns_fhe.rs"
_spec = importlib.util.spec_from_file_location("recumbency", ROOT / ".github/scripts/check_cram_recumbency.py")
assert _spec and _spec.loader
_gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_gate)


def metadata_errors(source: str) -> list[str]:
    code = _gate.executable_view(_gate.strip_pure_test_items(source))
    required = {
        "checked scalar field": r"pub\s+q_product_checked\s*:\s*Option\s*<\s*u128\s*>",
        "exact limb field": r"pub\s+q_product_limbs\s*:\s*Vec\s*<\s*u64\s*>",
        "exact bit width": r"let\s+q_bits\s*=\s*config\.rns_product_bit_length\s*\(\s*\)",
        "checked product initialization": r"let\s+q_product_checked\s*=\s*config\.try_rns_product\s*\(\s*\)",
        "exact limb initialization": r"let\s+q_product_limbs\s*=\s*config\.rns_product_limbs\s*\(\s*\)",
        "checked product stored": r"\bq_product_checked\s*,",
        "exact limbs stored": r"\bq_product_limbs\s*,",
    }
    errors = [f"missing {name}" for name, pattern in required.items() if not re.search(pattern, code)]
    if re.search(r"\.\s*q_product\b", code):
        errors.append("legacy scalar product read in production code")
    if re.search(r"\bq_product\s*==\s*0", code):
        errors.append("zero sentinel used for a product decision")
    return errors


def is_patched(source: str) -> bool:
    return not metadata_errors(source)


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.parse_args()
    errors = metadata_errors(TARGET.read_text(encoding="utf-8"))
    if errors:
        print("RNS context metadata contract failed: " + "; ".join(errors), file=sys.stderr)
        return 1
    print("RNS context exact-metadata contract is present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
