#!/usr/bin/env python3
"""Fail closed when production CRAM paths leave residue space.

This source-contract gate complements, but never replaces, Rust arithmetic and
runtime tests. It rejects internal coefficient reconstruction, ambiguous product
sentinels, approximate/saturated capacity decisions, and forbidden conversion
algorithms in active FHE paths.

Pure `#[cfg(test)]` items are removed before inspection. This permits the
public-vector reconstruction oracle required by the formal specification while
keeping every feature-enabled and production item in scope.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _code_without_strings_or_line_comment(line: str) -> str:
    code = line.split("//", 1)[0]
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', code)


def _is_pure_test_cfg(attribute: str) -> bool:
    normalized = re.sub(r"\s+", "", attribute)
    return normalized == "#[cfg(test)]" or normalized.startswith("#[cfg(all(test,")


def strip_pure_test_items(text: str) -> str:
    """Remove Rust items guarded only by `cfg(test)`.

    The scanner is intentionally conservative. Mixed gates such as
    `cfg(any(test, feature = "reference"))` remain visible because they may be
    compiled outside a test build. Source drift that produces an unbalanced
    item causes the original text to remain in scope rather than hiding it.
    """

    lines = text.splitlines(keepends=True)
    output: list[str] = []
    index = 0

    while index < len(lines):
        if "#[cfg" not in lines[index]:
            output.append(lines[index])
            index += 1
            continue

        attribute_start = index
        attribute_parts = [lines[index]]
        while "]" not in "".join(attribute_parts) and index + 1 < len(lines):
            index += 1
            attribute_parts.append(lines[index])
        attribute = "".join(attribute_parts)

        if not _is_pure_test_cfg(attribute):
            output.extend(lines[attribute_start : index + 1])
            index += 1
            continue

        item_index = index + 1
        # Keep consuming attributes and documentation attached to the item.
        while item_index < len(lines):
            stripped = lines[item_index].lstrip()
            if stripped.startswith("#[") or stripped.startswith("///") or stripped.startswith("//!"):
                item_index += 1
                continue
            break

        if item_index >= len(lines):
            # Fail visible: preserve malformed trailing source.
            output.extend(lines[attribute_start:])
            break

        brace_depth = 0
        saw_brace = False
        cursor = item_index
        item_end: int | None = None

        while cursor < len(lines):
            code = _code_without_strings_or_line_comment(lines[cursor])
            opens = code.count("{")
            closes = code.count("}")

            if not saw_brace and ";" in code and opens == 0:
                item_end = cursor + 1
                break

            if opens > 0:
                saw_brace = True
            if saw_brace:
                brace_depth += opens - closes
                if brace_depth == 0:
                    item_end = cursor + 1
                    break
            cursor += 1

        if item_end is None:
            # Never conceal malformed or unexpectedly shaped code.
            output.extend(lines[attribute_start : index + 1])
            index += 1
            continue

        index = item_end

    return "".join(output)


def executable_view(text: str) -> str:
    """Blank comment bodies and string literals, preserving line/column offsets.

    REPAIRED 2026-08-12 (Execution Plan Phase 2). The contracts below target
    *executable constructs*, but they were matched against raw source, so the
    "language" contracts fired on prose — including the compliance notes that
    state a mechanism is deliberately NOT used, e.g.

        // A2 "No-Garner" Invariant: Use Parallel Summation CRT
        /// (a single boundary read), NOT a mixed-radix / Garner conversion
        /// See: QMNF Separation Principle (Theorem 2.1); A2 (no mixed-radix fusion).

    A gate that fails because the source documents its own compliance reports
    nothing. `scripts/check_residue_native_architecture.py` already draws the
    line here ("Documentation and instrumentation counters are not execution
    mechanisms"); this brings the two gates into agreement.

    Blanking, not deleting: every character is replaced by a space and every
    newline is kept, so reported line numbers still match the real file. String
    literals are blanked too, so an error message naming a prohibited mechanism
    is not mistaken for using one. `//` inside a string literal is not treated
    as a comment. Multi-line string literals reset at each newline, which keeps
    more source visible rather than less.
    """

    out: list[str] = []
    index = 0
    length = len(text)
    in_block_comment = False
    in_string = False

    while index < length:
        char = text[index]

        if char == "\n":
            in_string = False
            out.append("\n")
            index += 1
            continue

        if in_block_comment:
            if char == "*" and index + 1 < length and text[index + 1] == "/":
                in_block_comment = False
                out.append("  ")
                index += 2
                continue
            out.append(" ")
            index += 1
            continue

        if in_string:
            if char == "\\" and index + 1 < length:
                out.append("  " if text[index + 1] != "\n" else " \n")
                index += 2
                continue
            if char == '"':
                in_string = False
            out.append(" ")
            index += 1
            continue

        if char == "/" and index + 1 < length and text[index + 1] == "/":
            end = text.find("\n", index)
            end = length if end < 0 else end
            out.append(" " * (end - index))
            index = end
            continue

        if char == "/" and index + 1 < length and text[index + 1] == "*":
            in_block_comment = True
            out.append("  ")
            index += 2
            continue

        if char == '"':
            in_string = True
            out.append(" ")
            index += 1
            continue

        out.append(char)
        index += 1

    return "".join(out)


def production_view(relative: str) -> str:
    return executable_view(strip_pure_test_items(read(relative)))


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def require_absent(relative: str, patterns: list[tuple[str, str]]) -> list[str]:
    text = production_view(relative)
    failures: list[str] = []
    for expression, explanation in patterns:
        matches = list(
            re.finditer(expression, text, flags=re.MULTILINE | re.IGNORECASE | re.DOTALL)
        )
        if matches:
            lines = ", ".join(str(_line_of(text, m.start())) for m in matches[:8])
            more = "" if len(matches) <= 8 else f", +{len(matches) - 8} more"
            failures.append(
                f"{relative}: {explanation} "
                f"[{expression}] at line(s) {lines}{more}"
            )
    return failures


def require_present(relative: str, patterns: list[tuple[str, str]]) -> list[str]:
    text = production_view(relative)
    failures: list[str] = []
    for expression, explanation in patterns:
        if not re.search(expression, text, flags=re.MULTILINE | re.DOTALL):
            failures.append(f"{relative}: missing {explanation} [{expression}]")
    return failures


def main() -> int:
    failures: list[str] = []

    failures += require_absent(
        "crates/nine65/src/ops/bootstrap.rs",
        [
            (r"\bcrt_reconstruct_n\s*\(", "number-line CRT reconstruction in bootstrap"),
            (r"\bcrt_reconstruct_u256\s*\(", "U256 number-line reconstruction in bootstrap"),
            (r"\bGarner\b", "Garner language in active bootstrap"),
            (r"mixed[- ]radix", "mixed-radix language in active bootstrap"),
        ],
    )

    failures += require_absent(
        "crates/nine65/src/ops/rns_mul.rs",
        [
            (r"\bself\.rns\.to_int\s*\(", "main coefficient reconstruction in production rescale"),
            (r"\bextract_k_rns(?:_level)?\s*\(", "scalar/U256 k reconstruction in production rescale"),
            (r"\bcrt_reconstruct_n\s*\(", "CRT reconstruction in production multiplication"),
            (r"\bcrt_reconstruct_u256\s*\(", "U256 reconstruction in production multiplication"),
            (r"\bGarner\b", "Garner language in active multiplication"),
            (r"mixed[- ]radix", "mixed-radix language in active multiplication"),
        ],
    )

    failures += require_absent(
        "crates/nine65/src/ops/rns_fhe.rs",
        [
            (r"q_product\s*==\s*0", "zero sentinel used as modulus-overflow state"),
            (r"unwrap_or\s*\(\s*0\s*\)", "zero overflow sentinel construction"),
            (
                r"map\s*\(\s*\|&p\|\s*\(64\s*-\s*p\.leading_zeros\(\)\).*?\.sum",
                "summed lane widths used instead of exact product bit length",
            ),
            (r"\bGarner\b", "Garner language in active RNS FHE path"),
            (r"mixed[- ]radix", "mixed-radix language in active RNS FHE path"),
        ],
    )

    failures += require_absent(
        "crates/nine65/src/arithmetic/rns.rs",
        [
            (r"anchor_product\s*:\s*u128.*?0 if", "zero sentinel documented as anchor-product state"),
            (r"main_inv_anchor\s*=\s*if anchor_product > 0.*?else\s*\{\s*0", "zero sentinel for unavailable anchor inverse"),
            (r"unwrap_or\s*\(\s*u128::MAX\s*\)", "u128::MAX fallback in capacity decision"),
            (r"k_max_bound\s*=\s*q_max\.saturating_mul", "saturated k bound"),
            (
                r"fn\s+anchor(?:3)?_capacity_bits.*?map\s*\(\s*\|&p\|\s*64\s*-\s*p\.leading_zeros\(\)\s*\).*?sum",
                "summed lane widths used as exact anchor capacity",
            ),
            (
                r"fn\s+extract_k_rns(?:_level)?\b.*?(?:crt_reconstruct_n|crt_reconstruct_u256)\s*\(",
                "bounded k extraction reconstructs a number-line representative",
            ),
            (r"\bGarner\b", "Garner language in active DualRNS arithmetic"),
            (r"mixed[- ]radix", "mixed-radix language in active DualRNS arithmetic"),
        ],
    )

    failures += require_absent(
        "crates/nine65/src/arithmetic/k_elimination.rs",
        [
            (
                r"pub\s+fn\s+capacity\s*\([^)]*\).*?saturating_mul",
                "saturating scalar capacity accessor",
            ),
            (r"\bGarner\b", "Garner language in active K-Elimination module"),
            (r"mixed[- ]radix", "mixed-radix language in active K-Elimination module"),
        ],
    )

    failures += require_present(
        "crates/nine65/src/ops/rns_fhe.rs",
        [
            (r"q_product_checked\s*:\s*Option<u128>", "checked scalar modulus metadata"),
            (r"q_product_limbs\s*:\s*Vec<u64>", "exact modulus limb metadata"),
        ],
    )

    failures += require_present(
        "crates/nine65/src/arithmetic/rns.rs",
        [
            (r"main_product_checked\s*:\s*Option<u128>", "checked scalar main-product metadata"),
            (r"main_product_limbs\s*:\s*Vec<u64>", "exact main-product limb metadata"),
            (r"main_product_bit_length\s*:\s*u32", "exact main-product bit length"),
            (r"anchor_product_checked\s*:\s*Option<u128>", "checked scalar anchor-product metadata"),
            (r"anchor_product_limbs\s*:\s*Vec<u64>", "exact anchor-product limb metadata"),
            (r"anchor_product_bit_length\s*:\s*u32", "exact anchor-product bit length"),
            (r"main_inv_anchor_checked\s*:\s*Option<u128>", "checked scalar main inverse metadata"),
        ],
    )

    failures += require_present(
        "crates/nine65/src/arithmetic/k_elimination.rs",
        [
            (r"pub\s+fn\s+try_capacity\s*\([^)]*\)\s*->\s*Option<u128>", "checked capacity API"),
        ],
    )

    failures += require_present(
        "crates/nine65/src/ops/rns_mul.rs",
        [
            (r"project_bounded\s*\(", "proof-carrying bounded residue quotient projection"),
        ],
    )

    if failures:
        print("CRAM recumbency contract failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print("CRAM recumbency source contract passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
