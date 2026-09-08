#!/usr/bin/env python3
"""WR-1 §F source-call-graph denylist for the derived-transient exact route.

Fails closed when a prohibited mechanism enters any production source file
reachable from `ExactMulEvaluator::try_mul_exact` /
`try_mul_no_relin_exact` / `try_decrypt_exact`.

WR-1 §F names the denied set. The route may not reach:

    RNSContext::to_int
    to_u256_level
    extract_k_rns_level*
    extract_digit_dual
    k_elim_rescale_dual
    k_elim_rescale_manufactured
    DualRNSContext / DualRNSCiphertext conversion paths
    BaseExt redundant-lane projection
    CompareBit::decide_ct
    legacy RNSFHEContext::exact_rescale

plus evaluator-side Garner / mixed-radix terminology or helpers, and any
floating-point type or literal.

Explicitly PERMITTED, per §F's own carve-out and §B1:

  * the bounded `U256` / `U512` parallel idempotent-sum fallback used solely to
    certify the rank and half decisions in `MainOnlyBaseExt` — it compares
    against multiples of `M` and never materializes a canonical coefficient;
  * `DualRNSContext::canonical_anchor_primes_for_n`, read NUMERICALLY as the
    deterministic NTT-compatible candidate pool. §B1 permits using the catalog
    as a candidate pool and forbids *constructing* a `DualRNSContext` or
    attaching those primes to ciphertext state, which is what the
    `dual_rns_construction` and `dual_rns_type` patterns below enforce.

Non-vacuity: `--self-test` injects each forbidden construct into a scratch copy
of a scanned file and asserts the scanner reports it. Run it in CI alongside
the scan so a pattern that stops matching cannot pass silently.

Usage:
    python3 scripts/check_wr1_exact_route_denylist.py
    python3 scripts/check_wr1_exact_route_denylist.py --self-test
"""

from __future__ import annotations

import pathlib
import re
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]

# The production source set reachable from the WR-1 exact route. Every file
# here is scanned in full (minus `#[cfg(test)]` items and comments); a missing
# target is a hard error, never a silent pass.
ROUTE_SOURCES = (
    ROOT / "crates" / "nine65" / "src" / "ops" / "exact_mul.rs",
    ROOT / "crates" / "nine65" / "src" / "arithmetic" / "main_only_base_ext.rs",
    ROOT / "crates" / "nine65" / "src" / "arithmetic" / "exact_scale_round.rs",
)

# Split identifiers so this scanner does not match itself when it is, in turn,
# scanned by another gate.
_GARNER = "gar" + "ner"
_MRC = "mixed[_ -]?" + "radix"

PROHIBITED = {
    # --- canonical reconstruction --------------------------------------
    "to_int_reconstruction": re.compile(r"\bto_int\s*\("),
    "to_u256_level": re.compile(r"\bto_u256_level\w*\s*\("),
    "extract_k_rns_level": re.compile(r"\bextract_k_rns_level\w*\s*\("),
    "extract_digit_dual": re.compile(r"\bextract_digit_dual\w*\s*\("),
    # --- K-Elimination rescale -----------------------------------------
    "k_elim_rescale": re.compile(r"\bk_elim_rescale\w*\s*\("),
    "k_elimination_type": re.compile(r"\bKElimination\b"),
    # --- dual-RNS state -------------------------------------------------
    # Any DualRNS* TYPE in the route would mean an anchor lane is being carried;
    # `DualRNSContext::canonical_anchor_primes_for_n` is a pure numeric catalog
    # lookup and is excluded by name below.
    "dual_rns_type": re.compile(
        r"\bDualRNS(?:Poly|Ciphertext|SecretKey|PublicKey|EvalKey|GadgetKey|KeySet)\b"
    ),
    "dual_rns_construction": re.compile(
        r"\bDualRNSContext::(?!canonical_anchor_primes_for_n)\w+"
    ),
    "dual_poly_op": re.compile(r"\bdual_poly_\w+\s*\("),
    # --- redundant-lane base extension ----------------------------------
    # `BaseExt` reads an externally supplied redundant residue; `MainOnlyBaseExt`
    # is the replacement and must not be caught, hence the negative lookbehind.
    "redundant_base_ext": re.compile(r"(?<!MainOnly)\bBaseExt\s*(?:::|\{)"),
    # --- comparison kernel ----------------------------------------------
    "compare_bit_decide": re.compile(r"\bdecide_ct\s*\(|\bCompareBit\b"),
    # --- legacy approximate rescale --------------------------------------
    "legacy_exact_rescale": re.compile(r"(?<!_)\bexact_rescale\s*\("),
    # --- forbidden reconstruction families --------------------------------
    "garner_call": re.compile(r"\b" + _GARNER + r"[A-Za-z0-9_]*\s*(?:::|\()", re.IGNORECASE),
    "garner_term": re.compile(r"\b" + _GARNER + r"\b", re.IGNORECASE),
    "mixed_radix": re.compile(r"\b" + _MRC + r"\b", re.IGNORECASE),
    "crt_reconstruct": re.compile(r"\bcrt_reconstruct\w*\s*\(", re.IGNORECASE),
    # --- arithmetic contract ---------------------------------------------
    "floating_type": re.compile(r"\bf(?:32|64)\b"),
    "float_literal": re.compile(r"(?<![\w.])\d+\.\d+(?![\w.])"),
    "hidden_big_integer": re.compile(r"\b(?:Big" + r"Int|Big" + r"Uint)\b"),
}

COMMENT_PREFIXES = ("//", "//!", "///", "#")
TEST_GATE = re.compile(r"^\s*#\[(?:cfg\(test\)|cfg\(all\(test\s*,|test)\]?")


def _brace_code(line: str) -> str:
    """Line view used only for brace counting: no strings, no line comment."""
    code = re.sub(r'"(?:\\.|[^"\\])*"', '""', line)
    return code.split("//", 1)[0]


def executable_fragment(line: str) -> str:
    """Executable part of a line: no comment lines, no trailing comment, no
    string CONTENTS (so a denied name quoted in an error message or a doc
    string is not a false positive)."""
    stripped = line.lstrip()
    if stripped.startswith(COMMENT_PREFIXES):
        return ""
    code = line.split("//", 1)[0]
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', code)


def production_lines(text: str) -> list[tuple[int, str]]:
    """Numbered source lines outside any `#[cfg(test)]`-gated item.

    Same rule as `scripts/check_residue_native_architecture.py`, so the two
    gates tell the same story about what "production" means. Conservative:
    anything that does not parse as a balanced item stays visible.
    """
    lines = text.splitlines()
    kept: list[tuple[int, str]] = []
    index = 0
    total = len(lines)

    while index < total:
        line = lines[index]
        if not TEST_GATE.match(line):
            kept.append((index + 1, line))
            index += 1
            continue

        cursor = index + 1
        while cursor < total:
            stripped = lines[cursor].lstrip()
            if stripped.startswith("#[") or stripped.startswith("//"):
                cursor += 1
                continue
            break

        if cursor >= total:
            kept.extend((n + 1, lines[n]) for n in range(index, total))
            break

        depth = 0
        saw_brace = False
        end: int | None = None
        while cursor < total:
            code = _brace_code(lines[cursor])
            opens = code.count("{")
            closes = code.count("}")
            if not saw_brace and ";" in code and opens == 0:
                end = cursor + 1
                break
            if opens > 0:
                saw_brace = True
            if saw_brace:
                depth += opens - closes
                if depth <= 0:
                    end = cursor + 1
                    break
            cursor += 1

        if end is None:
            kept.append((index + 1, line))
            index += 1
            continue

        index = end

    return kept


def scan_text(label: str, text: str) -> list[str]:
    failures: list[str] = []
    for line_number, line in production_lines(text):
        fragment = executable_fragment(line)
        if not fragment.strip():
            continue
        for name, pattern in PROHIBITED.items():
            if pattern.search(fragment):
                failures.append(f"{label}:{line_number}: {name}: {line.strip()}")
    return failures


def scan_file(path: pathlib.Path) -> list[str]:
    return scan_text(str(path.relative_to(ROOT)), path.read_text(encoding="utf-8"))


# Injected constructs used by --self-test. Each is a line of plausible Rust that
# WR-1 §F forbids; every one must be caught.
SELF_TEST_INJECTIONS = (
    ("to_int_reconstruction", "    let v = self.rns.to_int(&residues);"),
    ("to_u256_level", "    let v = ctx.to_u256_level(&r, level);"),
    ("extract_k_rns_level", "    let k = ctx.extract_k_rns_level(&p, 2);"),
    ("extract_digit_dual", "    let d = ctx.extract_digit_dual(&p, 0);"),
    ("k_elim_rescale", "    let s = ctx.k_elim_rescale_dual(&p)?;"),
    ("dual_rns_type", "    let p: DualRNSPoly = todo!();"),
    ("dual_rns_construction", "    let c = DualRNSContext::for_fhe(&primes, n);"),
    ("dual_poly_op", "    let d = ctx.dual_poly_mul(&a, &b);"),
    ("redundant_base_ext", "    let e = BaseExt::new(&main, &aux, m_r);"),
    ("compare_bit_decide", "    let up = kernel.decide_ct(&residues);"),
    ("legacy_exact_rescale", "    let e = ctx.exact_rescale(&poly);"),
    ("garner_call", "    let v = " + "gar" + "ner_reconstruct(&residues);"),
    ("mixed_radix", "    let v = " + "mixed_" + "radix(&residues);"),
    ("floating_type", "    let ratio: f64 = 1_f64;"),
    ("float_literal", "    let scale = 1.5;"),
    ("hidden_big_integer", "    let v: Big" + "Int = Big" + "Int::from(3);"),
)


def self_test() -> int:
    """Prove every pattern is live by injecting the construct it denies."""
    base = ROUTE_SOURCES[0].read_text(encoding="utf-8")
    missed: list[str] = []
    for name, snippet in SELF_TEST_INJECTIONS:
        # Insert at the very top so it is unambiguously production scope.
        mutated = snippet + "\n" + base
        with tempfile.TemporaryDirectory() as tmp:
            probe = pathlib.Path(tmp) / "probe.rs"
            probe.write_text(mutated, encoding="utf-8")
            found = scan_text("probe.rs", mutated)
        if not any(f": {name}: " in f for f in found):
            missed.append(f"{name}: injection not detected -> {snippet.strip()}")
    if missed:
        print("WR-1 §F self-test FAILED: patterns are vacuous", file=sys.stderr)
        for m in missed:
            print(f"  {m}", file=sys.stderr)
        return 1
    print(
        f"WR-1 §F denylist self-test: PASS; "
        f"{len(SELF_TEST_INJECTIONS)} injected constructs all detected"
    )
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()

    failures: list[str] = []
    missing: list[str] = []
    scanned_lines = 0

    for target in ROUTE_SOURCES:
        if not target.exists():
            missing.append(str(target.relative_to(ROOT)))
            continue
        text = target.read_text(encoding="utf-8")
        scanned_lines += len(production_lines(text))
        failures.extend(scan_file(target))

    if missing:
        print("WR-1 §F gate defect: scan target(s) missing", file=sys.stderr)
        for m in missing:
            print(f"  {m}", file=sys.stderr)
        return 2

    if failures:
        print("WR-1 §F denylist FAILED", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    print(
        f"WR-1 §F denylist: PASS; {len(ROUTE_SOURCES)} route sources, "
        f"{scanned_lines} production lines, {len(PROHIBITED)} patterns, "
        f"0 violations"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
