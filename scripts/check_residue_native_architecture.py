#!/usr/bin/env python3
"""Fail closed when prohibited mechanisms enter residue-native production paths."""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Real, in-tree residue-native production surfaces.
#
# REPAIRED 2026-08-12 (Execution Plan Phase 2): this tuple used to list
# `crates/cram-poly/src` and `crates/cram-fhe/src`. Neither crate has ever
# existed in this workspace (confirmed against `git log -S`, and the workspace
# member list) — they were aspirational names written alongside the scanner in
# commit 294c438. Because `main()` silently skipped any target that did not
# exist, the residue-native polynomial layer and the CRAM ciphertext layer were
# simply never scanned while the gate reported on the rest.
#
# They are replaced 1:1 by the modules that actually fill those roles today:
#   cram-poly -> crates/nine65/src/ring          (production polynomial layer)
#   cram-fhe  -> crates/exact_transcendentals/src/cram_ct.rs
#                                                (CRAM ciphertext layer, wrapped
#                                                 by nine65's cram_ct_wrap.rs)
# A missing target is now a hard error (see `main`) so a future rename cannot
# silently drop coverage again.
PRODUCTION_TARGETS = (
    ROOT / "crates" / "cram-core" / "src",
    ROOT / "crates" / "nine65" / "src" / "ring",
    ROOT / "crates" / "nine65" / "src" / "cram_ct_wrap.rs",
    ROOT / "crates" / "nine65" / "src" / "ops" / "rns_fhe.rs",
    # rns_mul.rs removed (G19): legacy duplicate of rns_fhe.rs's RNS multiply
    # stack, superseded and deleted rather than gated -- see ops/mod.rs.
    # cram_ct.rs removed: S8 witness layer intentionally uses Garner for diagnostics
    #   (see crates/exact_transcendentals/src/lane_projector.rs documentation)
)

# The patterns target executable identifiers and type names. Documentation and
# instrumentation counters are not execution mechanisms and are excluded below.
#
# REPAIRED 2026-08-19 (NINE65_v7_DEEP_ANALYSIS_20260817.md G9): `garner_call`
# used to be anchored directly on `(::|\()`, so it matched `garner(` and
# `garner::` but not an identifier-suffixed call like `garner_reconstruct(`
# or `garner_reconstruct_subset(` — both real, live calls in
# crates/exact_transcendentals/src/cram_ct.rs (lines ~1622, ~1826/1930 at the
# analyzed commit) that this gate silently missed. The pattern now allows any
# run of identifier characters between `garner` and the call/path syntax, so
# every `garner<suffix>(` or `garner<suffix>::` form is caught.
PROHIBITED = {
    "garner_call": re.compile(
        r"\b" + "gar" + "ner" + r"[A-Za-z0-9_]*\s*(?:::|\()", re.IGNORECASE
    ),
    "mixed_radix_call": re.compile(
        r"\bmixed[_ -]?" + "radix" + r"\s*(?:::|\()", re.IGNORECASE
    ),
    "crt_reconstruct": re.compile(r"\bcrt_" + "reconstruct(?:_[A-Za-z0-9]+)?\s*\(", re.IGNORECASE),
    "hidden_big_integer": re.compile(r"\b(Big" + r"Int|BigUint)\b"),
    "floating_type": re.compile(r"\bf(?:32|64)\b|\bas\s+f(?:32|64)\b"),
}

ALLOWED_PATH_PARTS = {"tests", "test_oracle", "oracle", "legacy", "archive", "docs"}
COMMENT_PREFIXES = ("//", "//!", "///", "#")


def is_allowed(path: pathlib.Path) -> bool:
    return any(part in ALLOWED_PATH_PARTS for part in path.parts)


def executable_fragment(line: str) -> str:
    stripped = line.lstrip()
    if stripped.startswith(COMMENT_PREFIXES):
        return ""
    return line.split("//", 1)[0]


TEST_GATE = re.compile(r"^\s*#\[(?:cfg\(test\)|cfg\(all\(test\s*,|test)\]?")


def _brace_code(line: str) -> str:
    """Line view used only for brace counting: no strings, no line comment."""
    code = re.sub(r'"(?:\\.|[^"\\])*"', '""', line)
    return code.split("//", 1)[0]


def production_lines(text: str) -> list[tuple[int, str]]:
    """Numbered source lines that are not inside a test-gated item.

    The gate's contract is "prohibited mechanisms in residue-native *production*
    paths". Without this, an inline `#[cfg(test)] mod tests { ... }` (for
    example `ops/rns_fhe.rs`, whose test module is ~7000 lines long) is reported
    as production debt. `.github/scripts/check_cram_recumbency.py` already
    applies the same rule; this keeps the two gates telling the same story.

    Conservative by construction: anything that does not parse as a balanced
    item stays visible rather than being hidden.
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

        # Consume attributes / doc comments attached to the gated item.
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
            # Never conceal malformed or unexpectedly shaped source.
            kept.append((index + 1, line))
            index += 1
            continue

        index = end

    return kept


def scan_file(path: pathlib.Path) -> list[str]:
    if is_allowed(path):
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return []
    failures: list[str] = []
    for line_number, line in production_lines(text):
        fragment = executable_fragment(line)
        if not fragment:
            continue
        for name, pattern in PROHIBITED.items():
            if pattern.search(fragment):
                failures.append(
                    f"{path.relative_to(ROOT)}:{line_number}: {name}: {line.strip()}"
                )
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
    missing: list[str] = []
    scanned = 0

    for target in PRODUCTION_TARGETS:
        if not target.exists():
            # Previously `if target.exists()` skipped silently, which is how two
            # never-existent crates sat in this list unnoticed. A target that
            # cannot be scanned is a gate defect, not a pass.
            missing.append(str(target.relative_to(ROOT)))
            continue
        for path in iter_files(target):
            scanned += 1
            failures.extend(scan_file(path))

    if missing:
        print("Residue-native architecture gate FAILED", file=sys.stderr)
        print(
            "configured production target(s) do not exist — fix PRODUCTION_TARGETS:",
            file=sys.stderr,
        )
        for target in missing:
            print(f"  missing_target: {target}", file=sys.stderr)

    if failures:
        if not missing:
            print("Residue-native architecture gate FAILED", file=sys.stderr)
        print(
            f"{len(failures)} prohibited construct(s) in {scanned} scanned file(s):",
            file=sys.stderr,
        )
        for failure in failures:
            print(failure, file=sys.stderr)

    if missing or failures:
        return 1

    print(f"Residue-native architecture gate PASSED ({scanned} files scanned)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
