#!/usr/bin/env python3
"""Fail closed on floating-point in owned Rust benchmark/test/audit sources.

Issue #90: `check_no_floats_runtime.sh` already gates production code in
`crates/nine65/src`, but nothing scanned the benchmark and test harnesses
that measure it — exactly where a `Duration` cast to `f64` for a ratio is
easiest to reach for. Two ignored microbench sections
(`crates/nine65/src/arithmetic/compare_bit_verify.rs`,
`crates/nine65/src/arithmetic/base_ext.rs`) did exactly that. This gate
closes that gap for the surfaces the issue names — benches, tests, examples,
and the standalone audit/benchmark binaries under `src/bin/` — across every
crate in the workspace.

Unlike a naive `grep -r f64`, this strips `//` / `/* */` comments and
double-quoted string CONTENTS before matching, so a scanner self-test array
like `["f32", "f64"]` (see `crates/exact_transcendentals/tests/cram_gates.rs`
and `crates/nine65/tests/audit_regressions.rs`, both real, both scanned by
this gate) or a doc line reading "zero f32/f64" does not false-positive —
proved in `test_check_no_floats_benches_and_tests.py`, not just asserted.

It also flags a bare decimal literal such as `let x = 9.2;`: Rust infers
`f64` for that with no `f64` token anywhere in the source, and this repo had
shipped exactly that shape (`crates/nine65/src/bin/resilience_audit.rs`,
fixed alongside this gate) — a plain `f32`/`f64` token scan would have missed
it entirely.

Production `src/` (minus `src/bin/`) is intentionally out of scope here: it
already has `check_no_floats_runtime.sh` for nine65's crypto/arithmetic hot
path (with its own documented exception, `compiler.rs::NoiseModel`) and each
other crate's own gate where one exists (e.g.
`crates/exact_transcendentals/scripts/check_no_floats.py`). This gate is
specifically the "benches and test harnesses" scope issue #90 names.

One more seam: `check_no_floats_runtime.sh` deliberately SKIPS every
`#[cfg(test)]`-gated item, on the theory that test code is outside its
"production hot path" mandate. That skip is exactly how the two files issue
#90 opens with — `compare_bit_verify.rs` and `base_ext.rs`, both
`#[cfg(test)] mod tests { ... }` blocks holding an `#[ignore]`d microbench —
went unnoticed, and a third turned up the same way while fixing them:
`ops/rns_fhe.rs`'s `#[cfg(all(test, ...))] mod gate { fn gate_harness() }`,
the "canonical #19 suite" this issue's own verification section names. This
gate covers exactly those `#[cfg(test)]` regions in `NAMED_TEST_GATED_FILES`
below (never those files' surrounding production code, which the runtime gate
already owns) — a curated list, not a directory walk, because
`crates/nine65/src/security/ct_verification.rs` has the same
`#[cfg(test)] mod { ... }` shape and genuinely needs floating point (a
dudect-style Welch's-t-test constant-time verification suite, needing a
square root for standard error) for a fundamentally different, larger
numerical problem than the ratio/percentage reporting this issue is about;
see the issue #90 PR description for why it is deliberately not converted.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

# One directory per crate that is squarely "benchmark or test harness" in the
# sense issue #90 names. `src/bin` holds this crate's standalone audit and
# comparison binaries (`dpa_simulation.rs`, `keygen_benchmark.rs`, ...) —
# demo/measurement tools, not library code, but owned Rust source all the
# same, and issue #90 item 5 is explicit: "do not exclude an owned file
# merely because it is a benchmark."
TARGET_SUBDIRS = ("benches", "tests", "examples", "src/bin")

# Same construct this repo already uses for the equivalent check in
# `scripts/check_residue_native_architecture.py`'s `floating_type` pattern —
# kept identical so the two gates never disagree on what counts.
FLOAT_TOKEN = re.compile(r"\bf(?:32|64)\b|\bas\s+f(?:32|64)\b")

# A bare decimal literal: digits, a single '.', more digits. The lookarounds
# exclude the two shapes that are NOT a float literal but match `\d\.\d`
# naively: range syntax (`0..10` never has a digit directly touching a lone
# '.' on both sides once the second '.' is accounted for) and tuple-of-tuple
# field access (`a.0.1` — the '.' immediately before "0" fails the
# not-preceded-by-'.' check, and likewise for "1").
DECIMAL_LITERAL = re.compile(r"(?<![.\w])[0-9][0-9_]*\.[0-9][0-9_]*(?![.\w])")

# Individual production-tree files that hold a `#[cfg(test)]`-gated
# benchmark/ratio-reporting harness — scanned ONLY inside their gated
# region(s) (see `test_gated_lines`), never as whole files, since their
# surrounding production code is already `check_no_floats_runtime.sh`'s job.
# See the module docstring for why this is a curated list rather than a
# directory walk.
NAMED_TEST_GATED_FILES = (
    "crates/nine65/src/arithmetic/compare_bit_verify.rs",
    "crates/nine65/src/arithmetic/base_ext.rs",
    "crates/nine65/src/ops/rns_fhe.rs",
)

# Recognizes the attribute that opens a #[cfg(test)]-gated item — identical
# to `check_residue_native_architecture.py`'s `TEST_GATE`, so the two gates
# agree on what counts as "test-gated".
TEST_GATE = re.compile(r"^\s*#\[(?:cfg\(test\)|cfg\(all\(test\s*,|test)\]?")


def code_only(src: str) -> str:
    """Strip `//`, `/* */` comments and `"..."` string CONTENTS.

    Not a full Rust lexer — raw strings (`r"..."`) are not special-cased, so
    a `"` inside one would end the "string" early; the residual risk is
    scanning slightly more of a raw string's own text as code, which can
    only ADD a candidate match for a human to look at, never hide a real one
    silently. Newlines inside a stripped block comment or string are
    preserved so line numbers in the report stay aligned with the source
    file the reader has open.
    """
    out: list[str] = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            i += 2
            while i + 1 < n and not (src[i] == "*" and src[i + 1] == "/"):
                if src[i] == "\n":
                    out.append("\n")
                i += 1
            i = min(i + 2, n)
            continue
        if c == '"':
            out.append('"')
            i += 1
            while i < n and src[i] != '"':
                if src[i] == "\n":
                    out.append("\n")
                    i += 1
                elif src[i] == "\\" and i + 1 < n:
                    i += 2
                else:
                    i += 1
            if i < n:
                out.append('"')
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _brace_code(line: str) -> str:
    """Line view used only for brace counting: no strings, no line comment."""
    code = re.sub(r'"(?:\\.|[^"\\])*"', '""', line)
    return code.split("//", 1)[0]


def test_gated_lines(text: str) -> list[tuple[int, str]]:
    """1-indexed `(line_number, line)` pairs inside a `#[cfg(test)]`-gated item.

    The complement of what `check_no_floats_runtime.sh` skips: it walks past
    a `#[cfg(test)]`/`#[cfg(all(test, ...))]`/`#[test]` attribute and
    everything the item it gates spans (matched by brace depth, or by a
    trailing `;` for an attribute-only statement), on the theory that test
    code is outside its "production hot path" mandate. This collects exactly
    that span instead, for `NAMED_TEST_GATED_FILES` to be scanned by.
    """
    lines = text.splitlines()
    kept: list[tuple[int, str]] = []
    index = 0
    total = len(lines)

    while index < total:
        line = lines[index]
        if not TEST_GATE.match(line):
            index += 1
            continue

        gate_start = index
        cursor = index + 1
        while cursor < total:
            stripped = lines[cursor].lstrip()
            if stripped.startswith("#[") or stripped.startswith("//"):
                cursor += 1
                continue
            break

        if cursor >= total:
            kept.extend((n + 1, lines[n]) for n in range(gate_start, total))
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
            index += 1
            continue

        kept.extend((n + 1, lines[n]) for n in range(gate_start, end))
        index = end

    return kept


def scan_test_gated_regions(path: pathlib.Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return []
    code_lines = code_only(text).splitlines()
    text_lines = text.splitlines()

    failures: list[str] = []
    for line_no, _ in test_gated_lines(text):
        idx = line_no - 1
        if idx >= len(code_lines):
            continue
        failures.extend(
            _match_line(path, line_no, code_lines[idx], text_lines[idx])
        )
    return failures


def _match_line(path: pathlib.Path, line_no: int, stripped: str, raw: str) -> list[str]:
    try:
        rel = path.relative_to(ROOT)
    except ValueError:
        rel = path
    matches = []
    for pattern, label in (
        (FLOAT_TOKEN, "float_type_or_cast"),
        (DECIMAL_LITERAL, "bare_decimal_literal"),
    ):
        if pattern.search(stripped):
            matches.append(f"{rel}:{line_no}: {label}: {raw.strip()}")
    return matches


def iter_target_files() -> list[pathlib.Path]:
    crates_dir = ROOT / "crates"
    files: list[pathlib.Path] = []
    for crate_dir in sorted(p for p in crates_dir.iterdir() if p.is_dir()):
        for subdir in TARGET_SUBDIRS:
            base = crate_dir / subdir
            if base.is_dir():
                files.extend(sorted(base.rglob("*.rs")))
    return files


def scan_file(path: pathlib.Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return []
    text_lines = text.splitlines()
    code_lines = code_only(text).splitlines()

    failures: list[str] = []
    for line_no, (raw, stripped) in enumerate(zip(text_lines, code_lines), start=1):
        failures.extend(_match_line(path, line_no, stripped, raw))
    return failures


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv

    failures: list[str] = []
    scanned = 0

    if args:
        for a in args:
            path = pathlib.Path(a)
            if not path.is_file() or path.suffix != ".rs":
                continue
            scanned += 1
            failures.extend(scan_file(path))
    else:
        for path in iter_target_files():
            scanned += 1
            failures.extend(scan_file(path))
        for rel in NAMED_TEST_GATED_FILES:
            path = ROOT / rel
            if not path.is_file():
                print(f"::error::missing NAMED_TEST_GATED_FILES entry: {rel}", file=sys.stderr)
                return 1
            scanned += 1
            failures.extend(scan_test_gated_regions(path))

    if failures:
        print(
            "No-floats (benches/tests/bin) gate FAILED — "
            f"{len(failures)} violation(s) in {scanned} scanned file(s):",
            file=sys.stderr,
        )
        for failure in failures:
            print(failure, file=sys.stderr)
        print(
            "Fix: replace with integer-scaled arithmetic (see "
            "crates/nine65/src/arithmetic/integer_math.rs: format_ratio, "
            "checked_scaled_ratio, integer_sqrt_u128).",
            file=sys.stderr,
        )
        return 1

    print(f"No-floats (benches/tests/bin) gate PASSED ({scanned} files scanned)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
