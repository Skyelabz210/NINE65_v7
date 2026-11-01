#!/usr/bin/env python3
"""Exact-integer audit of current CLASS-F main lanes and field-backed anchors.

The script reads the Rust sources, extracts the named parameter chains and
canonical anchors, and checks primality, NTT compatibility, distinctness, and
main/anchor coprimality. It records that the current FHE anchor path is CLASS-A:
field-backed polynomial convolution plus CLASS-R K-Elimination extraction.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECURE_CONFIGS = ROOT / "crates/nine65/src/params/secure_configs.rs"
RNS = ROOT / "crates/nine65/src/arithmetic/rns.rs"
OUTPUT = ROOT / "artifacts/security/modulus_class_audit_2026-07-13.json"

PROFILE_NAMES = (
    "secure_128",
    "secure_128_deep",
    "secure_192",
    "secure_256",
)
SUPPORTED_N = (1024, 2048, 8192, 16384, 32768)
MR_BASES = (2, 325, 9375, 28178, 450775, 9780504, 1795265022)

def is_prime(value: int) -> bool:
    if value < 2:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if value == small:
            return True
        if value % small == 0:
            return False

    odd_part = value - 1
    shifts = 0
    while odd_part % 2 == 0:
        odd_part //= 2
        shifts += 1

    for base in MR_BASES:
        if base % value == 0:
            continue
        witness = pow(base, odd_part, value)
        if witness in (1, value - 1):
            continue
        for _ in range(shifts - 1):
            witness = witness * witness % value
            if witness == value - 1:
                break
        else:
            return False
    return True


def parse_integer_list(text: str) -> list[int]:
    return [int(token.replace("_", "")) for token in re.findall(r"\b[0-9][0-9_]*\b", text)]


def function_body(source: str, name: str) -> str:
    marker = f"pub fn {name}() -> Self"
    start = source.find(marker)
    if start < 0:
        raise AssertionError(f"missing profile function {name}")
    next_function = source.find("\n    pub fn ", start + len(marker))
    if next_function < 0:
        next_function = source.find("\n}", start)
    if next_function < 0:
        raise AssertionError(f"unterminated profile function {name}")
    return source[start:next_function]


def parse_profile(source: str, name: str) -> dict[str, object]:
    body = function_body(source, name)
    call = re.search(
        r"Self::new_verified\(\s*([0-9_]+),\s*vec!\[(.*?)\],\s*([0-9_]+),",
        body,
        re.DOTALL,
    )
    if call is None:
        raise AssertionError(f"unable to parse profile {name}")
    n = int(call.group(1).replace("_", ""))
    primes = parse_integer_list(call.group(2))
    plaintext_modulus = int(call.group(3).replace("_", ""))
    return {"n": n, "primes": primes, "plaintext_modulus": plaintext_modulus}


def strip_line_comments(text: str) -> str:
    """Drop `//`-style comment bodies, preserving line structure.

    `DualRNSContext::canonical_anchor_primes_for_n` annotates every anchor with
    an inline comment (`// 15 x 2^27 + 1 (~31 bits)`). Those digits are not
    anchors; scraping them was what made `all_anchors_prime` and
    `pairwise_coprime` fail. String literals are not stripped because the
    parsed region is a numeric literal list.
    """

    return "\n".join(line.split("//", 1)[0] for line in text.splitlines())


def balanced_block(text: str, open_index: int, opener: str, closer: str) -> str:
    """Return the contents between `opener` at `open_index` and its match.

    Non-greedy `.*?` stops at the first `]`, which is why the previous parser
    never saw the extra `n >= 16384` anchors appended after the initial
    `vec![...]`. Depth counting reads the whole nested block instead.
    """

    depth = 0
    for index in range(open_index, len(text)):
        char = text[index]
        if char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return text[open_index + 1 : index]
    raise AssertionError(f"unbalanced '{opener}' block while parsing anchors")


def anchor_function_body(source: str) -> str:
    # Reuse the source-contract lexer so a commented-out example cannot be
    # mistaken for the published function. It also handles block
    # comments and comment markers inside strings.
    spec = importlib.util.spec_from_file_location(
        "nine65_anchor_audit_lexer", ROOT / ".github/scripts/check_cram_recumbency.py"
    )
    assert spec is not None and spec.loader is not None
    lexer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lexer)
    source = lexer.executable_view(source)
    marker = "pub fn canonical_anchor_primes_for_n"
    start = source.find(marker)
    if start < 0:
        raise AssertionError("missing canonical anchor function")
    brace = source.find("{", start)
    if brace < 0:
        raise AssertionError("unterminated canonical anchor function")
    return balanced_block(source, brace, "{", "}")


def parse_anchors(source: str) -> dict:
    """Read the complete supported numeric Vec/conditional grammar.

    Every token is consumed. Unknown Rust operations fail closed rather than
    silently appending slices from mutually exclusive branches. Execution is
    independently compared with the actual compiled Rust body below.
    """
    body = anchor_function_body(source)
    token = re.compile(r"\s*(==|>=|<=|!=|[<>]|[A-Za-z_][A-Za-z_0-9]*|[0-9][0-9_]*|[{}\[\]();,.!&=])")
    tokens = []
    position = 0
    while position < len(body):
        match = token.match(body, position)
        if match is None:
            if body[position:].strip():
                raise AssertionError(f"unsupported anchor Rust near {body[position:position+40]!r}")
            break
        tokens.append(match.group(1))
        position = match.end()
    index = 0

    def peek():
        return tokens[index] if index < len(tokens) else None

    def take(expected=None):
        nonlocal index
        value = peek()
        if value is None or (expected is not None and value != expected):
            raise AssertionError(f"anchor grammar expected {expected!r}, got {value!r}")
        index += 1
        return value

    def number():
        value = take()
        if re.fullmatch(r"[0-9][0-9_]*", value) is None:
            raise AssertionError(f"anchor grammar expected integer, got {value!r}")
        return int(value.replace("_", ""))

    def literal():
        take("[")
        values = []
        while peek() != "]":
            values.append(number())
            if peek() != "]":
                take(",")
        take("]")
        return values

    def operations():
        take("{")
        result = []
        while peek() != "}":
            take("primes"); take(".")
            method = take(); take("(")
            if method == "truncate":
                value = number()
            elif method == "extend_from_slice":
                take("&"); value = literal()
            else:
                raise AssertionError(f"unsupported anchor Vec method {method!r}")
            take(")"); take(";")
            result.append((method, value))
        take("}")
        return result

    for expected in ("let", "mut", "primes", "=", "vec", "!"):
        take(expected)
    base = literal(); take(";")
    if not base:
        raise AssertionError("canonical anchor base must be nonempty")
    branches = []
    if peek() == "if":
        while True:
            take("if"); take("n")
            comparison = take()
            if comparison not in ("==", ">=", "<=", "!=", ">", "<"):
                raise AssertionError("unsupported anchor dimension comparison")
            bound = number()
            branches.append(((comparison, bound), operations()))
            if peek() != "else":
                break
            take("else")
            if peek() != "if":
                branches.append((None, operations()))
                break
    take("primes")
    if peek() is not None:
        raise AssertionError(f"unconsumed anchor Rust token {peek()!r}")
    return {"base": base, "branches": branches}


def anchors_for_n(anchors: dict, n: int) -> list[int]:
    result = list(anchors["base"])
    for condition, operations in anchors["branches"]:
        if condition is not None:
            comparison, value = condition
            applies = {"==": n == value, ">=": n >= value, "<=": n <= value,
                       "!=": n != value, ">": n > value, "<": n < value}[comparison]
            if not applies:
                continue
        for method, value in operations:
            if method == "truncate":
                del result[value:]
            else:
                result.extend(value)
        break
    return result


def verify_runtime_catalogue(source: str, catalogue: dict, dimensions) -> dict[str, list[int]]:
    """Compile only the parsed, side-effect-free Vec body, not the crate.

    parse_anchors must have accepted every token before Rust execution. This
    restricted body can only manipulate the numeric vector using n. rustc
    and its output executable are invoked with argument lists, never a shell.
    """
    parse_anchors(source)
    rustc = shutil.which("rustc")
    if rustc is None:
        raise AssertionError("rustc is required for the runtime anchor catalogue cross-check")
    dimensions = list(dimensions)
    assert dimensions and all(type(n) is int and 0 < n < 1 << 64 for n in dimensions)
    program = ("fn anchors(n: usize) -> Vec<u64> {" + anchor_function_body(source)
               + "}\nfn main() { for n in " + repr(dimensions)
               + ' { println!("{}:{:?}", n, anchors(n)); } }\n')
    with tempfile.TemporaryDirectory(prefix="nine65-anchor-audit-") as directory:
        code = Path(directory) / "catalogue.rs"
        binary = Path(directory) / "catalogue"
        code.write_text(program)
        subprocess.run([rustc, "--edition=2021", str(code), "-o", str(binary)],
                       check=True, capture_output=True, text=True)
        output = subprocess.run([str(binary)], check=True, capture_output=True, text=True).stdout
    runtime = {n: json.loads(values) for n, values in
               (line.split(":", 1) for line in output.splitlines())}
    if any(not basis or len(basis) != len(set(basis)) for basis in runtime.values()):
        raise AssertionError("runtime anchor bases must be nonempty and contain distinct lanes")
    expected = {str(n): anchors_for_n(catalogue, n) for n in dimensions}
    if runtime != expected:
        raise AssertionError(f"Rust/Python anchor catalogue disagreement: {runtime!r} != {expected!r}")
    return runtime


def pairwise_coprime(values: list[int]) -> bool:
    return all(
        math.gcd(left, right) == 1
        for index, left in enumerate(values)
        for right in values[index + 1 :]
    )


def main() -> int:
    secure_source = SECURE_CONFIGS.read_text(encoding="utf-8")
    rns_source = RNS.read_text(encoding="utf-8")

    profiles = {name: parse_profile(secure_source, name) for name in PROFILE_NAMES}
    anchor_sets = parse_anchors(rns_source)
    canonical_anchors_by_n = verify_runtime_catalogue(rns_source, anchor_sets, SUPPORTED_N)
    # This is a catalogue UNION, not one runtime basis. N=32768 substitutes
    # lanes rather than extending the N=16384 list.
    anchors = list(dict.fromkeys(p for basis in canonical_anchors_by_n.values() for p in basis))

    all_main = [
        prime
        for profile in profiles.values()
        for prime in profile["primes"]  # type: ignore[index]
    ]

    all_main_prime = all(is_prime(prime) for prime in all_main)
    all_main_ntt_compatible = all(
        (prime - 1) % (2 * int(profile["n"])) == 0
        for profile in profiles.values()
        for prime in profile["primes"]  # type: ignore[index]
    )
    all_profile_lanes_pairwise_coprime = all(
        pairwise_coprime(list(profile["primes"]))  # type: ignore[arg-type]
        for profile in profiles.values()
    )
    all_plaintext_moduli_valid = all(
        2 <= int(profile["plaintext_modulus"])
        and all(
            int(profile["plaintext_modulus"]) < prime
            for prime in profile["primes"]  # type: ignore[index]
        )
        for profile in profiles.values()
    )

    all_anchors_prime = all(is_prime(anchor) for anchor in anchors)
    # NTT compatibility is evaluated against the anchor set actually used at
    # that ring dimension, not the union.
    anchors_ntt_compatible = {
        str(n): all((anchor - 1) % (2 * n) == 0 for anchor in canonical_anchors_by_n[str(n)])
        for n in SUPPORTED_N
    }
    anchors_pairwise_coprime = pairwise_coprime(anchors)
    main_anchor_disjoint_and_coprime = all(
        math.gcd(prime, anchor) == 1 for prime in all_main for anchor in anchors
    )

    checks = (
        all_main_prime,
        all_main_ntt_compatible,
        all_profile_lanes_pairwise_coprime,
        all_plaintext_moduli_valid,
        all_anchors_prime,
        all(anchors_ntt_compatible.values()),
        anchors_pairwise_coprime,
        main_anchor_disjoint_and_coprime,
    )
    if not all(checks):
        raise AssertionError("one or more modulus-class checks failed")

    result: dict[str, object] = {
        "schema": 2,
        "status": "PASS",
        "arithmetic": "exact_integer_only",
        "main_lane_class": "CLASS-F",
        "current_anchor_execution_class": (
            "CLASS-A_FIELD_BACKED_NTT_PLUS_CLASS-R_K-ELIM"
        ),
        "profiles": profiles,
        "canonical_anchors": anchors,
        "canonical_anchors_by_n": canonical_anchors_by_n,
        "canonical_anchor_base_count": len(anchor_sets["base"]),
        "canonical_anchor_extended_count": max(map(len, canonical_anchors_by_n.values())),
        "canonical_anchor_union_count": len(anchors),
        "canonical_anchor_counts_by_n": {n: len(basis) for n, basis in canonical_anchors_by_n.items()},
        "canonical_anchors_scope": "union_of_dimension_specific_runtime_bases",
        "runtime_anchor_catalogue_verified": True,
        "source_sha256": {"secure_configs.rs": hashlib.sha256(secure_source.encode()).hexdigest(),
                          "rns.rs": hashlib.sha256(rns_source.encode()).hexdigest()},
        "all_main_prime": all_main_prime,
        "all_main_ntt_compatible": all_main_ntt_compatible,
        "all_profile_lanes_pairwise_coprime": all_profile_lanes_pairwise_coprime,
        "all_plaintext_moduli_valid": all_plaintext_moduli_valid,
        "all_anchors_prime": all_anchors_prime,
        "anchors_ntt_compatible_for_supported_n": anchors_ntt_compatible,
        "anchors_pairwise_coprime": anchors_pairwise_coprime,
        "main_anchor_disjoint_and_coprime": main_anchor_disjoint_and_coprime,
        "ring_only_composite_anchor_fast_path_available": False,
    }
    canonical = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    result["evidence_sha256"] = hashlib.sha256(canonical).hexdigest()

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
