#!/usr/bin/env python3
"""Source-level CT-NTT/Persistent-Montgomery gate.

This gate validates declared source invariants and public address schedules. It is
not a replacement for compiler IR/disassembly review or empirical timing tests.
All decision values are exact integers or booleans.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NTT = ROOT / "crates/nine65/src/arithmetic/ntt_fft.rs"
PERSISTENT = ROOT / "crates/nine65/src/arithmetic/persistent_montgomery.rs"
MONTGOMERY = ROOT / "crates/nine65/src/arithmetic/montgomery.rs"


def section(text: str, start: str, end: str) -> str:
    if start not in text:
        raise AssertionError(f"missing section start: {start}")
    tail = text.split(start, 1)[1]
    if end not in tail:
        raise AssertionError(f"missing section end: {end}")
    return tail.split(end, 1)[0]


def require(text: str, token: str) -> None:
    if token not in text:
        raise AssertionError(f"required token absent: {token}")


def forbid(text: str, token: str) -> None:
    if token in text:
        raise AssertionError(f"forbidden token present: {token}")


def public_butterfly_schedule(n: int) -> list[tuple[int, int, int]]:
    if n < 1 or n & (n - 1):
        raise ValueError("n must be a positive power of two")
    schedule: list[tuple[int, int, int]] = []
    width = 1
    while width < n:
        half = width
        width *= 2
        twiddle_step = n // width
        for block in range(0, n, width):
            twiddle_index = 0
            for offset in range(half):
                upper = block + offset
                lower = upper + half
                schedule.append((upper, lower, twiddle_index))
                twiddle_index += twiddle_step
    return schedule


def main() -> int:
    ntt = NTT.read_text(encoding="utf-8")
    persistent = PERSISTENT.read_text(encoding="utf-8")
    montgomery = MONTGOMERY.read_text(encoding="utf-8")

    require(ntt, "use crate::params::is_prime;")
    require(ntt, "if !is_prime(q)")
    require(ntt, "CLASS-F NTT modulus must be prime")
    require(ntt, "self.mont.montgomery_add")
    require(ntt, "self.mont.montgomery_sub")
    require(ntt, "self.mont.montgomery_neg")
    forbid(ntt, "fn mont_add")
    forbid(ntt, "fn mont_sub")
    forbid(ntt, "if sum >= self.q")
    forbid(ntt, "if ai >= bi")

    ntt_add = section(ntt, "pub fn add(&self", "pub fn sub(&self")
    ntt_sub = section(ntt, "pub fn sub(&self", "pub fn neg(&self")
    ntt_neg = section(ntt, "pub fn neg(&self", "pub fn scalar_mul(&self")
    for name, body in (("ntt_add", ntt_add), ("ntt_sub", ntt_sub), ("ntt_neg", ntt_neg)):
        if "if " in body:
            raise AssertionError(f"data-dependent branch candidate in {name}")

    require(persistent, "Montgomery modulus must be odd")
    require(persistent, "Montgomery modulus must be below 2^63")
    require(persistent, "for bit_index in (0..64).rev()")
    require(persistent, "odd composite CLASS-R")

    persistent_sections = (
        ("redc", "pub fn redc", "pub fn mul"),
        ("mul", "pub fn mul", "pub fn add"),
        ("add", "pub fn add", "pub fn sub"),
        ("sub", "pub fn sub", "pub fn neg"),
        ("neg", "pub fn neg", "pub fn square"),
        ("pow", "pub fn pow", "pub fn inverse"),
    )
    for name, start, end in persistent_sections:
        body = section(persistent, start, end)
        if "if " in body:
            raise AssertionError(f"data-dependent branch candidate in persistent {name}")

    require(montgomery, "pub fn montgomery_reduce")
    require(montgomery, "overflowing_sub(self.q)")
    require(montgomery, "pub fn montgomery_add")
    require(montgomery, "pub fn montgomery_sub")

    schedule_counts: dict[str, int] = {}
    digest = hashlib.sha256()
    for n in (8, 16, 1024):
        schedule = public_butterfly_schedule(n)
        expected_count = n * (n.bit_length() - 1) // 2
        if len(schedule) != expected_count:
            raise AssertionError(f"schedule length mismatch for N={n}")
        schedule_counts[str(n)] = len(schedule)
        for upper, lower, twiddle in schedule:
            digest.update(upper.to_bytes(8, "little"))
            digest.update(lower.to_bytes(8, "little"))
            digest.update(twiddle.to_bytes(8, "little"))

    result = {
        "schema": 1,
        "status": "PASS",
        "scope": "source_invariants_and_public_schedule_only",
        "class_f_prime_guard": True,
        "ntt_branchless_coefficient_ops": True,
        "persistent_branchless_core": True,
        "class_r_odd_composite_support": True,
        "public_schedule_counts": schedule_counts,
        "public_schedule_sha256": digest.hexdigest(),
        "compiler_disassembly_verified": False,
        "empirical_timing_verified": False,
        "cache_line_alignment_verified": False,
    }
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
