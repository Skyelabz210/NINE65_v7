#!/usr/bin/env python3
"""Independent integer-only oracle for the fixed-work CompareBit integration."""

from __future__ import annotations

from itertools import product
from pathlib import Path


MASK64 = (1 << 64) - 1
MASK128 = (1 << 128) - 1
MASK256 = (1 << 256) - 1


def subborrow_word(a: int, b: int, borrow: int) -> int:
    widened = (a - b - borrow) & MASK128
    return (widened >> 127) & 1


def ge_mask_u256(left: int, right: int) -> int:
    left_words = [(left >> (64 * index)) & MASK64 for index in range(4)]
    right_words = [(right >> (64 * index)) & MASK64 for index in range(4)]
    borrow = 0
    for left_word, right_word in zip(left_words, right_words):
        borrow = subborrow_word(left_word, right_word, borrow)
    return MASK256 if borrow == 0 else 0


def select_mask_u256(if_false: int, if_true: int, true_mask: int) -> int:
    return ((if_false & (MASK256 ^ true_mask)) | (if_true & true_mask)) & MASK256


def compute_barrett_mu(modulus: int) -> int:
    half = 1 << 127
    quotient = half // modulus
    remainder = half % modulus
    return 2 * quotient + (2 * remainder) // modulus


def barrett_reduce_ct(value: int, modulus: int, mu: int) -> int:
    quotient_hat = (value * mu) >> 128
    remainder = (value - quotient_hat * modulus) & MASK128
    result = remainder & MASK64
    for _ in range(2):
        candidate = (result - modulus) & MASK64
        keep_candidate = MASK64 if result >= modulus else 0
        result = (result & (MASK64 ^ keep_candidate)) | (candidate & keep_candidate)
    return result


def fixed_work_compare(primes: tuple[int, ...], residues: tuple[int, ...]) -> bool:
    modulus = 1
    for prime in primes:
        modulus *= prime

    total = 0
    for prime, residue in zip(primes, residues):
        partial = modulus // prime
        inverse = pow(partial, -1, prime)
        mu = compute_barrett_mu(prime)
        coefficient = barrett_reduce_ct(residue * inverse, prime, mu)
        assert coefficient == (residue * inverse) % prime
        total += coefficient * partial

    assert total < len(primes) * modulus
    reduced = total & MASK256
    for _ in range(1, len(primes)):
        candidate = (reduced - modulus) & MASK256
        reduced = select_mask_u256(reduced, candidate, ge_mask_u256(reduced, modulus))

    assert reduced == total % modulus
    return ge_mask_u256(reduced, modulus - modulus // 2) != 0


def xorshift64(state: int) -> int:
    state ^= (state << 13) & MASK64
    state ^= state >> 7
    state ^= (state << 17) & MASK64
    return state & MASK64


def verify_u256_comparison() -> int:
    edges = (
        0,
        1,
        (1 << 63) - 1,
        1 << 63,
        (1 << 127) - 1,
        1 << 127,
        (1 << 127) + 1,
        (1 << 128) - 1,
        1 << 128,
        (1 << 191) - 1,
        1 << 191,
        (1 << 255) - 1,
        1 << 255,
        MASK256,
    )
    checked = 0
    for left, right in product(edges, repeat=2):
        assert (ge_mask_u256(left, right) != 0) == (left >= right)
        checked += 1

    state = 0x9650_2026_0901_0001
    for _ in range(100_000):
        left = 0
        right = 0
        for word in range(4):
            state = xorshift64(state)
            left |= state << (64 * word)
            state = xorshift64(state)
            right |= state << (64 * word)
        assert (ge_mask_u256(left, right) != 0) == (left >= right)
        checked += 1
    return checked


def verify_small_bases() -> int:
    checked = 0
    for primes in ((3, 5), (3, 5, 7), (3, 5, 7, 11, 13)):
        modulus = 1
        for prime in primes:
            modulus *= prime
        for value in range(modulus):
            residues = tuple(value % prime for prime in primes)
            assert fixed_work_compare(primes, residues) == (2 * value >= modulus)
            checked += 1
    assert checked == 15_135
    return checked


def verify_production_bases() -> int:
    bases = (
        (998_244_353, 985_661_441, 754_974_721, 469_762_049),
        (998_244_353, 985_661_441, 754_974_721, 469_762_049, 167_772_161),
        (
            998_244_353,
            985_661_441,
            754_974_721,
            469_762_049,
            167_772_161,
            595_591_169,
        ),
    )
    state = 0x9650_2026_0901_0002
    checked = 0
    for primes in bases:
        modulus = 1
        for prime in primes:
            modulus *= prime
        boundary = {
            0,
            1,
            modulus // 2 - 1,
            modulus // 2,
            modulus // 2 + 1,
            modulus - 2,
            modulus - 1,
        }
        for value in sorted(boundary):
            residues = tuple(value % prime for prime in primes)
            assert fixed_work_compare(primes, residues) == (2 * value >= modulus)
            checked += 1

        for _ in range(50_000):
            value = 0
            for word in range(4):
                state = xorshift64(state)
                value |= state << (64 * word)
            value %= modulus
            residues = tuple(value % prime for prime in primes)
            assert fixed_work_compare(primes, residues) == (2 * value >= modulus)
            checked += 1
    return checked


def verify_rust_wiring(repository: Path) -> int:
    compare_source = (
        repository / "crates/nine65/src/arithmetic/compare_bit.rs"
    ).read_text(encoding="utf-8")
    fhe_source = (
        repository / "crates/nine65/src/ops/rns_fhe.rs"
    ).read_text(encoding="utf-8")

    start = compare_source.index("    pub fn decide_ct(")
    end = compare_source.index("    /// The basis product", start)
    function = compare_source[start:end]
    code_lines = [line.split("//", 1)[0] for line in function.splitlines()]
    code = "\n".join(code_lines)

    assert "while " not in code
    assert "decide_with_path" not in code
    assert " / " not in code
    assert " % " not in code
    assert "for _ in 1..self.main.len()" in code
    assert "select_mask_ct" in code
    assert "ge_mask_ct" in code
    assert fhe_source.count("is_upper_half_main(&rns_coeff") == 4
    assert "compare_bits_by_level" in fhe_source
    return 8


def main() -> None:
    repository = Path(__file__).resolve().parents[1]
    comparison_checks = verify_u256_comparison()
    small_checks = verify_small_bases()
    production_checks = verify_production_bases()
    source_checks = verify_rust_wiring(repository)
    total = comparison_checks + small_checks + production_checks + source_checks
    print(
        "compare_bit fixed-work verification: "
        f"{total} exact checks "
        f"({comparison_checks} U256 ordering, "
        f"{small_checks} exhaustive small-basis, "
        f"{production_checks} production-basis, "
        f"{source_checks} source-contract)"
    )


if __name__ == "__main__":
    main()
