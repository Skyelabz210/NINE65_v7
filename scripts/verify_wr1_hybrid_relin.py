#!/usr/bin/env python3
"""WR-1 integer-only oracle for mod-Q hybrid RNS-limb relinearization.

The route decomposes each existing main-lane residue locally in base 2^10 and
uses CRT-idempotent evaluation-key messages whose RNS representation is zero
on every main lane except the source lane.  No canonical coefficient, Garner
walk, mixed-radix state, auxiliary ciphertext lane, or floating-point value is
needed.

This harness checks the underlying ring identity independently of the Rust
implementation for every named production main basis.
"""

from __future__ import annotations

from math import prod


BASE_BITS = 10
BASE = 1 << BASE_BITS
DIGIT_MASK = BASE - 1
RING_N = 8
SAMPLES = 64

MAIN_3 = (998_244_353, 985_661_441, 754_974_721)
MAIN_4 = MAIN_3 + (469_762_049,)
MAIN_5 = MAIN_4 + (167_772_161,)
MAIN_6 = MAIN_5 + (595_591_169,)

CONFIGS = (
    ("secure_128", MAIN_3),
    ("secure_128_deep", MAIN_4),
    ("secure_192", MAIN_5),
    ("secure_256", MAIN_6),
)


def next_state(state: int) -> int:
    return (
        state * 6_364_136_223_846_793_005
        + 1_442_695_040_888_963_407
    ) & ((1 << 256) - 1)


def negacyclic(left: tuple[int, ...], right: tuple[int, ...]) -> tuple[int, ...]:
    if len(left) != len(right):
        raise AssertionError("polynomial length mismatch")
    n = len(left)
    output = [0] * n
    for i, lhs in enumerate(left):
        for j, rhs in enumerate(right):
            index = i + j
            term = lhs * rhs
            if index < n:
                output[index] += term
            else:
                output[index - n] -= term
    return tuple(output)


def negacyclic_mod(
    left: tuple[int, ...], right: tuple[int, ...], modulus: int
) -> tuple[int, ...]:
    return tuple(value % modulus for value in negacyclic(left, right))


def verify_config(label: str, main: tuple[int, ...]) -> tuple[int, int]:
    modulus = prod(main)
    state = 0x9650_2026_0903_1000 + len(main)
    checks = 0

    digits_per_lane = max(
        (lane.bit_length() + BASE_BITS - 1) // BASE_BITS for lane in main
    )
    if digits_per_lane != 3:
        raise AssertionError(
            f"{label}: expected three base-2^10 digits per current main lane, "
            f"got {digits_per_lane}"
        )

    for _ in range(SAMPLES):
        # c2 is the canonical, post-scale-round degree-2 polynomial supplied to
        # relinearization.  Secret coefficients use the production-small style
        # range only to generate a nontrivial s^2 polynomial; the identity under
        # test holds independently of this range.
        c2: list[int] = []
        secret: list[int] = []
        for _ in range(RING_N):
            state = next_state(state)
            c2.append(state % modulus)
            state = next_state(state)
            secret.append((state % 7) - 3)

        secret_sq = negacyclic(tuple(secret), tuple(secret))

        for target_index, target_modulus in enumerate(main):
            c2_target = tuple(value % target_modulus for value in c2)
            secret_sq_target = tuple(
                value % target_modulus for value in secret_sq
            )
            expected = negacyclic_mod(
                c2_target, secret_sq_target, target_modulus
            )

            accumulated = [0] * RING_N

            # For source lane i, g_i is the CRT idempotent.  Its RNS image is
            # exactly 1 on lane i and 0 on every other main lane, so the
            # key-message g_i * BASE^j * s^2 can be formed at keygen directly
            # in RNS form without ever materializing g_i as a wide integer.
            for source_index, source_modulus in enumerate(main):
                source_residues = tuple(
                    value % source_modulus for value in c2
                )

                for digit_index in range(digits_per_lane):
                    digit_poly = tuple(
                        (value >> (digit_index * BASE_BITS)) & DIGIT_MASK
                        for value in source_residues
                    )

                    if target_index == source_index:
                        scale = pow(BASE, digit_index, target_modulus)
                        key_message = tuple(
                            (scale * residue) % target_modulus
                            for residue in secret_sq_target
                        )
                    else:
                        key_message = (0,) * RING_N

                    contribution = negacyclic_mod(
                        digit_poly, key_message, target_modulus
                    )
                    accumulated = [
                        (left + right) % target_modulus
                        for left, right in zip(accumulated, contribution)
                    ]

            if tuple(accumulated) != expected:
                raise AssertionError(
                    f"{label}: hybrid relin identity mismatch on target lane "
                    f"{target_index}"
                )
            checks += RING_N

    return checks, digits_per_lane


def main() -> None:
    total = 0
    print("WR-1 hybrid RNS-limb relinearization algebra gate")
    print("all arithmetic: integer-only")
    print(f"base_bits={BASE_BITS}; ring_n={RING_N}; samples={SAMPLES}")

    for label, main_base in CONFIGS:
        checks, digits = verify_config(label, main_base)
        total += checks
        print(
            f"{label}: PASS; lanes={len(main_base)}; "
            f"digits_per_lane={digits}; checks={checks}"
        )

    print(f"WR-1 hybrid relin gate: PASS; exact_checks={total}")


if __name__ == "__main__":
    main()
