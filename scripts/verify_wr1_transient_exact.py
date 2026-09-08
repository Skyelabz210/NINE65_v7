#!/usr/bin/env python3
"""WR-1 independent integer-only oracle for derived-transient exact multiply.

This harness pins the arithmetic obligations that must hold before T1.4 is
wired into the Rust evaluator:

1. derive a *centered* transient auxiliary representation from main residues
   without materializing canonical X;
2. carry a negacyclic tensor product in main and transient auxiliary bases;
3. apply the same exact BFV scale-and-round identity as ExactScaleRound;
4. certify the minimum canonical transient basis required by each named
   production configuration.

No floating-point arithmetic is used.
"""

from __future__ import annotations

from math import gcd, prod


T = 65_537

MAIN_3 = (998_244_353, 985_661_441, 754_974_721)
MAIN_4 = MAIN_3 + (469_762_049,)
MAIN_5 = MAIN_4 + (167_772_161,)
MAIN_6 = MAIN_5 + (595_591_169,)

AUX_10 = (
    2_013_265_921,
    2_281_701_377,
    2_483_027_969,
    2_885_681_153,
    3_221_225_473,
    3_221_422_081,
    3_222_306_817,
    3_222_372_353,
    3_222_568_961,
    3_222_962_177,
)

CONFIGS = (
    ("secure_128", 8_192, MAIN_3, 4),
    ("secure_128_deep", 8_192, MAIN_4, 5),
    ("secure_192", 16_384, MAIN_5, 6),
    ("secure_256", 16_384, MAIN_6, 7),
)


def canonical_coefficients(residues: tuple[int, ...], main: tuple[int, ...]) -> tuple[int, ...]:
    modulus = prod(main)
    coefficients: list[int] = []
    for residue, lane in zip(residues, main):
        if residue < 0 or residue >= lane:
            raise AssertionError("non-canonical main residue")
        partial = modulus // lane
        inverse = pow(partial % lane, -1, lane)
        coefficients.append((residue * inverse) % lane)
    return tuple(coefficients)


def canonical_projection(
    residues: tuple[int, ...],
    main: tuple[int, ...],
    aux: tuple[int, ...],
) -> tuple[tuple[int, ...], int, int]:
    """MainOnlyBaseExt identity, plus exact rank numerator for the oracle."""
    modulus = prod(main)
    coefficients = canonical_coefficients(residues, main)
    numerator = sum(
        coefficient * (modulus // lane)
        for coefficient, lane in zip(coefficients, main)
    )
    rank = numerator // modulus
    if rank < 0 or rank >= len(main):
        raise AssertionError("canonical rank outside proven range")

    output: list[int] = []
    for aux_lane in aux:
        synthesis = sum(
            coefficient * ((modulus // lane) % aux_lane)
            for coefficient, lane in zip(coefficients, main)
        ) % aux_lane
        output.append((synthesis - rank * (modulus % aux_lane)) % aux_lane)
    return tuple(output), rank, numerator


def centered_projection(
    residues: tuple[int, ...],
    main: tuple[int, ...],
    aux: tuple[int, ...],
) -> tuple[tuple[int, ...], bool]:
    """Project the centered lift without ever constructing X = N - rank*M.

    Let N = sum_i c_i * M_i and rank = floor(N/M).  The canonical value lies
    in the upper half exactly when

        N >= rank*M + ceil(M/2)

    which is equivalent, for odd M, to

        2*N >= (2*rank + 1)*M.

    The comparison is made directly against the parallel idempotent sum.  When
    true, subtract M only *inside each transient auxiliary lane*.
    """
    canonical, rank, numerator = canonical_projection(residues, main, aux)
    modulus = prod(main)
    upper_half = 2 * numerator >= (2 * rank + 1) * modulus
    if not upper_half:
        return canonical, False
    centered = tuple(
        (residue - (modulus % aux_lane)) % aux_lane
        for residue, aux_lane in zip(canonical, aux)
    )
    return centered, True


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


def residue_limbs(poly: tuple[int, ...], base: tuple[int, ...]) -> tuple[tuple[int, ...], ...]:
    return tuple(tuple(coefficient % lane for coefficient in poly) for lane in base)


def transient_tensor(
    left_main: tuple[tuple[int, ...], ...],
    right_main: tuple[tuple[int, ...], ...],
    main: tuple[int, ...],
    aux: tuple[int, ...],
) -> tuple[tuple[tuple[int, ...], ...], tuple[tuple[int, ...], ...]]:
    n = len(left_main[0])
    left_aux = [[0] * n for _ in aux]
    right_aux = [[0] * n for _ in aux]

    for coefficient_index in range(n):
        left_residues = tuple(left_main[lane][coefficient_index] for lane in range(len(main)))
        right_residues = tuple(right_main[lane][coefficient_index] for lane in range(len(main)))
        left_projection, _ = centered_projection(left_residues, main, aux)
        right_projection, _ = centered_projection(right_residues, main, aux)
        for lane in range(len(aux)):
            left_aux[lane][coefficient_index] = left_projection[lane]
            right_aux[lane][coefficient_index] = right_projection[lane]

    main_tensor = tuple(
        tuple(value % modulus for value in negacyclic(left_main[lane], right_main[lane]))
        for lane, modulus in enumerate(main)
    )
    aux_tensor = tuple(
        tuple(value % modulus for value in negacyclic(tuple(left_aux[lane]), tuple(right_aux[lane])))
        for lane, modulus in enumerate(aux)
    )
    return main_tensor, aux_tensor


def exact_scale_round(
    x_main: tuple[int, ...],
    x_aux: tuple[int, ...],
    main: tuple[int, ...],
    aux: tuple[int, ...],
    ring_n: int,
    plaintext_modulus: int,
) -> tuple[int, ...]:
    """Independent transcription of ExactScaleRound's integer identity."""
    modulus = prod(main)
    aux_product = prod(aux)
    bound_over_q_sq = ring_n // 4
    shift_multiplier = bound_over_q_sq * plaintext_modulus + 1
    required = 2 * shift_multiplier * modulus
    if aux_product <= required:
        raise AssertionError("insufficient transient auxiliary capacity")

    q_mod_aux = tuple(modulus % lane for lane in aux)

    z_main = tuple(
        (residue * (plaintext_modulus % lane) + (lane - 1) // 2) % lane
        for residue, lane in zip(x_main, main)
    )

    z_aux: list[int] = []
    for residue, lane, q_mod in zip(x_aux, aux, q_mod_aux):
        half_q = ((q_mod + lane - 1) % lane) * pow(2, -1, lane) % lane
        z_aux.append((residue * (plaintext_modulus % lane) + half_q) % lane)

    w_aux, _, _ = canonical_projection(z_main, main, aux)

    yplus_aux: list[int] = []
    for z_residue, w_residue, lane, q_mod in zip(z_aux, w_aux, aux, q_mod_aux):
        quotient = ((z_residue - w_residue) * pow(q_mod, -1, lane)) % lane
        shift = (shift_multiplier % lane) * q_mod % lane
        yplus_aux.append((quotient + shift) % lane)

    output, _, _ = canonical_projection(tuple(yplus_aux), aux, main)
    return output


def next_state(state: int) -> int:
    return (
        state * 6_364_136_223_846_793_005
        + 1_442_695_040_888_963_407
    ) & ((1 << 256) - 1)


def capacity_certificate(
    label: str,
    ring_n: int,
    main: tuple[int, ...],
    expected_lanes: int,
) -> tuple[int, int]:
    modulus = prod(main)
    required = 2 * ((ring_n // 4) * T + 1) * modulus

    selected = 0
    for lane_count in range(1, len(AUX_10) + 1):
        if prod(AUX_10[:lane_count]) > required:
            selected = lane_count
            break
    if selected != expected_lanes:
        raise AssertionError(
            f"{label}: expected {expected_lanes} transient lanes, got {selected}"
        )

    aux = AUX_10[:selected]
    for main_lane in main:
        for aux_lane in aux:
            if gcd(main_lane, aux_lane) != 1:
                raise AssertionError(f"{label}: main/aux gcd is not 1")
    for aux_lane in aux:
        if (aux_lane - 1) % (2 * ring_n) != 0:
            raise AssertionError(f"{label}: auxiliary lane is not NTT-compatible")

    return prod(aux).bit_length(), required.bit_length()


def verify_projection_and_tensor(
    label: str,
    ring_n: int,
    main: tuple[int, ...],
    aux_lanes: int,
) -> int:
    aux = AUX_10[:aux_lanes]
    modulus = prod(main)
    state = 0x9650_2026_0903_0000 + len(main)
    checks = 0

    for _ in range(20_000):
        state = next_state(state)
        canonical_value = state % modulus
        residues = tuple(canonical_value % lane for lane in main)
        projected, upper_half = centered_projection(residues, main, aux)
        centered_value = (
            canonical_value - modulus
            if 2 * canonical_value >= modulus
            else canonical_value
        )
        if projected != tuple(centered_value % lane for lane in aux):
            raise AssertionError(f"{label}: centered projection mismatch")
        if upper_half != (2 * canonical_value >= modulus):
            raise AssertionError(f"{label}: half-modulus decision mismatch")
        checks += 1

    test_n = 8
    left: list[int] = []
    right: list[int] = []
    for _ in range(test_n):
        state = next_state(state)
        lhs = state % modulus
        state = next_state(state)
        rhs = state % modulus
        left.append(lhs - modulus if 2 * lhs >= modulus else lhs)
        right.append(rhs - modulus if 2 * rhs >= modulus else rhs)

    left_poly = tuple(left)
    right_poly = tuple(right)
    true_tensor = negacyclic(left_poly, right_poly)
    left_main = residue_limbs(left_poly, main)
    right_main = residue_limbs(right_poly, main)
    main_tensor, aux_tensor = transient_tensor(left_main, right_main, main, aux)

    for lane_index, lane in enumerate(main):
        expected = tuple(value % lane for value in true_tensor)
        if main_tensor[lane_index] != expected:
            raise AssertionError(f"{label}: main tensor mismatch")
        checks += test_n

    for lane_index, lane in enumerate(aux):
        expected = tuple(value % lane for value in true_tensor)
        if aux_tensor[lane_index] != expected:
            raise AssertionError(f"{label}: auxiliary tensor mismatch")
        checks += test_n

    for coefficient_index, exact_value in enumerate(true_tensor):
        x_main = tuple(main_tensor[lane][coefficient_index] for lane in range(len(main)))
        x_aux = tuple(aux_tensor[lane][coefficient_index] for lane in range(len(aux)))
        output = exact_scale_round(x_main, x_aux, main, aux, ring_n, T)
        expected_integer = (exact_value * T + modulus // 2) // modulus
        expected = tuple(expected_integer % lane for lane in main)
        if output != expected:
            raise AssertionError(f"{label}: exact scale-round mismatch")
        checks += 1

    return checks


def verify_centering_is_load_bearing() -> None:
    main = MAIN_3
    aux = AUX_10[:4]
    modulus = prod(main)
    canonical_value = modulus - 1
    residues = tuple(canonical_value % lane for lane in main)
    canonical, _, _ = canonical_projection(residues, main, aux)
    centered, upper = centered_projection(residues, main, aux)
    if not upper:
        raise AssertionError("load-bearing centering witness did not enter upper half")
    expected_centered = tuple((-1) % lane for lane in aux)
    if centered != expected_centered:
        raise AssertionError("centered witness does not encode -1")
    if canonical == centered:
        raise AssertionError("canonical and centered transient lifts unexpectedly match")


def main() -> None:
    total_checks = 0
    print("WR-1 derived-transient exact arithmetic gate")
    print("all arithmetic: integer-only")

    verify_centering_is_load_bearing()
    total_checks += 1

    for label, ring_n, main_base, expected_aux_lanes in CONFIGS:
        aux_bits, required_bits = capacity_certificate(
            label, ring_n, main_base, expected_aux_lanes
        )
        checks = verify_projection_and_tensor(
            label, ring_n, main_base, expected_aux_lanes
        )
        total_checks += checks
        print(
            f"{label}: PASS; "
            f"aux_lanes={expected_aux_lanes}; "
            f"aux_bits={aux_bits}; "
            f"required_bits={required_bits}; "
            f"checks={checks}"
        )

    print(f"WR-1 gate: PASS; exact_checks={total_checks}")


if __name__ == "__main__":
    main()
