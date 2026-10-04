#!/usr/bin/env python3
"""Integer-only WR-1 arithmetic oracle driven by the current registry."""

from __future__ import annotations

import json
import pathlib
from math import gcd, prod
from typing import NamedTuple

ROOT = pathlib.Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "artifacts" / "execution" / "parameter_registry.json"

# Retired three-prime secure_128 fixture. It is deliberately not a current
# named configuration and is never consumed by CONFIGS.
HISTORICAL_MAIN_3 = (998_244_353, 985_661_441, 754_974_721)

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


class RegistryConfig(NamedTuple):
    label: str
    ring_n: int
    main: tuple[int, ...]
    plaintext_modulus: int
    eta: int


def _same_tuple(left: dict, right: dict) -> bool:
    return all(
        left[field] == right[field]
        for field in ("ring_degree", "main_primes", "plaintext_modulus", "eta")
    )


def validate_registry_document(document: dict) -> tuple[RegistryConfig, ...]:
    if document.get("schema") != 1:
        raise AssertionError("unsupported parameter-registry schema")
    if document.get("registry_kind") != "current_source_parameter_snapshot":
        raise AssertionError("parameter registry is not a current source snapshot")
    if document.get("integer_arithmetic_only") is not True:
        raise AssertionError("parameter registry does not declare integer-only arithmetic")
    if document.get("main_modulus_width_method") != "bit_length_of_exact_product":
        raise AssertionError("main modulus width was not derived from the exact product")

    entries = document.get("configurations")
    if not isinstance(entries, list) or not entries:
        raise AssertionError("parameter registry has no current configurations")

    expected_names = {
        "secure_128",
        "secure_128_deep",
        "secure_192",
        "secure_256",
    }
    by_name: dict[str, dict] = {}
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("status") != "current":
            raise AssertionError("historical or malformed entry in current registry")
        name = entry.get("name")
        if not isinstance(name, str) or name in by_name:
            raise AssertionError("duplicate or malformed current configuration name")
        by_name[name] = entry
    if set(by_name) != expected_names:
        raise AssertionError(
            f"current named configurations changed: expected {sorted(expected_names)}, "
            f"got {sorted(by_name)}"
        )

    for entry in entries:
        primes = entry.get("main_primes")
        if not isinstance(primes, list) or not primes or any(
            type(prime) is not int or prime <= 1 for prime in primes
        ):
            raise AssertionError(f"{entry['name']}: malformed ordered main primes")
        modulus = prod(primes)
        encoded = entry.get("main_modulus_hex")
        if not isinstance(encoded, str) or int(encoded, 16) != modulus:
            raise AssertionError(f"{entry['name']}: main modulus does not match its prime list")
        if entry.get("main_modulus_product_bits") != modulus.bit_length():
            raise AssertionError(f"{entry['name']}: exact product width mismatch")
        for field in ("ring_degree", "plaintext_modulus", "eta"):
            if type(entry.get(field)) is not int or entry[field] <= 0:
                raise AssertionError(f"{entry['name']}: malformed {field}")

    secure_128 = by_name["secure_128"]
    secure_128_deep = by_name["secure_128_deep"]
    historical = list(HISTORICAL_MAIN_3)
    if (
        secure_128["main_primes"] == historical
        or len(secure_128["main_primes"]) != 4
    ):
        raise AssertionError(
            "the historical three-prime WR-1 fixture cannot be labeled current secure_128"
        )
    if not _same_tuple(secure_128, secure_128_deep):
        raise AssertionError("secure_128 and secure_128_deep are not identical current tuples")

    for entry in entries:
        equivalent = [other for other in entries if _same_tuple(entry, other)]
        relation = entry.get("alias_relation")
        if not isinstance(relation, dict):
            raise AssertionError(f"{entry['name']}: missing alias relation")
        expected_kind = (
            "identical_current_tuple" if len(equivalent) > 1 else "unique_current_tuple"
        )
        expected_aliases = [
            other["name"] for other in equivalent if other["name"] != entry["name"]
        ]
        if (
            relation.get("kind") != expected_kind
            or relation.get("canonical_name") != equivalent[0]["name"]
            or relation.get("aliases") != expected_aliases
        ):
            raise AssertionError(f"{entry['name']}: alias relation disagrees with tuple equality")

    return tuple(
        RegistryConfig(
            label=entry["name"],
            ring_n=entry["ring_degree"],
            main=tuple(entry["main_primes"]),
            plaintext_modulus=entry["plaintext_modulus"],
            eta=entry["eta"],
        )
        for entry in entries
    )


def load_current_configs(path: pathlib.Path = REGISTRY_PATH) -> tuple[RegistryConfig, ...]:
    with path.open(encoding="utf-8") as registry_file:
        document = json.load(registry_file)
    return validate_registry_document(document)


def operand_bound_over_q_squared(ring_n: int) -> int:
    if ring_n <= 0 or ring_n % 2 != 0:
        raise AssertionError("WR-1 N/2 operand bound requires positive even N")
    return ring_n // 2


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


def _centered_aux_limbs(
    polynomial_main: tuple[tuple[int, ...], ...],
    main: tuple[int, ...],
    aux: tuple[int, ...],
) -> tuple[tuple[int, ...], ...]:
    if len(polynomial_main) != len(main):
        raise AssertionError("main limb count mismatch")
    n = len(polynomial_main[0])
    projected = [[0] * n for _ in aux]
    for coefficient_index in range(n):
        residues = tuple(
            polynomial_main[lane][coefficient_index] for lane in range(len(main))
        )
        centered, _ = centered_projection(residues, main, aux)
        for lane, residue in enumerate(centered):
            projected[lane][coefficient_index] = residue
    return tuple(tuple(lane) for lane in projected)


def _main_product(
    left: tuple[tuple[int, ...], ...],
    right: tuple[tuple[int, ...], ...],
    main: tuple[int, ...],
) -> tuple[tuple[int, ...], ...]:
    return tuple(
        tuple(value % modulus for value in negacyclic(left[lane], right[lane]))
        for lane, modulus in enumerate(main)
    )


def transient_tensor_components(
    left0_main: tuple[tuple[int, ...], ...],
    left1_main: tuple[tuple[int, ...], ...],
    right0_main: tuple[tuple[int, ...], ...],
    right1_main: tuple[tuple[int, ...], ...],
    main: tuple[int, ...],
    aux: tuple[int, ...],
) -> tuple[
    tuple[tuple[tuple[int, ...], ...], ...],
    tuple[tuple[tuple[int, ...], ...], ...],
]:
    left0_aux = _centered_aux_limbs(left0_main, main, aux)
    left1_aux = _centered_aux_limbs(left1_main, main, aux)
    right0_aux = _centered_aux_limbs(right0_main, main, aux)
    right1_aux = _centered_aux_limbs(right1_main, main, aux)

    main_e0 = _main_product(left0_main, right0_main, main)
    main_e1 = tuple(
        tuple((a + b) % modulus for a, b in zip(product_a, product_b))
        for product_a, product_b, modulus in zip(
            _main_product(left0_main, right1_main, main),
            _main_product(left1_main, right0_main, main),
            main,
        )
    )
    main_e2 = _main_product(left1_main, right1_main, main)

    aux_e0 = _main_product(left0_aux, right0_aux, aux)
    aux_e1 = tuple(
        tuple((a + b) % modulus for a, b in zip(product_a, product_b))
        for product_a, product_b, modulus in zip(
            _main_product(left0_aux, right1_aux, aux),
            _main_product(left1_aux, right0_aux, aux),
            aux,
        )
    )
    aux_e2 = _main_product(left1_aux, right1_aux, aux)
    return (main_e0, main_e1, main_e2), (aux_e0, aux_e1, aux_e2)


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
    bound_over_q_sq = operand_bound_over_q_squared(ring_n)
    shift_multiplier = bound_over_q_sq * plaintext_modulus + 1
    required = 2 * shift_multiplier * modulus
    if aux_product <= required:
        raise AssertionError("insufficient transient auxiliary capacity")

    q_mod_aux = tuple(modulus % lane for lane in aux)
    half_modulus = modulus // 2

    z_main = tuple(
        (residue * (plaintext_modulus % lane) + half_modulus) % lane
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
    plaintext_modulus: int,
) -> tuple[tuple[int, ...], int, int]:
    modulus = prod(main)
    required = (
        2
        * (operand_bound_over_q_squared(ring_n) * plaintext_modulus + 1)
        * modulus
    )

    aux = ()
    for lane_count in range(1, len(AUX_10) + 1):
        candidate = AUX_10[:lane_count]
        if prod(candidate) > required:
            aux = candidate
            break
    if not aux:
        raise AssertionError(f"{label}: auxiliary pool cannot satisfy N/2 capacity")

    for main_lane in main:
        for aux_lane in aux:
            if gcd(main_lane, aux_lane) != 1:
                raise AssertionError(f"{label}: main/aux gcd is not 1")
    for aux_lane in aux:
        if (aux_lane - 1) % (2 * ring_n) != 0:
            raise AssertionError(f"{label}: auxiliary lane is not NTT-compatible")

    return aux, prod(aux).bit_length(), required.bit_length()


def verify_projection_and_tensor(
    config: RegistryConfig,
    aux: tuple[int, ...],
) -> int:
    label = config.label
    ring_n = config.ring_n
    main = config.main
    plaintext_modulus = config.plaintext_modulus
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
    operands: list[list[int]] = [[], [], [], []]
    for _ in range(test_n):
        for operand in operands:
            state = next_state(state)
            canonical = state % modulus
            operand.append(
                canonical - modulus if 2 * canonical >= modulus else canonical
            )

    left0, left1, right0, right1 = (tuple(operand) for operand in operands)
    true_e0 = negacyclic(left0, right0)
    true_e1 = tuple(
        a + b
        for a, b in zip(
            negacyclic(left0, right1),
            negacyclic(left1, right0),
        )
    )
    true_e2 = negacyclic(left1, right1)
    true_components = (true_e0, true_e1, true_e2)

    d1_bound = operand_bound_over_q_squared(ring_n) * modulus * modulus
    if any(abs(value) > d1_bound for value in true_e1):
        raise AssertionError(f"{label}: d1 exceeds the declared N/2 Q^2 bound")

    main_components, aux_components = transient_tensor_components(
        residue_limbs(left0, main),
        residue_limbs(left1, main),
        residue_limbs(right0, main),
        residue_limbs(right1, main),
        main,
        aux,
    )

    for component_index, (true_values, main_component, aux_component) in enumerate(
        zip(true_components, main_components, aux_components)
    ):
        for lane_index, lane in enumerate(main):
            expected = tuple(value % lane for value in true_values)
            if main_component[lane_index] != expected:
                raise AssertionError(
                    f"{label}: main tensor component {component_index} mismatch"
                )
            checks += test_n
        for lane_index, lane in enumerate(aux):
            expected = tuple(value % lane for value in true_values)
            if aux_component[lane_index] != expected:
                raise AssertionError(
                    f"{label}: auxiliary tensor component {component_index} mismatch"
                )
            checks += test_n

        for coefficient_index, exact_value in enumerate(true_values):
            x_main = tuple(
                component[coefficient_index] for component in main_component
            )
            x_aux = tuple(
                component[coefficient_index] for component in aux_component
            )
            output = exact_scale_round(
                x_main,
                x_aux,
                main,
                aux,
                ring_n,
                plaintext_modulus,
            )
            expected_integer = (
                exact_value * plaintext_modulus + modulus // 2
            ) // modulus
            expected = tuple(expected_integer % lane for lane in main)
            if output != expected:
                raise AssertionError(
                    f"{label}: exact scale-round component {component_index} mismatch"
                )
            checks += 1

    return checks


def verify_historical_centering_fixture() -> None:
    main = HISTORICAL_MAIN_3
    aux = AUX_10[:4]
    modulus = prod(main)
    canonical_value = modulus - 1
    residues = tuple(canonical_value % lane for lane in main)
    canonical, _, _ = canonical_projection(residues, main, aux)
    centered, upper = centered_projection(residues, main, aux)
    if not upper:
        raise AssertionError("historical centering witness did not enter upper half")
    if centered != tuple((-1) % lane for lane in aux):
        raise AssertionError("historical centered witness does not encode -1")
    if canonical == centered:
        raise AssertionError("canonical and centered historical lifts unexpectedly match")


def main() -> None:
    total_checks = 0
    print("WR-1 derived-transient exact arithmetic gate")
    print("all arithmetic: integer-only")
    print(
        "historical fixture: HISTORICAL_MAIN_3 "
        "(retired three-prime secure_128 shape; not current)"
    )

    configs = load_current_configs()
    verify_historical_centering_fixture()
    total_checks += 1

    for config in configs:
        aux, aux_bits, required_bits = capacity_certificate(
            config.label,
            config.ring_n,
            config.main,
            config.plaintext_modulus,
        )
        checks = verify_projection_and_tensor(config, aux)
        total_checks += checks
        print(
            f"{config.label}: PASS; "
            f"operand_bound=(N/2)*Q^2; "
            f"aux_lanes={len(aux)}; "
            f"aux_bits={aux_bits}; "
            f"required_bits={required_bits}; "
            f"checks={checks}"
        )

    print(f"WR-1 gate: PASS; exact_checks={total_checks}")


if __name__ == "__main__":
    main()
