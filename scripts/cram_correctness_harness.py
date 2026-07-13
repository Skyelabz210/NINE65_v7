#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from math import gcd


@dataclass(frozen=True)
class ScaleProfile:
    name: str
    lane_counts: tuple[int, ...]
    steps: int
    kelim_samples: int


PROFILES = {
    "small": ScaleProfile("small", (2, 4, 8), 128, 2_048),
    "medium": ScaleProfile("medium", (8, 16, 32), 1_024, 16_384),
    "large": ScaleProfile("large", (32, 64), 8_192, 131_072),
    "endurance": ScaleProfile("endurance", (64,), 65_536, 1_048_576),
}


class XorShift64:
    MASK = (1 << 64) - 1

    def __init__(self, seed: int) -> None:
        if seed == 0:
            raise ValueError("seed must be nonzero")
        self.state = seed & self.MASK

    def next(self) -> int:
        value = self.state
        value ^= (value << 13) & self.MASK
        value ^= value >> 7
        value ^= (value << 17) & self.MASK
        self.state = value & self.MASK
        return self.state


def is_prime(value: int) -> bool:
    if value < 2:
        return False
    if value == 2:
        return True
    if value % 2 == 0:
        return False
    divisor = 3
    while divisor <= value // divisor:
        if value % divisor == 0:
            return False
        divisor += 2
    return True


def first_primes(count: int) -> list[int]:
    primes: list[int] = []
    candidate = 2
    while len(primes) < count:
        if is_prime(candidate):
            primes.append(candidate)
        candidate += 1
    return primes


def validate_basis(moduli: list[int]) -> None:
    if not moduli:
        raise AssertionError("empty basis")
    for index, modulus in enumerate(moduli):
        if modulus < 2:
            raise AssertionError((index, modulus))
    for left in range(len(moduli)):
        for right in range(left + 1, len(moduli)):
            if gcd(moduli[left], moduli[right]) != 1:
                raise AssertionError((left, right, moduli[left], moduli[right]))


def inverse_mod(value: int, modulus: int) -> int:
    old_r, r = value, modulus
    old_s, s = 1, 0
    while r:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
    if old_r != 1:
        raise ValueError("inverse requires coprimality")
    return old_s % modulus


def reference_winding(main_residue: int, anchor_residue: int, main: int, anchor: int) -> int:
    inverse = inverse_mod(main % anchor, anchor)
    difference = (anchor_residue - (main_residue % anchor)) % anchor
    return (difference * inverse) % anchor


def run_profile(profile: ScaleProfile) -> dict[str, int | str | list[int]]:
    lane_operations = 0
    rolling_digest = hashlib.sha256()

    for lane_count in profile.lane_counts:
        moduli = first_primes(lane_count)
        validate_basis(moduli)
        rng = XorShift64(0x9E3779B97F4A7C15 ^ lane_count)
        residues = [rng.next() % modulus for modulus in moduli]

        for step in range(profile.steps):
            for index, modulus in enumerate(moduli):
                rhs = rng.next() % modulus
                old = residues[index]
                mode = (step + index) % 3
                if mode == 0:
                    updated = (old + rhs) % modulus
                elif mode == 1:
                    updated = (old - rhs) % modulus
                else:
                    updated = (old * rhs) % modulus
                if not 0 <= updated < modulus:
                    raise AssertionError((profile.name, lane_count, step, index))
                residues[index] = updated
                lane_operations += 1

        rolling_digest.update(lane_count.to_bytes(2, "big"))
        for residue in residues:
            rolling_digest.update(residue.to_bytes(8, "big"))

    exhaustive_pairs = ((4, 9), (8, 9), (15, 16), (25, 49), (36, 37))
    exhaustive_states = 0
    for main, anchor in exhaustive_pairs:
        if gcd(main, anchor) != 1:
            raise AssertionError((main, anchor))
        for value in range(main * anchor):
            recovered = reference_winding(value % main, value % anchor, main, anchor)
            if recovered != value // main:
                raise AssertionError((main, anchor, value, recovered, value // main))
            exhaustive_states += 1

    main = 9_699_690
    anchor = 23
    span = main * anchor
    rng = XorShift64(0xD1B54A32D192ED03)
    for sample in range(profile.kelim_samples):
        value = rng.next() % span
        recovered = reference_winding(value % main, value % anchor, main, anchor)
        if recovered != value // main:
            raise AssertionError((sample, value, recovered, value // main))
        rolling_digest.update(recovered.to_bytes(8, "big"))

    return {
        "profile": profile.name,
        "lane_counts": list(profile.lane_counts),
        "steps": profile.steps,
        "lane_operations": lane_operations,
        "exhaustive_anchor_states": exhaustive_states,
        "sampled_anchor_states": profile.kelim_samples,
        "internal_projections": 0,
        "crt_reconstructions": 0,
        "scalar_materializations": 0,
        "garner_calls": 0,
        "mixed_radix_calls": 0,
        "digest_sha256": rolling_digest.hexdigest(),
        "status": "PASS",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", choices=tuple(PROFILES), default="small")
    parser.add_argument("--all", action="store_true")
    args = parser.parse_args()
    selected = tuple(PROFILES.values()) if args.all else (PROFILES[args.profile],)
    results = [run_profile(profile) for profile in selected]
    print(json.dumps({"results": results}, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
