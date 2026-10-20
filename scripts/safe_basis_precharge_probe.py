#!/usr/bin/env python3
"""Exact precharge/carry experiments; reconstruction is a clear test oracle.

Encrypted coordinate production is tested separately in Rust. The carry
recovery here receives decrypted/plain coordinates, never ciphertexts.
"""

import hashlib
import itertools
import json
import math
from pathlib import Path

from refresh_carry_bridge import centered, convolution, nearest

ROOT = (2, 3, 5, 7, 11, 13, 17, 19)
POWERS = (17, 11, 8, 6, 5, 5, 4, 4)
FRAME = tuple(p ** e for p, e in zip(ROOT, POWERS))
P = math.prod(ROOT)
Q = 348959453350711275087786864768188417
N = 8192


def centered_even_or_odd(value, modulus):
    value %= modulus
    return value - modulus if 2 * value >= modulus else value


def crt_oracle(residues, moduli):
    """Test-only scalar CRT, not an encrypted or production transducer."""
    product = math.prod(moduli)
    return sum(r * (product // p) * pow(product // p, -1, p)
               for r, p in zip(residues, moduli)) % product


def carry_from_phase_and_safe(phase, safe_residue, q, p=P):
    """Requires the CENTERED phase representative, not just its encryption."""
    assert centered(phase, q) == phase
    k_mod_p = ((safe_residue - phase % p) * pow(q, -1, p)) % p
    return centered_even_or_odd(k_mod_p, p)


def run():
    assert P == 9699690
    assert FRAME == (131072, 177147, 390625, 117649, 161051, 371293, 83521, 130321)
    assert all(m % p == 0 for m, p in zip(FRAME, ROOT))
    assert all(math.gcd(a, b) == 1 for a, b in itertools.combinations(FRAME, 2))
    ring_cases = coefficients = nonzero = 0
    # Exhaustive public residual/ternary-secret cases, then a larger boundary
    # alphabet. These are residual polynomials, not ciphertext distributions.
    for q, alphabet in ((5, range(-2, 3)), (17, (-8, -1, 0, 1, 8))):
        # Toy Q is itself a root factor. The Q+anchor inverse experiment
        # uses the coprime subset; the complete higher-power frame below
        # still retains all eight roles. Native Q is coprime to all of S8.
        safe_product = math.prod(p for p in ROOT if math.gcd(q, p) == 1)
        for r0, r1, s in itertools.product(
                itertools.product(alphabet, repeat=2),
                itertools.product(alphabet, repeat=2),
                itertools.product((-1, 0, 1), repeat=2)):
            sums = [a + b for a, b in zip(r0, convolution(r1, s))]
            residue_sums = [a + b for a, b in zip(
                [v % safe_product for v in r0],
                convolution([v % safe_product for v in r1], s))]
            for total, residue in zip(sums, residue_sums):
                k = nearest(total, q)
                g = centered(total, q)
                assert carry_from_phase_and_safe(g, residue % safe_product, q, safe_product) == k
                # A frame wide enough for S can name it without a Q phase
                # coordinate. Actual encrypted CRT/rank is not performed here.
                full = crt_oracle([total % m for m in FRAME], FRAME)
                assert centered_even_or_odd(full, math.prod(FRAME)) == total
                assert nearest(centered_even_or_odd(full, math.prod(FRAME)), q) == k
                coefficients += 1
                nonzero += k != 0
            ring_cases += 1
    h = Q // 2
    bound = (N + 1) * h
    frame_product = math.prod(FRAME)
    assert frame_product > 2 * bound
    assert Q * P > 2 * bound
    native_cases = 0
    seen = set()
    # Every admissible carry, both cut neighbors, and both global extrema.
    for k in range(-N // 2, N // 2 + 1):
        for g in (-h, -h + 1, -1, 0, 1, h - 1, h):
            total = k * Q + g
            if abs(total) > bound:
                continue
            assert nearest(total, Q) == k
            assert carry_from_phase_and_safe(g, total % P, Q) == k
            lifted = centered_even_or_odd(crt_oracle([total % m for m in FRAME], FRAME), frame_product)
            assert lifted == total
            assert nearest(lifted, Q) == k
            seen.add(k % P)
            native_cases += 1
    assert len(seen) == N + 1
    for total in (-bound, bound):
        assert carry_from_phase_and_safe(centered(total, Q), total % P, Q) == nearest(total, Q)

    # Independent residues are essential: an ordinary mod-Q view identifies
    # these two states despite their different carries. S8 alone also aliases.
    assert centered(0, Q) == centered(Q, Q)
    assert nearest(0, Q) != nearest(Q, Q)
    assert h % P == (h + P) % P
    assert nearest(h, Q) != nearest(h + P, Q)
    # Once the large frame's interval is exceeded, even that frame aliases.
    assert [0 % m for m in FRAME] == [frame_product % m for m in FRAME]
    assert 11 <= N  # shadow-11 alone cannot hold the full signed carry.
    assert (-6) % 11 == 5 % 11
    # An anchor from a neighboring epoch can produce an incorrect carry
    # still INSIDE the admitted range. Bounds do not establish lineage.
    stale = carry_from_phase_and_safe(0, Q % P, Q)
    assert stale == 1 and abs(stale) <= N // 2
    # Projecting/reducing before the secret sum yields S mod P, not g mod P;
    # confusing these would force the recovered carry to zero.
    assert carry_from_phase_and_safe(0, Q % P, Q) == 1
    assert centered_even_or_odd(((Q % P - Q % P) * pow(Q, -1, P)) % P, P) == 0

    noise = []
    beta = 3 * (2 * N + 1)
    for modulus in ROOT + FRAME:
        remainder = Q % modulus
        error = beta * N * (modulus // 2) + (N + 1) * remainder + (remainder + 1) // 2
        half_delta = (Q // modulus) // 2
        assert error < half_delta
        noise.append({"plaintext_modulus": modulus, "error_bound": error,
                      "half_delta": half_delta,
                      "headroom_bit_difference": half_delta.bit_length() - error.bit_length()})
    combined_error = sum(pow(P // p, -1, p) * row["error_bound"]
                         for p, row in zip(ROOT, noise[:len(ROOT)]))
    combined_half_delta = (Q // P) // 2
    assert combined_error < combined_half_delta

    repo = Path(__file__).resolve().parent.parent
    sources = [repo / name for name in (
        "scripts/safe_basis_precharge_probe.py", "scripts/refresh_carry_bridge.py",
        "crates/nine65/src/ops/safe_basis_precharge_tests.rs",
        "crates/nine65/src/ops/expanded_bootstrap.rs",
        "crates/nine65/src/arithmetic/main_only_base_ext.rs",
        "crates/nine65/src/params/secure_configs.rs", "Cargo.lock")]
    return {
        "schema": "nine65-safe-basis-precharge-v1",
        "scope": "clear carry oracle plus parameter bounds; encrypted coordinate tests are separate",
        "source_sha256": {str(p.relative_to(repo)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
        "checks": {"negacyclic_n2_residual_cases": ring_cases,
                   "signed_coefficient_recoveries": coefficients,
                   "nonzero_carries": nonzero,
                   "native_boundary_recoveries": native_cases,
                   "distinct_native_carries": len(seen),
                   "negative_controls": 6},
        "native": {"N": N, "Q": Q, "S_abs_bound": bound,
                   "minimum_signed_range_bits": (2 * bound + 1).bit_length(),
                   "safe_product": P, "Q_times_safe_product_bits": (Q * P).bit_length(),
                   "power_frame": FRAME, "power_frame_product": frame_product,
                   "power_frame_product_bits": frame_product.bit_length(),
                   "power_frame_preserves_root_roles": True,
                   "power_frame_covers_full_signed_S": True},
        "coordinate_noise_bounds_eta3": noise,
        "s8_assembly_noise_bound": {"error_bound": combined_error,
                                    "half_delta": combined_half_delta,
                                    "headroom_bit_difference": combined_half_delta.bit_length() - combined_error.bit_length()},
        "unresolved": ["encrypted canonical CRT rank or equivalent quotient circuit",
                       "complete carry-output noise and key transition admission"],
        "encrypted_carry_tested": False,
        "public_refresh_admitted": False,
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
