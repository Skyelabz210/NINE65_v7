"""Exact candidate checks, not an identification of the user's remembered source.

Run with Python 3 and sympy==1.14.0. No repository runtime is modified.
The candidate-specific primality checks also use complete trial division;
prime ranks use SymPy's primepi implementation.
"""
import hashlib
import json
from datetime import datetime, timezone
from math import gcd, isqrt, lcm, prod
from pathlib import Path

import sympy


def star(n):
    return 6 * n * (n - 1) + 1


def star_index(value):
    root = isqrt(24 * value + 12)
    if root * root == 24 * value + 12 and (root + 6) % 12 == 0:
        return (root + 6) // 12
    return None


def prime_by_trial(n):
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    return all(n % d for d in range(3, isqrt(n) + 1, 2))


superstar = []
for value in (661, 1750255921):
    assert prime_by_trial(value) and sympy.isprime(value)
    index = star_index(value)
    rank = int(sympy.primepi(value))
    rank_index = star_index(rank)
    assert index is not None and rank_index is not None
    assert star(index) == value and star(rank_index) == rank
    superstar.append(dict(value=value, star_index=index, prime_rank=rank,
                          prime_rank_star_index=rank_index,
                          left_twin=prime_by_trial(value - 2),
                          right_twin=prime_by_trial(value + 2)))
assert superstar[0]['prime_rank'] == 121
assert superstar[1]['prime_rank'] == 86526037

stars = [star(n) for n in range(1, 16)]
star_primes = [x for x in stars if prime_by_trial(x)]
anchors = [37, 73, 181, 337, 433]
assert all(prime_by_trial(a) for a in anchors)
assert all(gcd(a, 36) == 1 for a in anchors)
capacity = [prod(anchors[:i]) for i in range(1, len(anchors) + 1)]
assert capacity == [37, 2701, 488881, 164752897, 71338004401]

neighbors = []
for center in (12, 36, 72, 120, 180, 210, 2310, 30030):
    sides = []
    for n in (center - 1, center + 1):
        factors = {int(p): int(e) for p, e in sympy.factorint(n).items()}
        assert prod(p ** e for p, e in factors.items()) == n
        sides.append(dict(n=n, factors=factors, prime=prime_by_trial(n)))
    neighbors.append(dict(center=center, sides=sides))
assert 35 == 5 * 7 and 39 == 3 * 13
assert 209 == 11 * 19 and 30031 == 59 * 509

head_periods = [260, 365, 18980, 144000]
full_phase_period = lcm(*head_periods)
assert lcm(260, 365) == 18980
assert full_phase_period == 136656000
increments = [lcm(*head_periods[:i]) // lcm(*head_periods[:i - 1])
              for i in range(1, 5)]
assert increments == [260, 73, 1, 7200]
assert 2 ** 24 < full_phase_period

here = Path(__file__).resolve().parent
heads = here.parent / 'dccms-mechanism-investigation-2026-11-13/sources/dccms/dccms_atlas/src/heads.rs'
source_hash = hashlib.sha256(heads.read_bytes()).hexdigest() if heads.exists() else None
result = dict(
    status='PASS', executed_at_utc=datetime.now(timezone.utc).isoformat(),
    sympy_version=sympy.__version__, script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    superstar_candidates=superstar,
    first_two_order_status='Secondary page lists these as first two; membership checked here, absence of intermediate qualifying terms not checked.',
    ordinary_star_numbers=stars, ordinary_star_primes=star_primes,
    star_prime_anchors=anchors, quotient_capacities=capacity,
    fixed_36_source_capacities=[36 * c for c in capacity],
    primorials=[prod(list(sympy.primerange(1, p + 1))) for p in (2,3,5,7,11,13,17,19)],
    twin_neighbor_examples=neighbors,
    four_heads=dict(periods=head_periods, full_phase_joint_period=full_phase_period,
                    successive_resolution_factors=increments, packed_bit_capacity=2**24,
                    repository_commit='40a76158970c41440ec7e4c10437fa1c2e271d03',
                    heads_rs_sha256=source_hash,
                    scope='Source inspection and exact period arithmetic; no fresh Rust execution. Full phase readings differ from compressed carry_bits.'),
    limits=['Remembered sequence not confirmed by user.',
            'No universal twin-prime assertion established for the superstar subset.',
            'No historical Maya/Chinese transmission or physical influence inferred.'],
)
(here / 'verification.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
