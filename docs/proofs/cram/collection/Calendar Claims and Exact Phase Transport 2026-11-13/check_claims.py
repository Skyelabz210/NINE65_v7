"""Exact arithmetic checks. Standard-library only; no physical-data fitting."""
import hashlib
import json
from datetime import datetime, timezone
from math import gcd, isqrt, lcm, prod
from pathlib import Path

from eclipse_phase import eclipse_phase, restore_calendar_readings


def prime_factors(n):
    result = {}
    p = 2
    while p * p <= n:
        while n % p == 0:
            result[p] = result.get(p, 0) + 1
            n //= p
        p += 1
    if n > 1:
        result[n] = result.get(n, 0) + 1
    return result


def least_extra_anchor(P, D):
    path = [D // gcd(P, D)]
    while True:
        b = gcd(D, path[-1] ** 2)
        if b == path[-1]:
            return path
        path.append(b)


def long_count(days):
    digits = []
    for place in (144000, 7200, 360, 20, 1):
        digit, days = divmod(days, place)
        digits.append(digit)
    return digits


counts = {}
assert gcd(260, 365) == 5
assert gcd(365, 584) == 73
assert gcd(260, 584) == 4
assert gcd(260, 780) == 260
assert lcm(260, 365) == 18980
assert lcm(260, 365, 584) == 37960
assert 5 * 584 == 8 * 365 == 2920
assert 11960 == 520 * 23 == 46 * 260
assert divmod(1872000, 18980) == (98, 11960)
assert long_count(1) == [0, 0, 0, 0, 1]
assert long_count(18980) == [0, 2, 12, 13, 0]
assert long_count(1872000) == [13, 0, 0, 0, 0]
assert all(11959 % d for d in range(2, isqrt(11959) + 1))

cases = []
for P, expected_ambiguity, expected_anchor in ((30030,92,184), (18980,46,184), (37960,23,23)):
    D = 11960
    path = least_extra_anchor(P,D)
    assert D // gcd(P,D) == expected_ambiguity
    assert path[-1] == expected_anchor
    aliases = sorted({(P*j) % D for j in range(expected_ambiguity)})
    assert len(aliases) == expected_ambiguity
    cases.append(dict(source_period=P, target_period=D, ambiguity=expected_ambiguity,
                      minimal_additional_raw_modulus=expected_anchor, saturation=path,
                      observation_zero_target_values=aliases))
    for a in range(1, 1001):
        assert (lcm(P,a) % D == 0) == (a % expected_anchor == 0)
counts['additional_anchor_candidates'] = 3000

# A new complete finite source/target transfer, checked against an independent
# scalar oracle only at the test boundary. The constructor has no X input.
joint = lcm(260,584,23)
assert joint == 873080
for x in range(joint):
    readings = x % 260, x % 584, x % 23
    phase = eclipse_phase(*readings)
    assert phase == x % 11960
    assert restore_calendar_readings(phase, x % 73) == readings
counts['complete_observation_states'] = joint
counts['frame_roundtrips'] = joint
counts['distinct_target_phases'] = 11960

large = [-(1 << 256), -11961, -1, 1 << 256, (1 << 256) + 873081]
for x in large:
    readings = x % 260, x % 584, x % 23
    phase = eclipse_phase(*readings)
    assert phase == x % 11960
    assert restore_calendar_readings(phase, x % 73) == readings
counts['large_signed_cases'] = len(large)

bad = [(0,1,0), (-1,0,0), (260,0,0), (0,584,0), (0,0,23), (0.0,0,0), (False,0,0)]
for args in bad:
    try:
        eclipse_phase(*args)
        raise AssertionError('malformed input accepted')
    except ValueError:
        pass
counts['forward_refusals'] = len(bad)
bad_inverse = [(-1,0), (11960,0), (0,73), (False,0)]
for args in bad_inverse:
    try:
        restore_calendar_readings(*args)
        raise AssertionError('malformed inverse input accepted')
    except ValueError:
        pass
counts['inverse_refusals'] = len(bad_inverse)

# Direct nonunit K-elimination already suffices for the 260/365 query.
for x in range(18980):
    r,s = x%260,x%365
    assert (s-r) % 5 == 0
    assert (66*((s-r)//5)) % 73 == x//260
counts['calendar_quotient_window_cases'] = 18980

# The 36/37 observation alone cannot identify unrestricted calendar queries.
assert (0%36,0%37) == (1332%36,1332%37)
assert (0%260,0%365) != (1332%260,1332%365)

period_names = [('Tzolkin',260),('Haab',365),('Venus model',584),('Mars model',780),('819-day',819)]
P = 1
period_ladder = []
for name,m in period_names:
    nextP = lcm(P,m)
    period_ladder.append(dict(name=name, modulus=m, combined_period=nextP,
                              new_resolution_factor=nextP//P))
    P=nextP
assert P == 2391480

here=Path(__file__).resolve().parent
result=dict(status='PASS', executed_at_utc=datetime.now(timezone.utc).isoformat(),
    source_commit='40a76158970c41440ec7e4c10437fa1c2e271d03',
    source_execution_scope='Arithmetic model checks; no fresh execution of DCCMS Rust or Lean.',
    code_sha256={name:hashlib.sha256((here/name).read_bytes()).hexdigest()
                 for name in ('eclipse_phase.py','check_claims.py')},
    counts=counts, target_resolution_cases=cases, period_ladder=period_ladder,
    factorizations={str(n):prime_factors(n) for n in (260,365,584,780,819,11960,11959,30030,37960)},
    long_count_examples={str(n):long_count(n) for n in (1,20,18980,1872000)},
    long_count_calendar_round_boundary=dict(days=1872000,rounds=98,remainder=11960),
    source36_37_collision=dict(inputs=[0,1332],same_reading=[0,0],calendar_outputs=[[0,0],[32,237]]),
    authentic_readings='Same integer source, origin, frame and epoch are premises. Range and overlap checks do not certify provenance.',
    physical_scope='The computed quantity is X modulo the chosen integer period 11960; it is not an eclipse-occurrence prediction.',
    formal_scope='No new Lean declarations; earlier checked universal and least-anchor theorems are referenced.',
    history_scope='No historical opcode identification or cosmological conclusion follows from these computations.')
(here/'verification.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'status':result['status'],'counts':counts,'target_resolution_cases':
                 [{k:v for k,v in row.items() if k!='observation_zero_target_values'} for row in cases]},indent=2))
