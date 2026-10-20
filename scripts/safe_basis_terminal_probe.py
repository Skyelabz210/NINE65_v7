#!/usr/bin/env python3
"""Independent exact lookup identities and budgets for terminal pair readouts.

This is clear arithmetic, not encrypted execution. It uses the previous
independently specified noise model; the native evaluator is tested separately.
"""

import hashlib
import itertools
import json
from pathlib import Path

from safe_basis_pair_probe import (
    BOOT, ETA, H, HALF, N, PROJECTED, Q, QB, ROOT, SWITCH, T, multiply, nearest,
)

TRAYS = (6, 10, 77, 221, 1, 8, 27, 121, 4199, 65537)


def functions(q):
    return ([('carry', lambda s: nearest(s, q))]
            + [(f'root {p}', lambda s, p=p: s % p) for p in ROOT]
            + [('phase211', lambda s: (s // 2) % 11)]
            + [(f'tray {i} mod {p}', lambda s, p=p: s % p) for i, p in enumerate(TRAYS)])


def pair_sums(terms):
    return [terms[0]*u + terms[1]*v for u, v in itertools.product((-1, 0, 1), repeat=2)]


def differences(table):
    base = table[0][0]
    left = [row[0] - base for row in table[1:]]
    right = [v - base for v in table[0][1:]]
    mixed = [[table[i][j] - table[i][0] - table[0][j] + base
              for j in range(1, len(table[0]))] for i in range(1, len(table))]
    return base, left, right, mixed


def check_table(table):
    base, left, right, mixed = differences(table)
    failures = 0
    for i, row in enumerate(table):
        for j, expected in enumerate(row):
            linear = base + (left[i-1] if i else 0) + (right[j-1] if j else 0)
            assert linear + (mixed[i-1][j-1] if i and j else 0) == expected
            failures += int(i > 0 and j > 0 and linear != expected)
    return len(table) * len(table[0]), failures


def output_bound(table, ea=PROJECTED, eb=PROJECTED):
    base, left, right, mixed = differences(table)
    product = multiply(ea, eb)
    return (abs(base) + sum(map(abs, left))*ea + sum(map(abs, right))*eb
            + sum(abs(c) for row in mixed for c in row)*product)


def run():
    checks = failures = 0
    for q in (5, 17, 31):
        h = q // 2
        for initial in (-h, 0, h):
            for terms in itertools.product((-h, 0, h), repeat=4):
                left, right = pair_sums(terms[:2]), pair_sums(terms[2:])
                for _, f in functions(q):
                    table = [[f(initial+x+y) for y in right] for x in left]
                    checked, failed = check_table(table)
                    checks += checked
                    failures += failed
    assert checks == 1180980 and failures > 0

    terms = (H-1, H-3, H-9, H-27)
    left, right = pair_sums(terms[:2]), pair_sums(terms[2:])
    assert len(set(left)) == len(set(right)) == 9
    assert len(set(x+y for x in left for y in right)) == 81
    product_bound = multiply(PROJECTED, PROJECTED)
    profiles = []
    native_checks = 0
    rem = QB % T
    affine_error = (N * (ETA*(2*N+1)*N*(T//2) + (N+1)*rem + (rem+1)//2)
                    + (N-1)*SWITCH)
    for initial in (H, -H+40):
        for sign in (1, -1):
            outputs = []
            for name, f in functions(Q):
                table = [[f(sign*(initial+x+y)) for y in right] for x in left]
                checked, _ = check_table(table)
                native_checks += checked
                bound = output_bound(table)
                assert bound < HALF
                outputs.append({'name': name, 'error_bound': bound, 'error_bits': bound.bit_length()})
            total = sign*(initial + sum(terms))
            carry = nearest(total)
            carry_table = [[nearest(sign*(initial+x+y)) for y in right] for x in left]
            selected_mixed = differences(carry_table)[3][-1][-1]
            assert selected_mixed == (0 if initial == H else -sign)
            old_distance = abs(total-Q*carry)
            assert carry == sign*(2 if initial == H else 1)
            assert old_distance == H-(42 if initial == H else 1)
            if initial == H:
                assert nearest(sign*initial) == 0
                assert nearest(sign*(initial+sum(terms[:2]))) == sign
                assert carry == 2*sign  # Both sequential pair additions change K.
            else:
                # Both pair windings are +1; the centered remainder crossing
                # contributes -1 (or the signed reverse), giving total +/-1.
                pair_winding = nearest(sum(terms[:2])) + nearest(sum(terms[2:]))
                centered = initial + sum(terms) - Q*pair_winding
                assert pair_winding == 2 and nearest(centered) == -1
            inv = pow(T, -1, Q)
            components = [(sign*x*inv) % Q for x in (initial, *terms)]
            raw = sum(components)
            decoded = nearest(T*(raw % Q)) % T
            affine = sum(nearest(T*x) for x in components) % T
            assert (affine+carry) % T == decoded and affine != decoded
            fresh = affine_error + outputs[0]['error_bound']
            square = multiply(fresh, fresh)
            next_square = multiply(square, square)
            assert square < HALF and next_square >= HALF
            profiles.append({'initial': initial, 'sign': sign, 'selected_carry': carry,
                             'selected_carry_mixed_coefficient': selected_mixed,
                             'source_grid_distance': old_distance, 'outputs': outputs,
                             'fresh_bound': fresh, 'fresh_bits': fresh.bit_length(),
                             'square_bound': square, 'square_bits': square.bit_length(),
                             'next_square_refused_by_clear_bound': True,
                             'next_square_error_bits': next_square.bit_length()})
    assert native_checks == 6480
    # Product bounds fit, but the requested bundle must still refuse before
    # executing if any output's absolute-coefficient budget is too large.
    inflated = 1 << 80
    assert multiply(PROJECTED, inflated) < HALF
    inflated_bounds = [output_bound([[f(H+x+y) for y in right] for x in left], PROJECTED, inflated)
                       for _, f in functions(Q)]
    assert max(inflated_bounds) >= HALF
    repo = Path(__file__).resolve().parent.parent
    paths = ('scripts/safe_basis_terminal_probe.py', 'scripts/safe_basis_pair_probe.py',
             'crates/nine65/src/ops/safe_basis_terminal_tests.rs',
             'crates/nine65/src/ops/safe_basis_pair_tests.rs',
             'crates/nine65/src/ops/safe_basis_composition_tests.rs',
             'crates/nine65/src/ops/safe_basis_precharge_tests.rs',
             'crates/nine65/src/ops/exact_mul.rs', 'Cargo.lock')
    return {'schema': 'nine65-terminal-readout-v1',
            'baseline': '7441e7d2a87f6000beecd1c8edd18b2e637d0fee',
            'source_sha256': {p: hashlib.sha256((repo/p).read_bytes()).hexdigest() for p in paths},
            'small_readout_checks': checks, 'linear_only_failures': failures,
            'native_readout_checks': native_checks,
            'input_pair_rows': [9, 9], 'distinct_joint_sums': 81,
            'existing_combined_state_limit': 27,
            'shared_selector_products': 64, 'query_frames': 4, 'total_outputs': 80,
            'product_bound': product_bound, 'half_bound': HALF, 'half_bits': HALF.bit_length(),
            'profiles': profiles,
            'inflated_input_bundle_refused_before_execution': True,
            'safe_basis_roots_per_query': 1,
            'emits_composable_joint_state': False, 'full_refresh_admitted': False,
            'boot_primes': list(BOOT)}


if __name__ == '__main__':
    print(json.dumps(run(), indent=2, sort_keys=True))
