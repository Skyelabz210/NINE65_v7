#!/usr/bin/env python3
"""Exact clear identities and noise budgets for three-pair terminal readouts.

This independently checks the public lookup tables and certified bounds. It
does not perform encrypted evaluation; the native Rust fixture is separate.
"""

import hashlib
import itertools
import json
from pathlib import Path

from safe_basis_pair_probe import (
    BOOT, ETA, H, HALF, N, PROJECTED, Q, QB, ROOT, SWITCH, T, multiply, nearest,
)

TRAYS = (6, 10, 77, 221, 1, 8, 27, 121, 4199, 65537)
WEIGHTS_SMALL = (14, 12, 10, 8, 6, 4)


def pair_rows(terms, q=Q):
    rows = []
    for left, right in itertools.product((-1, 0, 1), repeat=2):
        value = terms[0] * left + terms[1] * right
        winding = nearest(value, q)
        rows.append((value - q * winding, winding))
    return rows


def raw(row, q=Q):
    return row[0] + q * row[1]


def carry_value(rows, initial, sign, q):
    return nearest(sign * (initial + sum(raw(row, q) for row in rows)), q)


def cube_differences(table):
    base = table[0][0][0]
    a = [table[i][0][0] - base for i in range(1, 9)]
    b = [table[0][j][0] - base for j in range(1, 9)]
    c = [table[0][0][k] - base for k in range(1, 9)]
    ab = [[table[i][j][0] - table[i][0][0] - table[0][j][0] + base
           for j in range(1, 9)] for i in range(1, 9)]
    ac = [[table[i][0][k] - table[i][0][0] - table[0][0][k] + base
           for k in range(1, 9)] for i in range(1, 9)]
    bc = [[table[0][j][k] - table[0][j][0] - table[0][0][k] + base
           for k in range(1, 9)] for j in range(1, 9)]
    abc = [[[table[i][j][k] - table[i][j][0] - table[i][0][k] - table[0][j][k]
             + table[i][0][0] + table[0][j][0] + table[0][0][k] - base
             for k in range(1, 9)] for j in range(1, 9)] for i in range(1, 9)]
    return base, a, b, c, ab, ac, bc, abc


def cube_at(diff, i, j, k):
    base, a, b, c, ab, ac, bc, abc = diff
    out = base
    if i:
        out += a[i - 1]
    if j:
        out += b[j - 1]
    if k:
        out += c[k - 1]
    if i and j:
        out += ab[i - 1][j - 1]
    if i and k:
        out += ac[i - 1][k - 1]
    if j and k:
        out += bc[j - 1][k - 1]
    if i and j and k:
        out += abc[i - 1][j - 1][k - 1]
    return out


def cube_bound(diff):
    base, a, b, c, ab, ac, bc, abc = diff
    pair_error = multiply(PROJECTED, PROJECTED)
    triple_error = multiply(pair_error, PROJECTED)
    return (abs(base)
            + PROJECTED * (sum(map(abs, a)) + sum(map(abs, b)) + sum(map(abs, c)))
            + pair_error * (sum(map(abs, itertools.chain.from_iterable(ab)))
                            + sum(map(abs, itertools.chain.from_iterable(ac)))
                            + sum(map(abs, itertools.chain.from_iterable(bc))))
            + triple_error * sum(map(abs, itertools.chain.from_iterable(
                itertools.chain.from_iterable(abc)))))


def table_for(states, initial, sign, q, modulus=None):
    def output(a, b, c):
        total = sign * (initial + raw(a, q) + raw(b, q) + raw(c, q))
        return nearest(total, q) if modulus is None else total % modulus
    return [[[output(a, b, c) for c in states[2]] for b in states[1]]
            for a in states[0]]


def phase211(parts):
    phase = sum(value // 2 % 11 for value in parts)
    parity = [value % 2 for value in parts]
    return (phase + sum(parity) // 2) % 11


def small_exact_cases():
    q = 31
    h = q // 2
    states = [pair_rows(WEIGHTS_SMALL[i:i + 2], q) for i in (0, 2, 4)]
    checks = failures = cubic_terms = 0
    for initial in (-h, h):
        for sign in (-1, 1):
            table = table_for(states, initial, sign, q)
            diff = cube_differences(table)
            for i, plane in enumerate(table):
                for j, row in enumerate(plane):
                    for k, expected in enumerate(row):
                        assert cube_at(diff, i, j, k) == expected
                        linear_pair = diff[0]
                        if i:
                            linear_pair += diff[1][i - 1]
                        if j:
                            linear_pair += diff[2][j - 1]
                        if k:
                            linear_pair += diff[3][k - 1]
                        if i and j:
                            linear_pair += diff[4][i - 1][j - 1]
                        if i and k:
                            linear_pair += diff[5][i - 1][k - 1]
                        if j and k:
                            linear_pair += diff[6][j - 1][k - 1]
                        failures += int(linear_pair != expected)
                        parts = [sign * (initial + raw(states[0][i], q)),
                                 sign * raw(states[1][j], q),
                                 sign * raw(states[2][k], q)]
                        total = sum(parts)
                        assert phase211(parts) == total // 2 % 11
                        for modulus in (2, 6, 11, 77, 221, 4199):
                            assert total % modulus == sum(x % modulus for x in parts) % modulus
                        checks += 1
            cubic_terms += sum(value != 0 for value in itertools.chain.from_iterable(
                itertools.chain.from_iterable(diff[7])))
    assert checks == 2916
    assert failures == cubic_terms == 1096
    return checks, failures


def run():
    small_checks, linear_pair_failures = small_exact_cases()
    states = [pair_rows((H - 1, H - 3)),
              pair_rows((H - 9, H - 27)),
              pair_rows((H - 81, H - 243))]
    queries = ((H, 1), (H, -1), (-H + 40, 1), (-H + 40, -1))
    carry_profiles = []
    diffs = []
    for initial, sign in queries:
        diff = cube_differences(table_for(states, initial, sign, Q))
        bound = cube_bound(diff)
        assert bound < HALF
        cubic = sum(value != 0 for value in itertools.chain.from_iterable(
            itertools.chain.from_iterable(diff[7])))
        carry_profiles.append({
            'initial': initial,
            'sign': sign,
            'selected_carry': carry_value(
                [states[i][8] for i in range(3)], initial, sign, Q),
            'error_bound': bound,
            'error_bits': bound.bit_length(),
            'nonzero_pair_terms': sum(value != 0 for surface in diff[4:7]
                                      for value in itertools.chain.from_iterable(surface)),
            'nonzero_three_way_terms': cubic,
        })
        diffs.append(diff)

    product_ab = set()
    product_ac = set()
    product_bc = set()
    product_abc = set()
    for diff in (diffs[0], diffs[2]):
        for i in range(8):
            for j in range(8):
                if diff[4][i][j] or any(diff[7][i][j][k] for k in range(8)):
                    product_ab.add((i, j))
                if diff[5][i][j]:
                    product_ac.add((i, j))
                if diff[6][i][j]:
                    product_bc.add((i, j))
                for k in range(8):
                    if diff[7][i][j][k]:
                        product_abc.add((i, j, k))
    shared_carry_products = len(product_ab) + len(product_ac) + len(product_bc) + len(product_abc)
    assert shared_carry_products == 146

    phase_bounds = []
    for initial, sign in queries:
        offset = sign * initial
        offset_phase, offset_parity = offset // 2 % 11, offset % 2
        phases = [sum(PROJECTED * abs(sign * raw(row) // 2 % 11) for row in state)
                  for state in states]
        parities = [sum(PROJECTED * abs(sign * raw(row) % 2) for row in state)
                    for state in states]
        pair_products = [multiply(parities[0], parities[1]),
                         multiply(parities[0], parities[2]),
                         multiply(parities[1], parities[2])]
        triple_product = multiply(pair_products[0], parities[2])
        bound = (abs(offset_phase) + sum(phases) + offset_parity * sum(parities)
                 + sum(pair_products) + 2 * triple_product)
        assert bound < HALF
        phase_bounds.append({'initial': initial, 'sign': sign,
                             'error_bound': bound, 'error_bits': bound.bit_length(),
                             'selector_products': 4})

    residue_moduli = ROOT + TRAYS
    residue_bounds = []
    for modulus in residue_moduli:
        assert modulus == T or 4 * (modulus - 1) < T
        per_pair = [sum(PROJECTED * abs((raw(row) % modulus)) for row in state)
                    for state in states]
        offset = H % modulus
        bound = offset + sum(per_pair)
        assert bound < HALF
        residue_bounds.append({'modulus': modulus, 'error_bound': bound,
                               'error_bits': bound.bit_length(),
                               'representation': 'additive residue representative'})

    oversized_diff = cube_differences(table_for(states, H, 1, Q, 20_000))
    oversized_bound = cube_bound(oversized_diff)
    assert oversized_bound >= HALF
    carry = carry_profiles[0]
    rem = QB % T
    affine_error = (N * (ETA * (2*N + 1) * N * (T//2)
                         + (N + 1) * rem + (rem + 1)//2)
                    + (N - 1) * SWITCH)
    refreshed_error = affine_error + carry['error_bound']
    assert refreshed_error < HALF
    next_square = multiply(refreshed_error, refreshed_error)
    assert next_square >= HALF

    native_checks = (27 + 4 + 1 + len(residue_moduli) + 2) * N
    assert native_checks == 425984
    repo = Path(__file__).resolve().parent.parent
    paths = (
        'scripts/safe_basis_three_pair_probe.py',
        'scripts/safe_basis_pair_probe.py',
        'crates/nine65/src/ops/safe_basis_terminal_tests.rs',
        'crates/nine65/src/ops/safe_basis_pair_tests.rs',
        'crates/nine65/src/ops/safe_basis_composition_tests.rs',
        'crates/nine65/src/ops/safe_basis_precharge_tests.rs',
        'crates/nine65/src/ops/exact_mul.rs',
        'Cargo.lock',
    )
    return {
        'schema': 'nine65-safe-basis-three-pair-terminal-v1',
        'baseline': 'ad276249b8b827868959957919ded3319c96b795',
        'source_sha256': {path: hashlib.sha256((repo / path).read_bytes()).hexdigest()
                          for path in paths},
        'small_exact_assignments': small_checks,
        'linear_and_pair_only_carry_failures': linear_pair_failures,
        'input_pair_rows': [9, 9, 9],
        'possible_joint_labels': 729,
        'existing_state_limit': 27,
        'carry_profiles': carry_profiles,
        'shared_carry_selector_products': shared_carry_products,
        'phase211_profiles': phase_bounds,
        'phase211_products_per_query': 4,
        'safe_basis_root_count': 1,
        'residue_views': residue_bounds,
        'oversized_modulus': {'modulus': 20_000, 'error_bound': oversized_bound,
                              'error_bits': oversized_bound.bit_length(),
                              'refused_before_products': True},
        'native_checks': native_checks,
        'native_carry_and_phase_products': {'carry': 146, 'phase211': 4},
        'refresh': {'affine_error_bound': affine_error,
                    'six_term_error_bound': refreshed_error,
                    'six_term_error_bits': refreshed_error.bit_length(),
                    'subsequent_square_bound': next_square,
                    'subsequent_square_bits': next_square.bit_length(),
                    'subsequent_square_refused_before_multiplication': True},
        'plaintext_modulus': T,
        'boot_primes': list(BOOT),
        'half_scale': HALF,
        'half_scale_bits': HALF.bit_length(),
        'full_refresh_admitted': False,
        'reusable_joint_state_emitted': False,
    }


if __name__ == '__main__':
    print(json.dumps(run(), indent=2, sort_keys=True))
