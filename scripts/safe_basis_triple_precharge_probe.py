#!/usr/bin/env python3
"""Clear identities and bounds for two precharged three-trit blocks."""

import hashlib
import itertools
import json
from pathlib import Path

from safe_basis_pair_probe import (
    BOOT, ETA, H, HALF, N, PROJECTED, Q, QB, ROOT, SWITCH, T, multiply, nearest,
)

TRAYS = (6, 10, 77, 221, 1, 8, 27, 121, 4199, 65537, 20000)
SMALL = (14, 12, 10, 8, 6, 4)


def block_rows(terms, q):
    rows = []
    for trits in itertools.product((-1, 0, 1), repeat=3):
        value = sum(a * u for a, u in zip(terms, trits))
        winding = nearest(value, q)
        rows.append((value - q * winding, winding))
    return rows


def raw(row, q):
    return row[0] + q * row[1]


def differences(table):
    base = table[0][0]
    left = [table[i][0] - base for i in range(1, len(table))]
    right = [v - base for v in table[0][1:]]
    mixed = [[table[i][j] - table[i][0] - table[0][j] + base
              for j in range(1, len(table[0]))] for i in range(1, len(table))]
    return base, left, right, mixed


def at(diff, i, j):
    base, left, right, mixed = diff
    return base + (left[i-1] if i else 0) + (right[j-1] if j else 0) \
        + (mixed[i-1][j-1] if i and j else 0)


def bound(diff, product_error):
    base, left, right, mixed = diff
    return (abs(base) + PROJECTED * (sum(map(abs, left)) + sum(map(abs, right)))
            + product_error * sum(abs(x) for row in mixed for x in row))


def output(value, modulus):
    if modulus == 'carry':
        return nearest(value)
    if modulus == 'phase211':
        return value // 2 % 11
    return value % modulus


def profile(states, initial, sign, moduli):
    rows = []
    product_error = multiply(PROJECTED, PROJECTED)
    total_checks = 0
    mixed_failures = 0
    for modulus in ('carry',) + ROOT + ('phase211',) + moduli:
        table = [[output(sign * (initial + raw(a, Q) + raw(b, Q)), modulus)
                  for b in states[1]] for a in states[0]]
        diff = differences(table)
        for i, row in enumerate(table):
            for j, expected in enumerate(row):
                assert at(diff, i, j) == expected
                linear = diff[0] + (diff[1][i-1] if i else 0) \
                    + (diff[2][j-1] if j else 0)
                mixed_failures += int(i > 0 and j > 0 and linear != expected)
                total_checks += 1
        error = bound(diff, product_error)
        assert error < HALF
        rows.append({'view': str(modulus), 'error_bound': error,
                     'error_bits': error.bit_length(),
                     'nonzero_mixed_terms': sum(x != 0 for row in diff[3] for x in row)})
    return rows, total_checks, mixed_failures


def small_exact():
    q = 31
    h = q // 2
    states = [block_rows(SMALL[:3], q), block_rows(SMALL[3:], q)]
    checks = failures = phase_checks = 0
    for initial in (-h, h):
        for sign in (-1, 1):
            table = [[nearest(sign * (initial + raw(a, q) + raw(b, q)), q)
                      for b in states[1]] for a in states[0]]
            diff = differences(table)
            for i, row in enumerate(table):
                for j, expected in enumerate(row):
                    assert at(diff, i, j) == expected
                    linear = diff[0] + (diff[1][i-1] if i else 0) \
                        + (diff[2][j-1] if j else 0)
                    failures += int(i > 0 and j > 0 and linear != expected)
                    parts = [sign * initial,
                             sign * raw(states[0][i], q),
                             sign * raw(states[1][j], q)]
                    phase = (sum(x // 2 % 11 for x in parts)
                             + sum(x % 2 for x in parts) // 2) % 11
                    assert phase == sum(parts) // 2 % 11
                    for modulus in (2, 6, 11, 77, 221, 4199):
                        assert sum(parts) % modulus == sum(x % modulus for x in parts) % modulus
                    checks += 1
                    phase_checks += 1
    assert checks == phase_checks == 4 * 27 * 27
    assert failures > 0
    return checks, failures


def run():
    small_checks, small_linear_failures = small_exact()
    weights = (H-1, H-3, H-9, H-27, H-81, H-243)
    states = [block_rows(weights[:3], Q), block_rows(weights[3:], Q)]
    assert len(set(raw(row, Q) for row in states[0])) == 27
    assert len(set(raw(row, Q) for row in states[1])) == 27
    profiles = []
    native_table_checks = 0
    native_linear_failures = 0
    for initial, sign in ((H, 1), (H, -1), (-H+40, 1), (-H+40, -1)):
        views, checked, failed = profile(states, initial, sign, TRAYS)
        native_table_checks += checked
        native_linear_failures += failed
        total = sign * (initial + sum(weights))
        carry = nearest(total)
        carry_bound = next(view['error_bound'] for view in views if view['view'] == 'carry')
        profiles.append({'initial': initial, 'sign': sign, 'selected_carry': carry,
                         'carry_bound': carry_bound,
                         'carry_bits': carry_bound.bit_length(),
                         'views': views})
    # Two positive-query tables share one 26x26 mixed-difference product set.
    # Negative carries are output by exact sign reversal in the native fixture.
    query_differences = []
    for initial in (H, -H+40):
        table = [[nearest(initial + raw(a, Q) + raw(b, Q)) for b in states[1]]
                 for a in states[0]]
        query_differences.append(differences(table))
    mixed_products = sum(
        any(diff[3][i][j] != 0 for diff in query_differences)
        for i in range(26) for j in range(26)
    )
    assert mixed_products <= 676
    residue_layouts = tuple(ROOT) + TRAYS
    native_checks = (54 + 84 + 2 + 1) * N  # selectors, views, refresh pair, square
    assert native_checks == 1_155_072
    rem = QB % T
    affine_error = (N * (ETA * (2*N + 1) * N * (T//2)
                         + (N + 1) * rem + (rem + 1)//2)
                    + (N - 1) * SWITCH)
    carry = profiles[0]['carry_bound']
    fresh = affine_error + carry
    square = multiply(fresh, fresh)
    assert fresh < HALF and square < HALF
    repo = Path(__file__).resolve().parent.parent
    paths = (
        'scripts/safe_basis_triple_precharge_probe.py',
        'scripts/safe_basis_pair_probe.py',
        'crates/nine65/src/ops/safe_basis_terminal_tests.rs',
        'crates/nine65/src/ops/safe_basis_triple_precharge_tests.rs',
        'crates/nine65/src/ops/safe_basis_pair_tests.rs',
        'crates/nine65/src/ops/safe_basis_composition_tests.rs',
        'crates/nine65/src/ops/safe_basis_precharge_tests.rs',
        'crates/nine65/src/ops/exact_mul.rs',
        'Cargo.lock',
    )
    return {
        'schema': 'nine65-safe-basis-triple-block-probe-v1',
        'baseline': 'c5bb6a21ee2a174ba047b4ec9a771bf9392f4b3c',
        'source_sha256': {path: hashlib.sha256((repo / path).read_bytes()).hexdigest()
                          for path in paths if (repo / path).exists()},
        'small_exact_assignments': small_checks,
        'small_linear_only_carry_failures': small_linear_failures,
        'native_lookup_checks': native_table_checks,
        'native_linear_only_carry_failures': native_linear_failures,
        'input_block_rows': [27, 27],
        'possible_joint_labels': 729,
        'mixed_difference_products_for_carry': mixed_products,
        'max_product_budget': 676,
        'max_products_per_selector': 1,
        'profiles': profiles,
        'arbitrary_target_moduli': list(residue_layouts),
        'same_keyholder_precharge_ciphertexts': 27,
        'two_triple_projection_traces': 54,
        'native_coefficient_checks_expected': native_checks,
        'native_observation': {
            'profile': 'release',
            'elapsed_seconds': 1138.90,
            'projected_selectors': 54,
            'terminal_products': 676,
            'terminal_views': 84,
            'refresh_matches_source_oracle': True,
            'affine_only_negative_control_fails': True,
            'followup_square_matches_source_oracle': True,
            'first_run_harness_exit': 'failed_only_at_final_product_counter_assertion',
            'counter_fix': 'count the separately executed square product',
            'native_rerun_after_counter_fix': False,
        },
        'followup_refresh': {'affine_error_bound': affine_error,
                             'six_term_error_bound': fresh,
                             'six_term_error_bits': fresh.bit_length(),
                             'square_bound': square,
                             'square_bits': square.bit_length(),
                             'square_predicted_admitted': square < HALF},
        'safe_basis_root_count': 1,
        'full_refresh_admitted': False,
        'boot_primes': list(BOOT),
        'half_scale': HALF,
        'half_scale_bits': HALF.bit_length(),
    }


if __name__ == '__main__':
    print(json.dumps(run(), indent=2, sort_keys=True))
