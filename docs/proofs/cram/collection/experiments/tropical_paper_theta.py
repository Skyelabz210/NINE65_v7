#!/usr/bin/env python3
"""Independent exact oracle for the uploaded October 25 report.

This is clear integer mathematics, not FHE and not the missing trop.rs.
The fixed minimization interval [-42,42] contains every global minimizer
on the checked domain: |z/Q| < 40.5, and also for z+1 the magnitude is <41.
Outside the interval the quadratic is strictly monotone away from its vertex.
"""
from collections import Counter
import json


def require(value, message):
    if not value:
        raise AssertionError(message)


def theta(q, z):
    values = [(q*n*n + 2*n*z, n) for n in range(-42, 43)]
    best = min(v for v, _ in values)
    return best, [n for v, n in values if v == best]


counts = Counter()
for q in range(3, 62, 2):
    for g in range(-(q//2), q//2+1):
        for k in range(-40, 41):
            z = g + q*k
            value, minimizers = theta(q, z)
            require(minimizers == [-k], ('argmin', q, g, k))
            require(value == -2*k*g-q*k*k, ('theta value', q, g, k))
            counts['theta_cases'] += 1
            next_value, _ = theta(q, z+1)
            bit = int(g == q//2)
            require(next_value-value == -2*k-bit, ('difference', q, g, k))
            counts['theta_difference_cases'] += 1
            anchor = 131
            observed = ((z % anchor-g % anchor)*pow(q, -1, anchor)) % anchor
            recovered = observed-anchor if 2*observed > anchor else observed
            require(recovered == k, ('anchor', q, g, k))
            counts['signed_anchor_recovery_cases'] += 1

require(counts['theta_cases'] == 77760, 'advertised domain count')
wall_value, wall_minimizers = theta(6, 3)
require(wall_value == 0 and wall_minimizers == [-1, 0], 'wall tie')
bad_value, bad_minimizers = theta(3, 3)
require(bad_value == -3 and bad_minimizers == [-1], 'noncentered g=3,K=0 fails claim')
require((0 % 131, (3*131) % 131) == (0, 0), 'fixed anchor alias')
print(json.dumps({
    'status': 'PASS',
    'scope': 'Independent exact arithmetic, not the missing original Rust source; not FHE',
    'domain': 'odd Q=3..61, integer g=-(Q-1)/2..(Q-1)/2, K=-40..40',
    'counts': dict(counts),
    'negative_controls': {
        'Q6_real_wall_z3_minimizers': wall_minimizers,
        'noncentered_Q3_g3_K0': {'actual_minimizers': bad_minimizers, 'actual_value': bad_value},
        'Q3_anchor131_sheet_alias': [0, 131]
    }
}, indent=2))
