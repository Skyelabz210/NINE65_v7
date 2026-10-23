#!/usr/bin/env python3
"""Public rounding-cell audit for the native 99/121 integer lift chart.

Every discontinuity is a half-integer. Quarter-integer probes cover both
boundaries and open cells exactly, without floating point. This establishes
the public component domain and invertibility, not an encrypted nonlinear
lift gate, source security, or refresh admission.
"""

import json


def report():
    period = 1089
    clock_modulus = 32768
    round_pair = lambda x4: ((x4 + 198) // 396, (x4 + 242) // 484)
    pairs = {round_pair(x4) for x4 in range(-2*clock_modulus, 2*clock_modulus + 1)}
    moduli = (2, 11, 22, 99, 121, 198, 65537)
    for z0, z1 in pairs:
        u, d = -4*z0 + 5*z1, 9*z0 - 11*z1
        assert (11*u + 5*d, 9*u + 4*d) == (z0, z1)
        for modulus in moduli:
            assert ((11*u + 5*d) % modulus, (9*u + 4*d) % modulus) == (z0 % modulus, z1 % modulus)
    for x4 in range(-4*period, 4*period + 1):
        a, b = round_pair(x4)
        c, e = round_pair(x4 + 4*period)
        assert 9*c - 11*e == 9*a - 11*b
        assert -4*c + 5*e == -4*a + 5*b + 1
    residuals = [9*a - 11*b for a, b in pairs]
    quotients = [-4*a + 5*b for a, b in pairs]
    assert max(map(abs, residuals)) == 9
    assert max(map(abs, quotients)) == 19
    return {
        "scope": "Public piecewise rounding cells and exact integer chart; no encrypted nonlinear gate",
        "M": clock_modulus, "coordinates": [99, 121], "common_factor": 11,
        "integer_matrix": [[-4, 5], [9, -11]], "determinant": -1,
        "inverse_integer_matrix": [[11, 5], [9, 4]], "checked_moduli": moduli,
        "public_component_pairs": len(pairs),
        "component_D_range": [min(residuals), max(residuals)],
        "component_U_range": [min(quotients), max(quotients)],
        "source_norm": 96,
        "source_sum_D_sharp_public_cell_bound": 97*max(map(abs, residuals)),
        "implemented_D_bound_conservative": 970,
        "source_sum_U_public_cell_bound": 97*max(map(abs, quotients)),
        "component_period": period, "D_period_increment": 0, "U_period_increment": 1,
        "quarter_grid_covers_all_rounding_cells": True,
        "coverage_reason": "All rounding discontinuities are half-integers; quarter-integer probes include each boundary and each open cell, with no floats.",
        "ideal_U_scale": "M/1089*(K+g/Q_source)", "ideal_D_scale": 0,
        "integer_K_extracted": False, "production_admitted": False,
    }


if __name__ == "__main__":
    print(json.dumps(report(), indent=2))
