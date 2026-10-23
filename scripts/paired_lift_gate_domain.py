#!/usr/bin/env python3
"""Exact valid-input witnesses for an INPUT-INDEPENDENT paired chart LUT.

The lower degree applies to a fixed coefficientwise polynomial F(U,D) over
Fp on the complete norm-admitted source envelope, including a public linear
change of its inputs. It does not rule out
input-adaptive compilers, additional encrypted views, rational/branching
circuits, or CRAM. Native client fixtures validate the witnesses separately.
"""

import json
from functools import lru_cache
from math import comb, factorial, prod

Q = 998244353 * 985661441
P = 65537
M = 32768
H = 96
COORDINATES = (99, 121)


def ceil_div(a, b):
    return -((-a) // b)


def rounding_cell(value):
    low = max(ceil_div(m*Q*(2*value - 1), 2*M) for m in COORDINATES)
    high = min(ceil_div(m*Q*(2*value + 1), 2*M) - 1 for m in COORDINATES)
    return max(low, -(Q//2)), min(high, Q//2)


def round_weight(residual, coordinate):
    return (2*M*residual + coordinate*Q) // (2*coordinate*Q)


def witness(t, k, phase_denominator=16):
    if t*k < 0 or t == 0 and k != 0:
        return None
    sign = 1 if t >= 0 else -1
    size = H + 1  # R0 plus 96 signed source contributions.
    cells = [rounding_cell(abs(t)//size + int(i < abs(t) % size)) for i in range(size)]
    if any(low > high for low, high in cells):
        return None
    low, high = sum(a for a, _ in cells), sum(b for _, b in cells)
    target = min(max(Q*abs(k), low), high)
    if abs(target-Q*abs(k)) > Q//phase_denominator:
        return None
    residuals = [a for a, _ in cells]
    extra = target - low
    for i, (a, b) in enumerate(cells):
        take = min(extra, b-a)
        residuals[i] += take
        extra -= take
    assert extra == 0
    residuals = [sign*v for v in residuals]
    z = [sum(round_weight(v, m) for v in residuals) for m in (99, 121, 143)]
    assert z[0] == z[1] == t
    g = sum(residuals) - Q*k
    assert abs(g) <= Q//phase_denominator
    assert all(abs(r) <= Q//2 for r in residuals)
    return {"t": t, "K": k, "g": g, "residuals": residuals,
            "Z": z, "U": -4*z[0]+5*z[1], "D": 9*z[0]-11*z[1]}


def newton_interpolation(points):
    xs = [x % P for x, _ in points]
    coefficients = [y % P for _, y in points]
    if len(set(xs)) != len(xs):
        raise ValueError("distinct plaintext points required")
    for j in range(1, len(xs)):
        for i in range(len(xs)-1, j-1, -1):
            coefficients[i] = (coefficients[i]-coefficients[i-1])*pow((xs[i]-xs[i-j]) % P, -1, P) % P
    return xs, coefficients


def evaluate_newton(xs, coefficients, x):
    value = 0
    for i in range(len(coefficients)-1, -1, -1):
        value = (value*(x-xs[i])+coefficients[i]) % P
    return value


@lru_cache(maxsize=None)
def analyze(denominator):
    witnesses = [w for k in (-1, 0, 1) for t in range(-4*(H+1), 4*(H+1)+1)
                 if (w := witness(t, k, denominator)) is not None]
    points = sorted((w["t"], w["K"]) for w in witnesses)
    xs, coefficients = newton_interpolation(points)
    assert all(evaluate_newton(xs, coefficients, t) == k % P for t, k in points)
    degree = max(i for i, value in enumerate(coefficients) if value)
    ranges = {str(k): {"minimum": min(t for t, y in points if y == k),
                       "maximum": max(t for t, y in points if y == k),
                       "count": sum(y == k for _, y in points)} for k in (-1, 0, 1)}
    return {"phase_denominator": denominator, "witness_count": len(points),
            "ranges": ranges, "chart_line": "U=t, D=-2*t",
            "minimal_univariate_restriction_degree": degree,
            "fixed_bivariate_total_degree_lower_bound": degree,
            "binary_ciphertext_multiply_depth_lower_bound": (degree-1).bit_length(),
            "newton_degree_certificate": {"leading_nonzero_index": degree,
                                           "leading_nonzero_value": coefficients[degree],
                                           "higher_coefficients": coefficients[degree+1:]},
            "points": points}


def simplex_indices(degree):
    return [(a,b,d-a-b) for d in range(degree+1) for a in range(d+1) for b in range(d-a+1)]


@lru_cache(maxsize=1)
def triple_simplex_certificate():
    coordinates=(99,121,143)
    blocks=[]
    for m in coordinates:
        boundary=m*Q//(2*M)
        block=[1,boundary,-boundary-1]
        assert sum(block)==0
        views=[sum(round_weight(r,sister) for r in block) for sister in coordinates]
        assert views==[-int(sister==m) for sister in coordinates]
        blocks.append(block)
    nodes=simplex_indices(32)
    determinant=1
    for alpha in nodes:
        # Each unit direction costs three source terms, so 96 terms cover
        # the entire simplex. R0=0 and the full client phase can be zero.
        residuals=[0]+[r for i,count in enumerate(alpha) for _ in range(count) for r in blocks[i]]
        residuals.extend([0]*(H+1-len(residuals)))
        assert len(residuals)==H+1 and sum(residuals)==0
        assert [sum(round_weight(r,m) for r in residuals) for m in coordinates]==[-v for v in alpha]
        diagonal=prod(factorial(v) for v in alpha)%P
        assert diagonal
        determinant=determinant*diagonal%P
    assert len(nodes)==comb(35,3) and determinant
    return {"scope":"Input-independent coefficientwise polynomial on all three native views, invariant under the unimodular chart change",
            "source_terms":H,"zero_lift_simplex_degree":32,"zero_lift_public_witnesses":len(nodes),
            "all_public_witness_residual_sums_zero":True,
            "native_simplex_ciphertexts_exhaustively_executed":False,
            "unit_direction_blocks":blocks,"unit_direction_view_vectors":[[-1,0,0],[0,-1,0],[0,0,-1]],
            "newton_basis":"graded falling factorials on the negative integer simplex",
            "evaluation_matrix_structure":"triangular by total degree, diagonal product(alpha_i!)",
            "nonzero_determinant_mod_plaintext":determinant,
            "nonzero_lift_point":[288,288,192],"nonzero_lift_value":1,
            "fixed_trivariate_total_degree_lower_bound":33,
            "binary_ciphertext_multiply_depth_lower_bound":6,
            "degree_33_gate_constructed":False}


def report():
    # The zero-phase three-term block distinguishes the third tray while
    # preserving source norm and the actual source Q, for every cap tested.
    a = 70*Q//M
    block = [a, a, -2*a]
    assert sum(block) == 0
    block_views = [sum(round_weight(v, m) for v in block) for m in (99, 121, 143)]
    high = [Q//H]*(H-1) + [Q-(H-1)*(Q//H)]
    assert sum(high) == Q
    high_views = [sum(round_weight(v, m) for v in high) for m in (99, 121, 143)]
    assert block_views == [1, 1, -1] and high_views == [288, 288, 192]
    matrix = [[-1,-3,5],[9,-11,0],[0,11,-13]]
    inverse = [[143,16,55],[117,13,45],[99,11,38]]
    triples = sorted({tuple((x4+2*m)//(4*m) for m in (99,121,143))
                      for x4 in range(-2*M,2*M+1)})
    transformed = [tuple(sum(a*x for a,x in zip(row,z)) for row in matrix) for z in triples]
    for z, y in zip(triples, transformed):
        assert tuple(sum(a*x for a,x in zip(row,y)) for row in inverse) == z
        for modulus in (2,11,22,99,121,143,65537):
            assert tuple(sum(a*x for a,x in zip(row,y)) % modulus for row in inverse) == tuple(v % modulus for v in z)
    for x4 in range(-565,566):
        z = [(x4+2*m)//(4*m) for m in (99,121,143)]
        shifted = [(x4+4*14157+2*m)//(4*m) for m in (99,121,143)]
        assert [sum(a*(b-c) for a,b,c in zip(row,shifted,z)) for row in matrix] == [1,0,0]
    ranges = [[min(v[i] for v in transformed),max(v[i] for v in transformed)] for i in range(3)]
    from source_encapsulation_budget import plan, WORK_Q
    old_input = plan(coordinate=143,phase_denominator=64,incoming_work_v=WORK_Q//20)
    safe_input = plan(coordinate=143,phase_denominator=64,incoming_work_v=WORK_Q//128)
    assert old_input["first_refusal"] == "prepared_source_phase_fits"
    assert safe_input["conditional_arithmetic_closure"]
    from full_polynomial_bootstrap_budget import square_v
    from outer_ring_return_budget import OUTER
    outer_q=prod(OUTER)
    # This is an optimistic generic ledger: it omits coefficient/slot maps
    # and starts with only a 47-bit chart input certificate. A refusal is a
    # refusal of this envelope, not a proof that all circuits are impossible.
    value=(1<<47)-1
    levels=[]
    for level in range(1,7):
        value=square_v(16384,P,outer_q,value,16384,primes=OUTER)
        fits=2*value<outer_q
        levels.append({"level":level,"V_bits":value.bit_length(),"decodes_under_bound":fits})
        if not fits:
            break
    return {"scope": "Exact norm-envelope restriction for a fixed coefficientwise polynomial LUT, not an impossibility result for other circuits or a restricted producer image",
            "source_N": 8192, "source_Q": Q, "source_norm": H, "plaintext": P, "M": M,
            "paired_domains": [analyze(16), analyze(64)],
            "third_tray": {"coordinate": 143, "common_anchor": 11,
                           "zero_phase_block_views": block_views,
                           "unit_lift_views": high_views,
                           "these_pair_line_witnesses_are_not_collinear_after_third_view": True,
                           "low_degree_three_variable_gate_proven": False,
                           "coordinates": [99,121,143], "matrix": matrix, "inverse": inverse,
                           "determinant": 1, "component_triples": len(triples),
                           "component_chart_ranges": ranges,
                           "H96_chart_integer_bounds": [97*max(map(abs,r)) for r in ranges],
                           "clock_window2_at_Q_over_64": [1024+m*97 for m in (99,121,143)],
                           "component_period": 14157, "chart_period_increment": [1,0,0]},
            "triple_simplex": triple_simplex_certificate(),
            "generic_native_polynomial_budget": {
                "scope":"Existing deterministic dense-outer multiplication envelope; omitted transform costs cannot be credited as completed work",
                "outer_N":16384,"outer_Q_bits":outer_q.bit_length(),"outer_norm_bound":16384,
                "optimistic_input_V_bits":47,"minimum_triple_gate_depth":6,
                "levels":levels,"first_refused_level":next((v["level"] for v in levels if not v["decodes_under_bound"]),None),
                "all_circuits_proven_impossible":False},
            "reference_return_envelope": {
                "scope": "Compatibility of source entry and existing reference return ledger, not execution of a triple-chart nonlinear gate",
                "old_Q119_over_20_input_refusal": old_input["first_refusal"],
                "accepted_example_working_v": WORK_Q//128,
                "maximum_admitted_working_v": safe_input["maximum_transformable_working_v"],
                "source_phase_cap": safe_input["source_phase_cap"],
                "returned_work_v_bits": safe_input["returned_work_v_bits"],
                "following_dense_work_product_v_bits": safe_input["following_dense_work_product_v_bits"],
                "following_prepared_source_v_bits": safe_input["following_source_transform"]["source_v_bits"],
                "conditional_reference_arithmetic_closure": True,
                "triple_chart_nonlinear_gate_executed": False},
            "native_fixtures_verified_by_this_script": False,
            "dense_work_transform_image_membership_proven": False,
            "authenticated_production_history_membership_proven": False,
            "covers_input_adaptive_coefficients": False,
            "encrypted_gate_implemented": False, "production_admitted": False}


if __name__ == "__main__":
    print(json.dumps(report(), indent=2))
