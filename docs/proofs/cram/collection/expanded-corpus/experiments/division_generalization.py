"""Independent arithmetic checks for the expanded K-Elimination corpus.

The transduction query receives only residues, fixed frame constants and a
range certificate. Scalar X and a CRT oracle occur only in the test harness.
This is research reference code, not a NINE65 implementation or security test.
"""
from itertools import product
from fractions import Fraction
from math import gcd, lcm, prod, isqrt
from pathlib import Path
import json


def quotient_lane(divisor, anchor, dividend_lane, remainder):
    d = gcd(divisor, anchor)
    delta = dividend_lane - remainder % anchor
    if delta % d:
        raise ValueError('incompatible observations')
    resolution = anchor // d
    q = 0 if resolution == 1 else (delta // d) * pow(divisor // d, -1, resolution) % resolution
    return q, resolution


def relative_lift_transduce(residues, moduli, anchor_residue, anchor, upper_q, targets):
    """No reconstruction of X, L, canonical CRT value, or persistent winding.

    Contract: residues all come from the same 0 <= X < (upper_q+1) M;
    anchor is a same-source residue; A/gcd(M,A) >= upper_q+n.
    """
    M = prod(moduli)
    n = len(moduli)
    cofs = [M // m for m in moduli]
    cs = [r * pow(w, -1, m) % m for r, w, m in zip(residues, cofs, moduli)]
    lift_mod_anchor = sum(c * (w % anchor) for c, w in zip(cs, cofs)) % anchor
    u, resolution = quotient_lane(M, anchor, anchor_residue, lift_mod_anchor)
    if resolution < upper_q + n:
        raise ValueError('insufficient certified relative-lift resolution')
    lower = -(n - 1)
    correction = lower + (u - lower) % resolution
    return [
        (sum(c * (w % b) for c, w in zip(cs, cofs)) + correction * (M % b)) % b
        for b in targets
    ], correction


def run():
    counts = {}
    count = 0
    # Non-coprime quotient recovery, including signed quotients and modulus one.
    for b in range(1, 17):
        for a1 in range(1, 11):
            for a2 in range(1, 11):
                L = lcm(a1, a2)
                R = lcm(a1 // gcd(b, a1), a2 // gcd(b, a2))
                assert R == L // gcd(b, L)
                for q in range(-R, 2 * R):
                    for r in range(b):
                        x = b * q + r
                        q1, r1 = quotient_lane(b, a1, x % a1, r)
                        q2, r2 = quotient_lane(b, a2, x % a2, r)
                        assert q1 == q % r1 and q2 == q % r2
                        assert (b * (q + R) + r) % L == x % L
                        assert x // b == q and x % b == r
                        count += 1
    counts['noncoprime_floor_quotient_cases'] = count
    # Exhaustive solution-class check for all linear congruences, not only
    # compatible source observations constructed by the preceding test.
    count = 0
    for b in range(1, 31):
        for a in range(1, 31):
            d, R = gcd(b, a), a // gcd(b, a)
            for delta in range(a):
                sols = [q for q in range(a) if (b * q - delta) % a == 0]
                assert bool(sols) == (delta % d == 0)
                if sols:
                    first = 0 if R == 1 else (delta // d) * pow(b // d, -1, R) % R
                    assert sols == list(range(first, a, R))
                count += 1
    counts['linear_congruences_exhausted'] = count
    count = count_nonunit = negative_correction = 0
    bases = [(2,3), (3,5), (2,3,5), (4,9), (4,9,5), (2,3,5,7)]
    targets = list(range(1, 31))
    for base in bases:
        M, n = prod(base), len(base)
        for Q in range(9):
            unit_anchor = Q + n
            while gcd(unit_anchor, M) != 1:
                unit_anchor += 1
            # Includes a nonunit anchor, where division is by gcd(M,A) first.
            for A in (unit_anchor, M * (Q + n)):
                for x in range((Q + 1) * M):
                    rs = [x % m for m in base]
                    outs, k = relative_lift_transduce(rs, base, x % A, A, Q, targets)
                    assert outs == [x % b for b in targets]
                    L = sum((x % m * pow(M // m, -1, m) % m) * (M // m) for m in base)
                    assert k == (x - L) // M
                    assert -(n-1) <= k <= Q
                    assert 0 <= L < n*M and L % M == x % M
                    count += len(targets)
                    count_nonunit += gcd(M, A) > 1
                    negative_correction += k < 0
    counts['relative_lift_target_residues'] = count
    counts['relative_lift_nonunit_anchor_inputs'] = count_nonunit
    counts['relative_lift_negative_correction_inputs'] = negative_correction

    # Stronger version of safe-basis Theorem 9: no adjacency or range needed
    # for quotient residue, provided P and A are positive.
    count = 0
    for P in range(1, 26):
        for A in range(1, 26):
            for X in range(-2*P*A, 2*P*A+1):
                digit = ((X % (P*A) - X % P) // P) % A
                assert digit == (X // P) % A
                count += 1
    counts['general_one_wave_modular_digit_cases'] = count
    # Adjacency/nearby safe-basis arithmetic with explicit nondegenerate bounds.
    count = 0
    for t in range(2, 81):
        for c in range(1, 81):
            q = c*t+1
            assert q % t == 1
            assert (t*(q-c)) % q == 1
            count += 1
    counts['star_family_parameter_pairs'] = count
    # Exact low-order resonance statement underlying the safe-basis degree
    # discussion. This is an arithmetic theorem, not a stability conclusion.
    count = 0
    resonance = []
    for base in [(3,7,11,13), (2,3,5), (4,9,25)]:
        radius = min(base)
        minimum = None
        for ks in product(range(-radius, radius+1), repeat=len(base)):
            f = sum((Fraction(k,m) for k,m in zip(ks,base)),Fraction(0))
            integer_relation = f.denominator == 1
            assert integer_relation == all(k % m == 0 for k,m in zip(ks,base))
            length = sum(abs(k) for k in ks)
            if integer_relation and length:
                minimum = length if minimum is None else min(minimum,length)
            count += 1
        assert minimum == min(base)
        resonance.append({'basis':base,'minimum_nonzero_resonant_l1':minimum})
    counts['exact_rational_resonance_vectors'] = count

    negative_controls = {
        'canonical_K_with_unnormalized_CRT': {
            'base': [2,3], 'X': 1, 'M': 6, 'K_canonical': 0,
            'idempotents': [3,4], 'CRT_sum': 7, 'target': 5,
            'incorrect_output': (3+4) % 5, 'correct_output': 1,
        },
        'gpai_worked_transduction_example': {
            'base':[2,3,5,7], 'residues':[1,2,4,6], 'X':209,
            'raw_sum':1469, 'raw_relative_K':-6,
            'normalized_sum':419, 'normalized_relative_K':-1,
            'target':11, 'incorrect_output':1469%11, 'correct_output':209%11,
        },
        'Nat_subtraction_in_adjacency': {
            'P': 2, 'A': 3, 'gamma': 0, 'K': 1, 'X': 2,
            'X_mod_A': 2, 'Nat_gamma_sub_K_mod_A': max(0,0-1)%3,
        },
        'star_transparency_missing_t_gt_1': {'t':1,'c':1,'q':2,'q_mod_t':0},
        'star_inverse_missing_q_gt_1': {'t':1,'c':0,'q':1,'lhs':0,'claimed_rhs':1},
        'skew_Euler_omitted_quadratic_term': {
            'omega':[1,0], 'Aomega':[0,1], 'dt':1,
            'inner_product':0, 'energy_before':1, 'energy_after':2,
            'omitted_dt_squared_norm':1,
        },
        'volume_preserving_padic_isometric_shear': {
            'F':'F(x,y)=(x+y,y)', 'determinant':1,
            'iterate_from_0_1':'F^n(0,1)=(n,1)',
            'norm_squared':'n^2+1',
        },
        'shadow_K_not_universally_in_designated_orbit': {
            'M':2,'A':11,'X':4,'K':2,'allowed':[0,1,3,4,5,9],
        },
    }
    assert negative_controls['canonical_K_with_unnormalized_CRT']['incorrect_output'] != 1
    assert sum(r*e for r,e in zip([1,2,4,6],[105,70,126,120])) == 1469
    assert (1469-6*210)%11 == (419-210)%11 == 209%11 == 0
    assert negative_controls['Nat_subtraction_in_adjacency']['Nat_gamma_sub_K_mod_A'] != 2
    # Shear/inverse have integer coefficients; this verifies the exact finite
    # congruence/isometry manifestation of the all-p proof over several p^e.
    for m in [2,3,4,5,7,8,9,11,25,49]:
        images = {( (x+y)%m, y) for x in range(m) for y in range(m)}
        assert len(images) == m*m
    for n in range(101):
        assert n*n+1 == sum(z*z for z in (n,1))

    # Check the compendium's finite safe-shell evidence from a fresh sieve.
    N, M = 500_000, 30_030
    sieve = bytearray(b'\x01') * (N + 1)
    sieve[0:2] = b'\x00\x00'
    for p in range(2, isqrt(N)+1):
        if sieve[p]: sieve[p*p:N+1:p] = b'\x00' * ((N-p*p)//p+1)
    first = {}
    for p in range(17, N+1):
        if sieve[p]: first.setdefault(p%M,p)
    assert len(first) == 5760
    last = max(first.values())
    shell = {
        'unit_signatures':len(first), 'last_filling_prime':last,
        'last_filling_signature':[last%p for p in [2,3,5,7,11,13]],
        'coverage':{str(h):sum(v<=h for v in first.values()) for h in [50_000,100_000,150_000,200_000,300_000,464_561,500_000]},
    }
    constants = {
        'M_S6':prod([2,3,5,7,11,13]),
        'M_S8':prod([2,3,5,7,11,13,17,19]),
        'phi_S6':prod(p-1 for p in [2,3,5,7,11,13]),
        'phi_S8':prod(p-1 for p in [2,3,5,7,11,13,17,19]),
        'transport_S6':[p for p in [2,3,5,7,11,13] if gcd(p,10_000)==1],
        'parking_S6':[p for p in [2,3,5,7,11,13] if gcd(p,10_000)>1],
        'SD11_anchor':11**6*13*17*19,
        'SD11_anchor_bit_length':(11**6*13*17*19).bit_length(),
        'SD11_orbit':[pow(4,k,11) for k in range(5)],
        'calendar_pair_count':lcm(260,365),
        'three_tier_smaller_witness':2*5*13,
        'periods_divisible_by_17':[x for x in [260,365,584,780,399,378,11960,18980,819,116,30] if x%17==0],
    }
    result={'status':'PASS','counts':counts,'negative_controls':negative_controls,'safe_shell_recomputed':shell,'constants_recomputed':constants,'finite_resonance_recomputed':resonance}
    out = Path(__file__).with_name('division_generalization_results.json')
    out.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))


if __name__=='__main__': run()
