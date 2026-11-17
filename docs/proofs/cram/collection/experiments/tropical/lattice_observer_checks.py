#!/usr/bin/env python3
"""Independent exact checks for the proposed lattice-observer generalization.

This is a finite oracle, not production CRAM and not a universal proof.
No dependencies beyond the Python standard library. Rational theta arithmetic.
"""
from fractions import Fraction as F
from itertools import product
from math import gcd
import json


def mv(B, v):
    return tuple(sum(b*x for b,x in zip(row,v)) for row in B)


def obs(B, k, anchors):
    x = mv(B, k)
    return tuple(tuple(v % a for v in x) for a in anchors)


def theta(B, z, radius=10):
    vals = []
    for n in product(range(-radius, radius+1), repeat=2):
        vals.append((sum(x*y for x,y in zip(n,mv(B,n))) + 2*sum(x*y for x,y in zip(n,z)),n))
    minimum = min(v for v,n in vals)
    return minimum, [n for v,n in vals if v == minimum]


def main():
    cases = {}
    B = ((2,1),(1,3)); A = 7
    det = B[0][0]*B[1][1]-B[0][1]*B[1][0]
    assert gcd(det,A) == 1
    ks = list(product(range(A), repeat=2))
    assert len({obs(B,k,[A]) for k in ks}) == A*A
    cases['matrix_unit_observer_states'] = len(ks)

    # No scalar inverse of either diagonal in combined modulus 36, yet
    # the heterogeneous observers still separate this bounded domain.
    B = ((2,0),(0,3))
    ks = list(product(range(4), repeat=2))
    assert len({obs(B,k,[4,9]) for k in ks}) == len(ks)
    assert len({obs(B,k,[4]) for k in ks}) < len(ks)
    assert len({obs(B,k,[9]) for k in ks}) < len(ks)
    assert obs(B,(0,0),[4,9]) == obs(B,(18,12),[4,9])
    cases['nonunit_fused_observer_states'] = len(ks)
    cases['nonunit_kernel_alias'] = [[0,0],[18,12]]

    # Genuine two-dimensional real chart points, represented exactly.
    B = ((4,1),(1,6))
    checked = 0
    for g in product([F(-1,2),F(0),F(1,2)], repeat=2):
        # For this B and these g, global uniqueness is justified by
        # n'Bn+2n'g >= 3n1²+5n2²-|n1|-|n2| > 0 for n != 0.
        for k in product(range(-3,4), repeat=2):
            Bk = mv(B,k)
            z = tuple(x+y for x,y in zip(g,Bk))
            val,mins = theta(B,z)
            expected = -2*sum(x*y for x,y in zip(k,g))-sum(x*y for x,y in zip(k,Bk))
            assert val == expected
            assert mins == [tuple(-x for x in k)]
            checked += 1
    cases['rank_two_rational_theta_cases'] = checked

    # Cell walls admit multiple minimizers; no uniqueness without a convention.
    val,mins = theta(((6,0),(0,4)),(F(3),F(0)))
    assert val == 0 and set(mins) == {(-1,0),(0,0)}
    cases['theta_wall_minimizers'] = [list(v) for v in mins]

    # The document's native small-chart collapse has distinct native sheets.
    Q = 348959453350711275087786864768188417
    A = 9699690
    L = 13*A
    D = (Q//L)*L
    assert D > Q//2 and D < Q
    assert D % 13 == 0 and (D//13) % A == 0 and D % A == 0
    assert (D+Q//2)//Q == 1
    assert ((0+Q//2)//Q) == 0
    cases['small_chart_native_alias'] = {'Q':str(Q),'D':str(D),'period':L,'native_sheets':[0,1], 'native_centered_phase':str(D-Q)}

    print(json.dumps({'status':'passed','scope':'finite exact oracle; general derivations in tropical-bridge.md','checks':cases},indent=2))


if __name__ == '__main__':
    main()
