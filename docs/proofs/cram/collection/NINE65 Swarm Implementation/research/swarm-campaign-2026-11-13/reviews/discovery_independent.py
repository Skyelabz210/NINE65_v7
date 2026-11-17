"""Independent rectangular-module, BBS and geometry checks of discovery code."""
from fractions import Fraction
from itertools import product
from pathlib import Path
import hashlib
import json
import random
import sys
from math import gcd

HERE = Path(__file__).resolve().parent
DISCOVERY = HERE.parent / "discovery"
sys.path.insert(0, str(DISCOVERY))
from models import (compile_integer_query, QueryDecoder, AdjacentFrame,
                    observe_point, orientation_from_views, bbs_residue_step,
                    heights, discrete_pitman, interpolate, continuous_pitman,
                    hasse_at, jet_quotient_query)


def multiply(a, b):
    return [[sum(a[i][k]*b[k][j] for k in range(len(b)))
             for j in range(len(b[0]))] for i in range(len(a))]


def invert(a):
    n = len(a)
    aug = [[Fraction(x) for x in row] + [Fraction(i == j) for j in range(n)]
           for i, row in enumerate(a)]
    for j in range(n):
        pivot = next(i for i in range(j,n) if aug[i][j])
        aug[j],aug[pivot] = aug[pivot],aug[j]
        divisor = aug[j][j]
        aug[j] = [x/divisor for x in aug[j]]
        for i in range(n):
            if i != j:
                factor = aug[i][j]
                aug[i] = [x-factor*y for x,y in zip(aug[i],aug[j])]
    result = [row[n:] for row in aug]
    assert all(x.denominator == 1 for row in result for x in row)
    return [[int(x) for x in row] for row in result]


def unimodular(n, rng):
    a = [[int(i == j) for j in range(n)] for i in range(n)]
    for _ in range(6):
        i,j = rng.randrange(n),rng.randrange(n)
        if i == j:
            a[i] = [-x for x in a[i]]
        else:
            c = rng.randrange(-3,4)
            a[i] = [x+c*y for x,y in zip(a[i],a[j])]
    return a


def main():
    rng = random.Random(913651)
    counts = {"module_certificates":0,"decoder_sources":0,"collision_certificates":0,
              "orientation_triples":0,"bbs_configurations":0,"interpolation_points":0,
              "jet_instances_including_composite_rings":0}
    for r,n,m in product(range(1,4), range(1,4), range(1,7)):
        for _ in range(8):
            u,v = unimodular(r,rng),unimodular(n,rng)
            diagonal = [[rng.randrange(-8,9) if i == j else 0 for j in range(n)] for i in range(r)]
            b = multiply(multiply(invert(u),diagonal),invert(v))
            c = [rng.randrange(-8,9) for _ in range(n)]
            result = compile_integer_query(b,c,m,u,v)
            counts["module_certificates"] += 1
            if isinstance(result,QueryDecoder):
                for x in product(range(m),repeat=n):
                    observation = [sum(row[j]*x[j] for j in range(n)) % m for row in b]
                    expected = sum(c[j]*x[j] for j in range(n)) % m
                    assert result.evaluate(observation) == expected
                    counts["decoder_sources"] += 1
            else:
                x = result.kernel_witness
                assert all(sum(row[j]*x[j] for j in range(n)) % m == 0 for row in b)
                assert sum(c[j]*x[j] for j in range(n)) % m == result.target_delta != 0
                counts["collision_certificates"] += 1

    frame = AdjacentFrame(9)
    points = tuple(product(range(-1,2),repeat=2))
    for a,b,c in product(points,repeat=3):
        # Homogeneous 3x3 determinant is an independent orientation expression.
        value = a[0]*(b[1]-c[1]) + b[0]*(c[1]-a[1]) + c[0]*(a[1]-b[1])
        assert orientation_from_views(tuple(observe_point(p,frame) for p in (a,b,c)),1,frame) == (value>0)-(value<0)
        counts["orientation_triples"] += 1

    for n in range(10):
        for bits in product((0,1),repeat=n):
            padded = bits + (0,)*n
            result,readings = bbs_residue_step(padded,frame)
            # Direct ball matching: each original ball moves to the first
            # unoccupied site strictly to its right, in left-to-right order.
            occupied = set(i for i,bit in enumerate(padded) if bit)
            destinations = set()
            for i,bit in enumerate(padded):
                if bit:
                    j = i+1
                    while j in occupied or j in destinations:
                        j += 1
                    destinations.add(j)
                    occupied.remove(i)
            expected = tuple(int(i in destinations) for i in range(len(padded)))
            assert result == expected
            assert sum(result) == sum(bits)
            assert readings[-1] == (0,0)
            h,hnew = heights(padded),heights(result)
            assert hnew == discrete_pitman(h)
            for k in range(6*n+1):
                t=Fraction(k,3)
                assert interpolate(hnew,t)==continuous_pitman(h,t)
                counts["interpolation_points"] += 1
            counts["bbs_configurations"] += 1
    assert interpolate(discrete_pitman((0,-1,1)),Fraction(5,4)) == 1
    assert continuous_pitman((0,-1,1),Fraction(5,4)) == Fraction(1,2)
    def poly_mul(a,b):
        out=[0]*(len(a)+len(b)-1)
        for i,x in enumerate(a):
            for j,y in enumerate(b): out[i+j]+=x*y
        return out
    def poly_add(a,b):
        return [(a[i] if i<len(a) else 0)+(b[i] if i<len(b) else 0) for i in range(max(len(a),len(b)))]
    def jet_by_horner(coeff,a,nu):
        # Expand by Horner substitution rather than the implementation's
        # binomial coefficient formula.
        shifted=[0]
        for c in reversed(coeff): shifted=poly_add(poly_mul(shifted,[a,1]),[c])
        return shifted[nu] if nu<len(shifted) else 0
    for modulus,point,order in product(range(2,13),range(-2,3),range(5)):
        units=[u for u in range(modulus) if gcd(u,modulus)==1]
        for _ in range(4):
            unit=rng.choice(units); slope=rng.randrange(-5,6)
            u=[unit-slope*point,slope]
            multiplier=[1]
            for _ in range(order): multiplier=poly_mul(multiplier,[-point,1])
            multiplier=poly_mul(multiplier,u)
            k=[rng.randrange(-9,10) for _ in range(3)]
            r=[rng.randrange(-9,10) for _ in range(3)]
            x=poly_add(r,poly_mul(multiplier,k))
            xj=jet_by_horner(x,point,order)%modulus
            rj=jet_by_horner(r,point,order)%modulus
            mj=jet_by_horner(multiplier,point,order)%modulus
            assert all(jet_by_horner(multiplier,point,i)%modulus==0 for i in range(order))
            assert hasse_at(x,point,order,modulus)==xj
            assert hasse_at(multiplier,point,order,modulus)==mj==unit
            assert jet_quotient_query(xj,rj,mj,modulus)==sum(v*point**i for i,v in enumerate(k))%modulus
            counts['jet_instances_including_composite_rings']+=1
    report={"status":"PASS","seed":913651,"scope":"Independent clear-model tests, not new Lean or encrypted execution",
            "counts":counts,"negative_controls":["general-jump interpolation obstruction"],
            "source_sha256":{str(p.name):hashlib.sha256(p.read_bytes()).hexdigest()
                             for p in [Path(__file__),DISCOVERY/'models.py']}}
    (HERE/'discovery_independent.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__':
    main()
