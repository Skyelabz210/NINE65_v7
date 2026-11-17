"""Reproducible finite discovery experiments with independent clear oracles."""
from fractions import Fraction
from itertools import product
from math import factorial
from pathlib import Path
import hashlib
import json
import random

from models import (AdjacentFrame, QueryDecoder, QueryObstruction,
                    bbs_residue_step, centered_theta_indices,
                    compile_integer_query, continuous_pitman, discrete_pitman,
                    hasse_at, heights, hensel_step, interpolate,
                    jet_quotient_query, matmul, observe_point,
                    orientation_from_views)

ROOT = Path(__file__).resolve().parent


def check_module_queries():
    rng = random.Random(651113)
    counts = {"certificates":0, "decoders":0, "obstructions":0, "source_vectors":0}
    for modulus in range(2,10):
        for _ in range(80):
            a,b = rng.randrange(-4,5),rng.randrange(-4,5)
            u,ui = [[1,a],[0,1]],[[1,-a],[0,1]]
            v,vi = [[1,0],[b,1]],[[1,0],[-b,1]]
            s = [[rng.randrange(-modulus,modulus+1),0],
                 [0,rng.randrange(-modulus,modulus+1)]]
            matrix = matmul(matmul(ui,s),vi)
            query = [rng.randrange(modulus),rng.randrange(modulus)]
            certificate = compile_integer_query(matrix,query,modulus,u,v)
            counts["certificates"] += 1
            if isinstance(certificate, QueryDecoder):
                counts["decoders"] += 1
                for x in product(range(modulus),repeat=2):
                    y = [sum(ci*xi for ci,xi in zip(row,x)) % modulus for row in matrix]
                    assert certificate.evaluate(y) == sum(ci*xi for ci,xi in zip(query,x)) % modulus
                    counts["source_vectors"] += 1
            else:
                counts["obstructions"] += 1
                x = certificate.kernel_witness
                assert all(sum(ci*xi for ci,xi in zip(row,x)) % modulus == 0 for row in matrix)
                assert sum(ci*xi for ci,xi in zip(query,x)) % modulus == certificate.target_delta != 0
    # Shared-factor composite example: no full inverse, but requested query works.
    matrix = [[2,4],[0,3]]
    v = [[1,-2],[0,1]]
    certificate = compile_integer_query(matrix,[2,1],6,[[1,0],[0,1]],v)
    assert certificate.weights == (1,1)
    impossible = compile_integer_query(matrix,[1,0],6,[[1,0],[0,1]],v)
    assert isinstance(impossible, QueryObstruction)
    for query in ([2,4],[0,1]):
        cert = compile_integer_query([[2,4]],query,6,[[1]],v)
        if query == [2,4]:
            assert isinstance(cert, QueryDecoder)
        else:
            assert isinstance(cert, QueryObstruction)
    counts["fixed_composite_and_rectangular_controls"] = 4
    return counts


def check_geometry():
    h,frame = 2,AdjacentFrame(9)
    points = tuple(product(range(-h,h+1),repeat=2))
    views = {p:observe_point(p,frame) for p in points}
    counts = {"ordered_point_triples":0,"positive":0,"negative":0,"collinear":0}
    for a,b,c in product(points,repeat=3):
        det = (b[0]-a[0])*(c[1]-a[1])-(b[1]-a[1])*(c[0]-a[0])
        got = orientation_from_views((views[a],views[b],views[c]),h,frame)
        assert got == (det>0)-(det<0)
        counts["ordered_point_triples"] += 1
        counts[{1:"positive",-1:"negative",0:"collinear"}[got]] += 1
    try:
        orientation_from_views([observe_point(p,AdjacentFrame(2)) for p in points[:3]],2,AdjacentFrame(2))
        raise AssertionError("insufficient capacity accepted")
    except ValueError:
        pass
    counts["capacity_negative_controls"] = 1
    return counts


def check_bbs():
    frame = AdjacentFrame(9)
    counts = {"configurations":0,"carrier_prefixes":0,"rational_interpolation_points":0}
    for n in range(1,11):
        for bits in product((0,1),repeat=n):
            # The empty tail makes the finite configuration fully drain.
            padded = bits + (0,)*n
            successor, readings = bbs_residue_step(padded,frame)
            h,actual = heights(padded),heights(successor)
            assert actual == discrete_pitman(h)
            assert sum(successor) == sum(bits)
            carrier = 0
            for i,bit in enumerate(padded):
                out = min(1-bit,carrier)
                carrier += bit-out
                assert successor[i] == out
                assert readings[i+1] == (carrier%9,carrier%10)
                # Ephemeral adjacent quotient query of the physical carrier.
                r,a = readings[i+1]
                assert (r-a)%10 == carrier//9
                counts["carrier_prefixes"] += 1
            assert carrier == 0
            for j in range(8*n+1):
                t = Fraction(j,4)
                assert interpolate(actual,t) == continuous_pitman(h,t)
                counts["rational_interpolation_points"] += 1
            counts["configurations"] += 1
    bad_path = (0,-1,1)
    t=Fraction(5,4)
    assert interpolate(discrete_pitman(bad_path),t) == 1
    assert continuous_pitman(bad_path,t) == Fraction(1,2)
    counts["general_jump_negative_controls"] = 1
    return counts


def poly_mul(a,b):
    result=[0]*(len(a)+len(b)-1)
    for i,x in enumerate(a):
        for j,y in enumerate(b): result[i+j]+=x*y
    return result


def check_jets_and_hensel():
    rng=random.Random(651114)
    counts={"jet_instances":0,"hensel_steps":0,"ordinary_derivative_failure_controls":1}
    for p in (2,3,5,7):
        for a in range(p):
            for order in range(1,p+2):
                for _ in range(15):
                    u=[rng.randrange(p) for _ in range(3)]
                    if hasse_at(u,a,0,p)==0: u[0]=(u[0]+1)%p
                    multiplier=[1]
                    for _ in range(order): multiplier=poly_mul(multiplier,[-a,1])
                    multiplier=poly_mul(multiplier,u)
                    k=[rng.randrange(p) for _ in range(5)]
                    remainder=[rng.randrange(p) for _ in range(4)]
                    source=poly_mul(multiplier,k)
                    source += [0]*max(0,len(remainder)-len(source))
                    for i,r in enumerate(remainder): source[i]+=r
                    assert all(hasse_at(multiplier,a,j,p)==0 for j in range(order))
                    got=jet_quotient_query(hasse_at(source,a,order,p),hasse_at(remainder,a,order,p),
                                           hasse_at(multiplier,a,order,p),p)
                    assert got==hasse_at(k,a,0,p)
                    counts["jet_instances"]+=1
        for c in range(p):
            coefficients=[-c,0,1]
            for initial in range(p):
                if (initial*initial-c)%p or (2*initial)%p==0: continue
                a=initial
                for exponent in range(1,5):
                    new=hensel_step(coefficients,p,exponent,a)
                    assert (new*new-c)%p**(exponent+1)==0
                    assert (new-a)%p**exponent==0
                    a=new
                    counts["hensel_steps"]+=1
    assert hasse_at([0,0,0,1],0,3,3)==1
    assert factorial(3)*hasse_at([0,0,0,1],0,3,3)%3==0
    return counts


def check_internal_bridges():
    counts={"theta_charts":0,"theta_walls":0,"maa_reflections":0,"allocations":0,
            "skew_energy_coordinate_bound_counterexamples":1}
    for q in range(2,14):
        for g in range(-q//2-1,q//2+2):
            if abs(2*g)>q: continue
            for k in range(-12,13):
                z=g+q*k
                minimizers=centered_theta_indices(q,z)
                if abs(2*g)<q:
                    assert minimizers==(-k,)
                    counts["theta_charts"]+=1
                else:
                    assert len(minimizers)==2 and -k in minimizers
                    counts["theta_walls"]+=1
                # Arbitrary centered reference, not canonical floor residue.
                assert ((z%(q+1))-(g%(q+1)))%(q+1)==(-k)%(q+1)
    form=lambda x:2*sum(t*t for t in x)-sum(x)**2
    for x in product(range(-2,3),repeat=4):
        for i in range(4):
            y=list(x);y[i]=2*sum(x[j] for j in range(4) if j!=i)-x[i]
            z=list(y);z[i]=2*sum(y[j] for j in range(4) if j!=i)-y[i]
            assert tuple(z)==x and form(y)==form(x)
            counts["maa_reflections"]+=1
    for weights in product(range(5),repeat=3):
        if not sum(weights):continue
        for total in range(10):
            den=sum(weights)
            floors=[total*a//den for a in weights]
            deficit=total-sum(floors)
            assert 0<=deficit<3
            ranked=sorted(range(3),key=lambda i:(-(total*weights[i]%den),i))
            for i in ranked[:deficit]:floors[i]+=1
            assert sum(floors)==total
            assert all(abs(Fraction(floors[i])-Fraction(total*weights[i],den))<1 for i in range(3))
            counts["allocations"]+=1
    x=(Fraction(1),Fraction(1));y=(Fraction(-1,5),Fraction(7,5))
    assert sum(t*t for t in x)==sum(t*t for t in y)==2
    assert max(map(abs,y))>max(map(abs,x))
    return counts


def main():
    evidence={"status":"PASS","scope":"Finite exact research models; no new Lean or ciphertext execution",
              "module_queries":check_module_queries(),"geometry":check_geometry(),
              "bbs":check_bbs(),"jets_and_hensel":check_jets_and_hensel(),
              "internal_bridges":check_internal_bridges(),
              "source_sha256":{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
                               for name in ("models.py","run_models.py")}}
    (ROOT/"model-evidence.json").write_text(json.dumps(evidence,indent=2)+"\n")
    print(json.dumps(evidence,indent=2))


if __name__=="__main__":main()
