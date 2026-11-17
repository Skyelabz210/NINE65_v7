"""Source-specific exact checks; independent of archived implementation."""
from fractions import Fraction
from math import gcd
import json


def val_p(n, p):
    assert n
    count=0
    while n % p == 0:
        n//=p
        count+=1
    return count


def chimera_signature(n, p=5, q=7):
    return (n//(p*q) % 11, n%p == 0, n%q == 0,
            n%77, (n%11,n%13))


def main():
    results={}
    # Uploaded tower monographs use least-nonnegative Euclidean digits for Z.
    # Negative integers do not become zero-tail under that convention.
    n=-1
    trace=[]
    for m in [2,3,5,7,11,13]:
        r=n % m
        n=n // m
        trace.append([m,r,n])
        assert n == -1
    results['negative_finite_support_counterexample']=trace

    bits={}
    for initial in [36, 9699690]:
        p=initial
        widths=[]
        for _ in range(8):
            p=p*(p+1)
            widths.append(p.bit_length())
        bits[str(initial)]=widths
    results['doubling_tower_bit_lengths_after_8_rungs']=bits
    assert bits['36'] != [47,93,186,372,743,1486,2971,5942]
    assert bits['9699690'] == [47,93,186,372,743,1486,2971,5942]

    # Positive floor-scale theorem tested over exact rationals, including signs.
    count=0
    for numerator in range(-100,101):
        for denominator in range(1,31):
            x=Fraction(numerator,denominator)
            for scale in [3,21,231,3003,51051]:
                z=x*scale
                y=z.numerator//z.denominator
                assert 0 <= x-Fraction(y,scale) < Fraction(1,scale)
                count+=1
    results['positive_floor_scale_cases']=count
    # Value-preserving transduction and increasing-resolution sampling differ.
    x=Fraction(1,2)
    first=(x*3).__floor__()
    next_sample=(x*21).__floor__()
    assert first == 1 and next_sample == 10
    results['incompatible_rescaled_sample']={'x':'1/2','M1':3,'M2':21,
        'value_preserving_transduction':first,'next_sample_value':next_sample}
    fixed_scale=10000
    decoded=Fraction((Fraction(1,3)*fixed_scale).__floor__(),fixed_scale)
    assert decoded == Fraction(3333,10000) and decoded != Fraction(1,3)
    results['fixed_scale_limit_counterexample']={'target':'1/3',
        'all_levels_decode':str(decoded),'nonzero_error':str(Fraction(1,3)-decoded)}

    # False blanket QR generator and period-duality statements in the archive.
    p=31
    orbit=set()
    t=1
    while t not in orbit:
        orbit.add(t)
        t=t*4 % p
    qr={i*i % p for i in range(1,p)}
    assert p%4 == 3 and len(orbit)==5 and len(qr)==15
    results['p31_quadratic_residue_orbit']={'orbit':sorted(orbit),
        'orbit_order':len(orbit),'QR_count':len(qr)}
    assert 2**2%3==1 and (2**2)//3==1
    results['period_duality_counterexample']={'base':2,'modulus':3,'period':2,
        'phase_at_period':1,'integer_lift_K':1,'cycle_count':1}
    a,b=25,5030
    assert chimera_signature(a)==chimera_signature(b)
    assert val_p(a,5)==2 and val_p(b,5)==1
    results['unbounded_chimera_valuation_alias']={'a':a,'b':b,
        'signature':chimera_signature(a),'v5_a':val_p(a,5),'v5_b':val_p(b,5)}

    # An extra coprime anchor cannot turn a nonunit into a unit of the full base.
    assert gcd(2,6*5)==2
    results['extended_coprimality_counterexample']={'divisor':2,'M':6,'A':5,
        'gcd_divisor_extended':gcd(2,6*5)}
    # Same authentic dividend residues in base 6 and aux 5, exact divisibility,
    # but different quotient residue in the nonunit lane.
    assert (2%6,2%5)==(32%6,32%5)
    assert (2//2)%6 != (32//2)%6
    results['unbounded_FPD_alias']={'dividend_a':2,'dividend_b':32,
        'M':6,'A':5,'divisor':2,'same_observations':[2,2],
        'quotient_residues_mod6':[1,4]}

    # Historical same-base PhaseDiff cannot see tuple winding when b is a unit.
    # Distinct integers a and a+bM are both divisible by b and have same residues.
    M,b=6,5
    xs=[5,35]
    assert all(x%b==0 for x in xs)
    assert xs[0]%M==xs[1]%M
    assert [x//M for x in xs]==[0,5]
    results['same_base_winding_alias']={'M':M,'divisor':b,'dividends':xs,
        'same_primary_residue':5,'different_windings':[0,5],
        'same_quotient_residue':[x//b%M for x in xs]}

    # p-adic 1-Lipschitzness does not force unreachable residues or short cycles.
    moduli=[2,3,5,7,11]
    capacity=1
    for m in moduli: capacity*=m
    orbit={(t%capacity) for t in range(capacity)}
    assert len(orbit)==capacity
    results['translation_orbit_void_density']={'basis':moduli,'map':'x -> x+1',
        'degree':1,'min_prime':2,'reachable':len(orbit),'capacity':capacity,
        'void_density':'0'}
    print(json.dumps({'status':'PASS','results':results},indent=2))


if __name__=='__main__':
    main()
