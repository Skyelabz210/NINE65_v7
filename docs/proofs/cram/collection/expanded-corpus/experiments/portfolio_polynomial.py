"""Independent exact finite-field checks for the polynomial K-Elimination lift.

All coefficients are low-degree first. This is an audit model, not a production
algorithm or a test of NINE65 Rust. It compares observer-based quotient recovery
against Euclidean polynomial division and records alias counterexamples.
"""
from itertools import product
from math import gcd, lcm
import json

def norm(a, p):
    a = [x % p for x in a]
    while a and a[-1] == 0:
        a.pop()
    return tuple(a)

def add(a, b, p):
    return norm([(a[i] if i < len(a) else 0) + (b[i] if i < len(b) else 0)
                 for i in range(max(len(a), len(b)))], p)

def neg(a, p):
    return norm([-x for x in a], p)

def sub(a, b, p):
    return add(a, neg(b, p), p)

def mul(a, b, p):
    if not a or not b:
        return ()
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            out[i+j] += x*y
    return norm(out, p)

def divrem(a, b, p):
    assert b
    q = [0] * max(0, len(a)-len(b)+1)
    r = a
    invlead = pow(b[-1], -1, p)
    while r and len(r) >= len(b):
        shift = len(r)-len(b)
        c = r[-1]*invlead % p
        q[shift] = c
        r = sub(r, (0,)*shift + tuple(c*x for x in b), p)
    return norm(q, p), r

def rem(a, b, p):
    return divrem(a, b, p)[1]

def inverse(a, modulus, p):
    r0, r1 = a, modulus
    s0, s1 = (1,), ()
    while r1:
        q, r = divrem(r0, r1, p)
        r0, r1 = r1, r
        s0, s1 = s1, sub(s0, mul(q, s1, p), p)
    if len(r0) != 1:
        return None
    return rem(mul(s0, (pow(r0[0], -1, p),), p), modulus, p)

def monics(p):
    return [coeffs+(1,) for d in (1, 2) for coeffs in product(range(p), repeat=d)]

def run():
    counts = {'coprime_anchor_pairs': 0, 'bounded_quotient_recoveries': 0,
              'arbitrary_target_projections': 0, 'out_of_window_aliases': 0,
              'noncoprime_anchor_rejections': 0}
    for p in (2, 3, 5):
        moduli = monics(p)
        for m in moduli:
            for a in moduli:
                inv = inverse(m, a, p)
                if inv is None:
                    counts['noncoprime_anchor_rejections'] += 1
                    continue
                counts['coprime_anchor_pairs'] += 1
                assert rem(mul(m, inv, p), a, p) == (1,)
                ma = mul(m, a, p)
                for coeffs in product(range(p), repeat=len(m)+len(a)-2):
                    x = norm(coeffs, p)
                    q, r = divrem(x, m, p)
                    s = rem(x, a, p)
                    recovered = rem(mul(sub(s, r, p), inv, p), a, p)
                    assert recovered == q, (p,m,a,x,q,recovered)
                    counts['bounded_quotient_recoveries'] += 1
                    # b shares factors with m, so this also checks the
                    # distinction between extraction and arbitrary projection.
                    b = mul(m, (0, 1), p)
                    projected = rem(add(rem(r,b,p), mul(rem(q,b,p),rem(m,b,p),p),p),b,p)
                    assert projected == rem(x,b,p)
                    counts['arbitrary_target_projections'] += 1
                    # The same authentic views also encode x+ma; its full
                    # quotient is q+a, proving why a degree window is needed.
                    y = add(x, ma, p)
                    qy, ry = divrem(y, m, p)
                    assert ry == r and rem(y,a,p) == s
                    assert qy == add(q,a,p) and qy != q
                    counts['out_of_window_aliases'] += 1

    # A quotient-ring element has no representative-independent degree.
    # In F_2[t]/(t^2+1), 1 and 1+(t^2+1)=t^2 are the same element,
    # while floor(degree / 2) gives respectively 0 and 1.
    f, x0, x1 = (1,0,1), (1,), (0,0,1)
    assert rem(x0,f,2) == rem(x1,f,2)
    assert (len(x0)-1)//2 == 0 and (len(x1)-1)//2 == 1

    # Historical Ultimate §4.3 scalar-floor reading is incorrect even when
    # the integer dividend is divisible by the divisor. Its proposed correction
    # k_i*(M mod m_i) cannot change any lane.
    x, d, lanes, anchor = 8, 2, (7,11), 13
    M=77
    qa=(x % anchor)*pow(d % anchor,-1,anchor) % anchor
    original=[(x%m)//(d%m) for m in lanes]
    corrected=[]
    for m, qi in zip(lanes,original):
        ki=(qa-qi)*pow(M,-1,anchor) % anchor
        corrected.append((qi+ki*(M%m))%m)
    expected=[(x//d)%m for m in lanes]
    assert corrected==original==[0,4] and expected==[4,4]

    # 'Fermat inverse works only for prime m' is too strong: 561 is
    # composite Carmichael, and the inverse expression works for every unit.
    fermat_units=[a for a in range(1,561) if gcd(a,561)==1]
    assert all(pow(a,559,561)==pow(a,-1,561) for a in fermat_units)
    # Elementary errors in the secondary review are not primary certificates.
    assert sum(gcd(a,210)==1 for a in range(210))==48

    phase_pairs=phase_observations=0
    for m in range(1,25):
        for a in range(1,25):
            g=gcd(m,a)
            L=lcm(m,a)
            c=(m-a)//g
            period=L//gcd(c,g)
            seen=set()
            for z in range(L):
                # Exact numerator over denominator L; no trigonometry or floats.
                observed=((m//g)*(z%a)-(a//g)*(z%m))%L
                assert observed==(c*z)%L
                seen.add(observed)
                phase_observations+=1
            assert len(seen)==period
            phase_pairs+=1

    return {'model':'Independent finite-field polynomial audit', 'fields':[2,3,5],
            'monic_anchor_degrees':[1,2], 'counts':counts,
            'relative_phase_checks':{'modulus_pairs':phase_pairs,'observations':phase_observations},
            'negative_controls': {
                'quotient_ring_degree_alias':{'p':2,'f':f,'x0':x0,'x1':x1,'degree_quotients':[0,1]},
                'historical_lane_division':{'x':x,'d':d,'lanes':lanes,'anchor':anchor,'observed':corrected,'expected':expected},
                'open_path_angular_integral':{'x':1,'M':2,'integral_over_2pi':'1/2','floor_quotient':0},
                'noncoprime_relative_phase_alias':{'M':6,'A':10,'values':[0,15], 'pair_period':30,'relative_phase_period':15},
                'carmichael_561_unit_inverses':len(fermat_units)
            }, 'status':'PASS'}

if __name__=='__main__':
    print(json.dumps(run(),indent=2))
