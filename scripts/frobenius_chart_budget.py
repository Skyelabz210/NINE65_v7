#!/usr/bin/env python3
"""Exact ring-section identities and public error plan for the 11 anchor.

Phi(x)=sigma_(11^-1)(x^11) in Z/121[X]/(X^N+1).  It is a section of
reduction mod11 and ignores additions of11H. It does not canonically lift
each coefficient to0..10 and does not recover the target integer K.
"""

import json
from math import prod

from compact_phase_clock_budget import shape
from outer_ring_return_budget import OUTER

BASE=11
T=121
NODES=((2,1,1),(3,1,2),(5,2,3),(6,3,3),(11,5,6))


def product(a,b,t=T):
    n=len(a)
    if len(b)!=n:
        raise ValueError("matching ring degree required")
    result=[0]*n
    for i,x in enumerate(a):
        for j,y in enumerate(b):
            result[(i+j)%n]=(result[(i+j)%n]+(1 if i+j<n else -1)*x*y)%t
    return result


def section(a):
    n=len(a)
    inverse=pow(BASE,-1,2*n)
    powers={1:a}
    for e,x,y in NODES:
        powers[e]=product(powers[x],powers[y])
    result=[0]*n
    for i,value in enumerate(powers[11]):
        target=i*inverse%(2*n)
        result[target%n]=(value if target<n else -value)%T
    return result


def plan(n=16384,input_v=None,primes=OUTER[:-1]):
    q=prod(primes)
    digits,digit_sum=shape(primes,10)
    switch=T*n*3*1023*digits
    galois=T*n*3*digit_sum
    fresh=T*(2*n+1)*3+(q%T)*(T-1)
    # Native worst-case component D weights use <=10. The actual producer
    # charges its public l1 norm, not this conservative common envelope.
    if input_v is None:
        full_q=prod(OUTER)
        full_fresh=T*(2*n+1)*3+(full_q%T)*(T-1)
        full_v=full_fresh*8192*10+(full_q%T)*10
        if tuple(primes)==OUTER[:-1]:
            special=OUTER[-1]
            input_v=(full_v+special-1)//special+(T*(n+1)+1)//2
        else:
            input_v=fresh*8192*10+(q%T)*10
    factor=n*((T-1)//2)+T*n*(n//2+1)
    rounding=(T*(1+n+n*n)+1)//2
    bounds={1:input_v}
    levels=[]
    for exponent,left,right in NODES:
        a,b=bounds[left],bounds[right]
        if 2*max(a,b)>=q:
            return {"admitted":False,"refused_exponent":exponent,"nodes":levels}
        v=factor*(a+b)+(n//2)*max(a,b)+rounding+switch
        levels.append({"power":exponent,"V":v,"V_bits":v.bit_length(),"decodes_under_bound":2*v<q})
        if 2*v>=q:
            return {"admitted":False,"refused_exponent":exponent,"nodes":levels}
        bounds[exponent]=v
    final=bounds[11]+galois
    return {"admitted":2*final<q,"ring_N":n,"ciphertext_Q_bits":q.bit_length(),
            "plaintext":T,"input_V":input_v,"input_V_bits":input_v.bit_length(),
            "nodes":levels,"section_V":final,"section_V_bits":final.bit_length(),
            "quotient_V":(input_v+final+10)//11,
            "quotient_V_bits":((input_v+final+10)//11).bit_length(),
            "multiplication_depth":4,"exact_ciphertext_products":5,"raw_galois_switches":1,
            "coefficient_slot_transform":False,"canonical_integer_lift":False,"production_admitted":False}


def report():
    p=plan()
    assert p["admitted"]
    repeat=plan(input_v=p["section_V"])
    assert not repeat["admitted"]
    example=[1,1]+[0]*6
    value=section(example)
    return {"scope":"11-adic RING section, not coefficientwise canonical digit lift or public bootstrap",
            "native_public_budget":p,"dependent_repeat_budget":repeat,
            "full_Q241_exact_plan":"refused by existing U256 rank fallback; nine auxiliary lanes need287bits",
            "evaluation_level":"public same-key drop from Q241 to Q211 before nonlinear work",
            "persistent_ciphertext_modulus_changed":False,
            "example":{"input":example,"section":value,"canonical_coefficient_section":example,
                       "witt_quotient":[((x-y)%121)//11 for x,y in zip(example,value)]},
            "linear_chart_identity":{
                "Z99":"11*U+5*D","Phi_Z99":"5^11*Phi_D mod121",
                "W_Z99":"U+5*W_D+((5-5^11)/11)*D mod11",
                "native_encrypted_identity_verified_by_this_script":False},
            "ciphertext_error_reduced_by_section":False,
            "integer_K_extracted":False,"full_public_bootstrap_admitted":False}


if __name__=="__main__":
    print(json.dumps(report(),indent=2))
