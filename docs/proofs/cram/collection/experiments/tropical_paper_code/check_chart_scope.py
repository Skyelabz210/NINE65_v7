#!/usr/bin/env python3
"""Exact scope checks for the supplied Oct 25 tropical report; no FHE execution."""
from fractions import Fraction
from math import factorial
import json

q, modulus, half = 13, 289, 6
inv_fact = pow(factorial(q), -1, modulus)
assert inv_fact == 40

def g(z):
    product = 1
    for r in range(-half, half + 1):
        product = product * (z-r) % modulus
    return product

single = double = 0
for chart in range(-half, half + 1):
    for u in (-1,0,1):
        z = chart+u
        assert g(z)*inv_fact % modulus == ((z+half)//q) % modulus
        single += 1
        for v in (-1,0,1):
            z = chart+u+v
            assert g(z)*(65-30*z*z) % modulus == ((z+half)//q) % modulus
            double += 1
assert (-9)%17 == 8%17
assert ((-9+half)//q)%17 != ((8+half)//q)%17

def theta_min(z):
    values = [(q*n*n+2*n*z,n) for n in range(-3,4)]
    smallest = min(t for t,n in values)
    return smallest,[n for t,n in values if t==smallest]

# The integer chart endpoint is a launch point for a wall-crossing step,
# whereas the actual continuous theta wall is at q/2.
assert theta_min(Fraction(6)) == (0,[0])
assert theta_min(Fraction(13,2)) == (0,[-1,0])
assert theta_min(Fraction(7)) == (-1,[-1])

def schedule(depths):
    depths=list(depths); products=0
    while len(depths)>1:
        depths.sort()
        a,b,*rest=depths
        depths=[*rest,max(a,b)+1]
        products+=1
    return {'multiplications':products,'depth':depths[0]}

one=schedule([0]*q)
two=schedule([0]*q+[1])
two['multiplications']+=1 # z*z for the quadratic
assert one == {'multiplications':12,'depth':4}
assert two == {'multiplications':14,'depth':4}

print(json.dumps({
    'scope':'finite exact arithmetic and source circuit schedule; no fresh encrypted run',
    'single_increment_cases':single,
    'two_increment_cases':double,
    'continuous_theta_wall':'13/2, not integer launch endpoint 6',
    'third_increment_polynomial_obstruction':{'inputs':[-9,8],'same_mod17':8,'desired_carries':[-1,1]},
    'one_increment_ciphertext_product_schedule':one,
    'batched_two_increment_ciphertext_product_schedule':two,
    'two_sequential_product_schedule':{'multiplications':24,'depth':8},
    'cost_exclusions':['coefficient/slot transforms','scalar products','key setup','noise and decryption analysis'],
},indent=2))
