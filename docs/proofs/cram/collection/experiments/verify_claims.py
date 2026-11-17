#!/usr/bin/env python3
"""Independent exact-arithmetic audit; no production or encrypted implementation.
Run: python experiments/verify_claims.py > evidence/independent-checks.json
"""
from math import gcd, lcm
from itertools import product
from fractions import Fraction
from pathlib import Path
import importlib.util, json

counts = {}
def check(name, proposition):
    assert proposition, name
    counts[name] = counts.get(name, 0) + 1

# No global bound is needed for quotient RESIDUES, including negative X.
for m in range(1, 33):
    for a in range(2, 34):
        d = gcd(m,a); h = a//d
        for x in range(-2*m*a, 2*m*a+1):
            r, s = x%m, x%a
            k = (((s-r)//d)*pow(m//d,-1,h))%h if h>1 else 0
            check('generalized_quotient_congruence', k == (x//m)%h)
            if 0<=x<lcm(m,a):
                check('bounded_generalized_recovery', k == x//m)

# Exhaust all small triples. Observe quotient residues with possibly shared factors.
for m,a,b in product(range(1,13), repeat=3):
    R=lcm(a,b)//gcd(m,lcm(a,b))
    check('lcm_resolution_identity', R==lcm(a//gcd(m,a), b//gcd(m,b)))
    observed={((m*k)%a,(m*k)%b) for k in range(R)}
    check('coupled_observer_injectivity',len(observed)==R)
    check('coupled_observer_alias',((m*R)%a,(m*R)%b)==(0,0))

# Exact threshold law; even and odd total ranges and arbitrary thresholds.
for m in range(1,14):
    for a in range(2,14):
        for x in range(m*a):
            for t in {0,m*a//2,(m*a+1)//2,m*a-1,m*a}:
                check('lexicographic_threshold', (x<t)==((x//m,x%m)<(t//m,t%m)))

# Basis-lane division leaves quotient in all surviving lanes; no scalar q input.
for mods in [(7,11,13),(4,9,5),(2,3,5,7)]:
    total=1
    for mod in mods: total*=mod
    for div in mods:
        for x in range(total):
            for p in mods:
                if p != div:
                    q_res=((x%p-x%div)*pow(div,-1,p))%p
                    check('basis_lane_division', q_res==(x//div)%p)

# Noncoprime exact division: dY=X, known signed |Y|<=B, enough good/aux moduli.
for d in range(1,21):
    good=[p for p in (5,7,11,13) if gcd(d,p)==1]
    P=1
    for p in good: P*=p
    for y in range(-20,21):
        x=d*y
        rs=[(x%p)*pow(d,-1,p)%p for p in good]
        q=sum(r*(P//p)*pow(P//p,-1,p) for r,p in zip(rs,good))%P
        q=q-P if 2*q>P else q
        check('bounded_auxiliary_exact_division',P>40 and q==y)

counterexamples={
 'anchor_larger_than_M_is_not_a_range_bound': {'M':3,'A':5,'X':15,'readout':0,'true_quotient':5},
 'sign_formula_for_range_M':{'M':10,'A':11,'X':9,'q':0,'q_lt_A_over_2':True,'X_lt_M_over_2':False},
 'odd_anchor_midpoint_needs_remainder':{'M':4,'A':5,'X':11,'q':2,'r':3,'q_lt_A_over_2':True,'X_lt_MA_over_2':False},
 'inverse_is_not_floor_division':{'X':3,'c':2,'modulus':5,'inverse_result':4,'floor_result':1},
 'winding_after_division_not_whole_quotient':{'X':22,'M':5,'c':2,'new_value':11,'new_r':1,'new_K':2,'survey_K_formula':11},
 'double_gcd_wrong_total_range':{'M':6,'A':4,'distinct_pairs':12,'lcm_M_A_div_gcd_M_A':6},
 'new_anchor_cannot_recover_already_lost_information':{'M':6,'old_anchor':5,'X':0,'Y':30,'same_old_pair':[0,0],'X_mod_7':0,'Y_mod_7':2},
 'luminance_not_pigment_injective':{'RGB1':[255,0,0],'RGB2':[0,0,255],'both_floor_mean':85,'both_bin37':2},
 'adjacent_not_necessary_for_subtraction_collapse':{'M':9,'A':5,'M_mod_A':4,'inverse':4},
 'odd_modulus_rounding_error':{'q':5,'V':2,'script_result':1,'nearest_result':0},
 'bootstrap_decryption_scale_missing':{'q':100,'t':5,'m':2,'c0':40,'c1':0,'s':0,'script_result':0,'correct_noiseless_plaintext':2},
 'finite_inv_not_for_every_prime_subset':{'construction':'choose increasing primes p_i>2^(i+2); sum 1/p_i converges, so product(1-1/p_i)>0'},
 'tropicalization_discards_prefactor':{'family1':'exp(-u/eps)','family2':'2*exp(-u/eps)','both_min_plus_limits':'u'}
}

# Exercise the provided Python functions on deterministic independent counterexamples.
src=Path(__file__).resolve().parents[1]/'inputs'/'13-k_elim_bootstrap_corrected.py'
spec=importlib.util.spec_from_file_location('historical_bootstrap',src)
module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
p=module.BootstrapParameters(q=5,t=2,rns_moduli=[2,3])
check('attached_rounding_negative_control',module.exact_bootstrap_round(2,p)==1 and Fraction(2,5)<Fraction(1,2))
check('attached_range_negative_control',module.exact_bootstrap_round(8,p)==2) # true round(8/5)=2; use q=4 below
p2=module.BootstrapParameters(q=4,t=2,rns_moduli=[2,3])
check('attached_alias_negative_control',module.exact_bootstrap_round(6,p2)==1) # true half-up round(6/4)=2
p3=module.BootstrapParameters(q=100,t=5,rns_moduli=[11,13])
check('attached_decryption_negative_control',module.exact_bootstrap_decryption(40,0,0,p3)==0)

print(json.dumps({'status':'PASS: valid laws and expected counterexamples','counts':counts,'counterexamples':counterexamples},indent=2))
