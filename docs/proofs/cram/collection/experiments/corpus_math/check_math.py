"""Independent exact-integer models, not execution of the Rust implementation."""
from math import gcd, lcm, prod, isqrt
from itertools import combinations_with_replacement, product
from pathlib import Path
import json

checks={}

def count(name): checks[name]=checks.get(name,0)+1

def gradient(x,m,a):
    d=gcd(m,a); r=a//d
    return 0 if r==1 else ((x%a-x%m)//d*pow(m//d,-1,r))%r

for m in range(1,31):
    for a in range(1,31):
        for x in range(-2*lcm(m,a),2*lcm(m,a)+1):
            assert gradient(x,m,a)==(x//m)%(a//gcd(m,a))
            count('signed_resolution_gradient')

for m in range(1,31):
    for anchors in combinations_with_replacement(range(1,16),2):
        L=lcm(*anchors); R=L//gcd(m,L)
        assert R==lcm(*(a//gcd(m,a) for a in anchors))
        assert m*R==lcm(m,*anchors)
        observations={}
        for k in range(R):
            key=tuple((m*k)%a for a in anchors)
            assert key not in observations
            observations[key]=k
            count('coupled_injectivity')
        assert tuple((m*R)%a for a in anchors)==tuple(0 for _ in anchors)
        count('coupled_capacity_and_alias')

for m in range(2,101):
    for a in range(2,101):
        if gcd(m,a)==1:
            inv=pow(m,-1,a)
            assert (inv in {1,a-1})==((m-1)%a==0 or (m+1)%a==0)
            count('unit_anchor_characterization')

def fusion_model(x,b,basis,aux,B):
    if not b or prod(basis)%abs(b): return 'unsupported'
    good=[p for p in (*basis,*aux) if gcd(b,p)==1]
    P=prod(good)
    if P<=2*B:return 'capacity'
    q=sum(((x%p)*pow(b,-1,p)%p)*(P//p)*pow(P//p,-1,p) for p in good)%P
    if q>P//2:q-=P
    if any((b*q-x)%p for p in basis if gcd(b,p)>1):return 'inexact'
    if abs(q)>B:return 'bound'
    return q

# Exhaustive small analogue of the guarded squarefree S8 FPD theorem.
basis=(2,3,5); aux=(7,11); M=prod(basis)
for b in [d for d in range(-M,M+1) if d and M%abs(d)==0]:
    P=prod(p for p in (*basis,*aux) if gcd(b,p)==1)
    B=min(25,(P-1)//2)
    for x in range(-abs(b)*B,abs(b)*B+1):
        got=fusion_model(x,b,basis,aux,B)
        if x%b==0:assert got==x//b,(x,b,got)
        else:assert got=='inexact',(x,b,got)
        count('bounded_fpd_squarefree')

# Carries over the subgroup of kth powers: symmetry or odd-cardinality proof.
for p in range(3,251,2):
    if any(p%d==0 for d in range(2,isqrt(p)+1)):continue
    for k in range(1,21):
        I={pow(x,k,p) for x in range(1,p)}; J=set(range(1,p))-I
        separate= bool(J) and sum(2*x>=p for x in I)*len(J)!=sum(2*x>=p for x in J)*len(I)
        g=gcd(k,p-1)
        assert separate==(g>1 and ((p-1)//g)%2==1),(p,k)
        count('carry_subgroup_separation')

# Rooted-tree quotient observations give a reversible coordinate transform.
moduli=(3,5,7,11)
for parents in ((0,1,2),(0,0,0)):
    seen=set()
    for residues in product(*(range(m) for m in moduli)):
        labels=tuple((residues[j]-residues[i])*pow(moduli[i],-1,moduli[j])%moduli[j] for j,i in enumerate(parents,1))
        key=(residues[0],*labels)
        assert key not in seen; seen.add(key)
        recovered=[residues[0]]
        for j,i in enumerate(parents,1):
            recovered.append((recovered[i]+moduli[i]*labels[j-1])%moduli[j])
        assert tuple(recovered)==residues
        count('tree_coordinate_bijection')

counterexamples={
 'natural_subtraction_core':{'M':3,'A':5,'X':5,'true_quotient':1,'truncated_formula':0},
 'noncoprime_zero_resolution_table':{'M':4,'A':8,'gcd':4,'resolution':2},
 'adjacency_not_necessary':{'M':11,'A':4,'inverse':3,'formula':'k=(r_M-r_A) mod 4'},
 'tower_range_inference':{'moduli':[2,3,5],'X':6,'product':30,'first_pair_product':6},
 'finite_anchor_alias':{'M':6,'anchors':[4,9],'R_K':6,'R_X':36,'X_alias_pair':[0,36]},
 'gcd_error_not_absolute_bound':{'M':6,'A':9,'gcd':3,'same_residue_X_pair':[0,180],'K_pair':[0,30]},
 'nonexact_inverse':{'X':1,'b':2,'modulus':5,'modular_division':3,'floor_division':0},
 'unwitnessed_prime_power_fpd':{'basis':[2,3,5],'aux':[7],'X':2,'b':4,'P':105,'candidate_q':-52,'B':52,'bad_lane_mod2_check':True,'exact_division':False,'current_wrapper':'rejects because 4 does not divide 30'},
 'threshold_is_polynomial':{'p':3,'f':'2*x^2+x mod 3','values':[0,0,1]},
 'finite_inv_fixed_divisor':{'b':2,'all_odd_primes_allow_inverse':True},
}
result={'checks':checks,'total_checks':sum(checks.values()),'counterexamples':counterexamples,'scope':'Independent Python mathematical model; no Rust/Lean execution.'}
Path(__file__).with_name('results.json').write_text(json.dumps(result,indent=2))
print(json.dumps(result,indent=2))
