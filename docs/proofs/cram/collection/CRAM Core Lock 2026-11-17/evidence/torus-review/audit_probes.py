from fractions import Fraction
from itertools import combinations
from math import gcd, prod
import json

def case(mods):
    M=prod(mods); Mi=[M//m for m in mods]; inv=[pow(v,-1,m) for v,m in zip(Mi,mods)]
    xi=[m-1 for m in mods]; rs=[v*w%m for v,w,m in zip(xi,Mi,mods)]
    S=sum(v*w for v,w in zip(xi,Mi)); x=S%M; alpha=S//M
    return {'moduli':mods,'M':M,'xi':xi,'residues':rs,'S':S,'x':x,'alpha':alpha}

small=case([2,3,5,7]); assert small['alpha']==2
short=case([9,25,49,121]); assert short['alpha']==3
for q in (2,169):
    short['alpha_readout_mod_'+str(q)]=((short['S']-short['x']) * pow(short['M'],-1,q))%q
assert short['alpha_readout_mod_2']==1 and short['alpha_readout_mod_169']==3
base_count=states=readouts=shifted=0
for k in range(1,5):
    for mods in combinations(range(2,11),k):
        if any(gcd(a,b)>1 for a,b in combinations(mods,2)): continue
        base_count+=1; M=prod(mods); Mis=[M//m for m in mods]; invs=[pow(mi,-1,m) for mi,m in zip(Mis,mods)]
        amax=sum((Fraction(m-1,m) for m in mods),Fraction())//1
        seen=set()
        for x in range(M):
            xis=[((x%m)*i)%m for m,i in zip(mods,invs)]; S=sum(xi*mi for xi,mi in zip(xis,Mis)); alpha=S//M
            assert S==x+alpha*M and 0<=alpha<=amax
            states+=1; seen.add(alpha)
            for q in range(2,18):
                if gcd(M,q)>1: continue
                ai=((S-x)*pow(M,-1,q))%q
                assert ai==alpha%q
                if q>amax: assert ai==alpha
                readouts+=1
                for K in (-2,0,3):
                    shifted_ai=((S-(x+K*M))*pow(M,-1,q))%q
                    assert shifted_ai==(alpha-K)%q
                    shifted+=1
        assert seen==set(range(amax+1))

# Independent finite minimization around its vertex verifies the piecewise tropical formula.
tropical=0
for Q in range(1,41):
    for z in range(-600,601):
        K,g=divmod(z,Q); ns=list(range(-K-3,-K+3)); vals={n:Q*n*n+2*n*z for n in ns}; v=min(vals.values())
        actual=sorted(n for n in ns if vals[n]==v)
        expected=[-K] if 2*g<Q else ([-K-1,-K] if 2*g==Q else [-K-1])
        assert actual==expected
        b=int(2*g>=Q); assert v==-Q*K*K-2*K*g+b*(Q-2*g)
        tropical+=1
out={'small_valid_base_counterexample':small,'undersized_readout_anchor_counterexample':short,'independent_exhaustive':{'bases':base_count,'canonical_states':states,'readouts':readouts,'shifted_readouts':shifted,'tropical_cases':tropical},'failures':0}
print(json.dumps(out,indent=2))
