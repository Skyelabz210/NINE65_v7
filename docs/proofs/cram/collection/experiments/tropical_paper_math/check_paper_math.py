#!/usr/bin/env python3
"""Exact finite checks for the newly supplied Oct 25 tropical report.

Independent mathematical oracle. Not the missing holte.rs/trop.rs, not FHE,
not a proof of the universal statements. Uses Python integers and Fractions.
"""
from collections import Counter
from fractions import Fraction
from itertools import product
from math import comb, factorial
from pathlib import Path
import json


counts = Counter()


def require(name, value):
    if not value:
        raise AssertionError(name)
    counts[name] += 1


def choose(n, k):
    return comb(n, k) if n >= k else 0


def cdf(s, n, base):
    return sum((-1)**j * comb(n, j) * choose(s-j*base+n, n) for j in range(n+1))


def matrix(n, base):
    return [[cdf((j+1)*base-1-i,n,base)-cdf(j*base-1-i,n,base)
             for j in range(n)] for i in range(n)]


def eulerian(n):
    row=[1]
    for size in range(2,n+1):
        row=[(j+1)*(row[j] if j<len(row) else 0)+(size-j)*(row[j-1] if j>0 else 0)
             for j in range(size)]
    return row


for n in range(1,9):
    for base in range(2,25):
        T=matrix(n,base); a=eulerian(n)
        require('holte_stationary_cases',all(sum(a[i]*T[i][j] for i in range(n))==a[j]*base**n for j in range(n)))
        require('holte_reversibility_cases',all(a[i]*T[i][j]==a[j]*T[j][i] for i in range(n) for j in range(n))==(n<=3))
for n in range(1,6):
    for base in range(2,5):
        T=matrix(n,base)
        actual=[[0]*n for _ in range(n)]
        for digits in product(range(base),repeat=n):
            for incoming in range(n):
                actual[incoming][(sum(digits)+incoming)//base]+=1
        require('holte_brute_matrix_cases',actual==T)

for p in range(2,2001):
    for v in range(p):
        require('carry_hinge_states',min(1,max(0,2*v-p+1))==(2*v)//p)

# v(0)=infinity represented by None, never a floating-point value.
def vp(x,p):
    if x==0: return None
    e=0
    while x%p==0:
        e+=1; x//=p
    return e

def vmin(a,b):
    if a is None: return b
    if b is None: return a
    return min(a,b)

for p in (2,3,5,7,11,13):
    for x,y in product(range(-64,65),repeat=2):
        a,b=vp(x,p),vp(y,p); c=vp(x+y,p)
        require('valuation_product_cases',vp(x*y,p)==(a+b if a is not None and b is not None else None))
        low=vmin(a,b)
        require('valuation_sum_cases',c is None or (low is not None and c>=low))
        if a!=b:
            require('valuation_distinct_cases',c==low)

# Integer interpolation as P_+ - P_- with convex integer-slope pieces.
def dc_eval(values,x):
    slopes=[b-a for a,b in zip(values,values[1:])]
    changes=[b-a for a,b in zip(slopes,slopes[1:])]
    positive=values[0]+max(slopes[0],0)*x
    negative=max(-slopes[0],0)*x
    for j,d in enumerate(changes,1):
        positive+=max(d,0)*max(0,x-j)
        negative+=max(-d,0)*max(0,x-j)
    return positive-negative

def runs(values):
    slopes=[b-a for a,b in zip(values,values[1:])]
    return 1+sum(a!=b for a,b in zip(slopes,slopes[1:]))

piece_counts={}
for p in (11,13,17,19,31,61,127,257):
    maps={'add1':[(i+1)%p for i in range(p)],
          'add3':[(i+3)%p for i in range(p)],
          'times3':[(3*i)%p for i in range(p)],
          'times_floor_half':[((p//2)*i)%p for i in range(p)],
          'square':[(i*i)%p for i in range(p)],
          'inverse_zero_extended':[0]+[pow(i,-1,p) for i in range(1,p)],
          'arbitrary_integer_values':[(-1)**i*(i*i+3*i+1) for i in range(p)]}
    for name,values in maps.items():
        for i,expected in enumerate(values):
            require('finite_lane_dc_interpolation',dc_eval(values,Fraction(i))==expected)
    piece_counts[p]={name:runs(values) for name,values in maps.items() if name!='arbitrary_integer_values'}
    require('finite_lane_run_profile',piece_counts[p]=={'add1':2,'add3':3,'times3':5,'times_floor_half':p-2,'square':p-1,'inverse_zero_extended':p-1})

# Uniform scalar fibers; no assertion about an RLWE joint distribution.
for Q in range(2,81):
    for t in range(1,Q+1):
        buckets=[[] for _ in range(t)]
        for c in range(Q): buckets[t*c//Q].append(c)
        expected=[((y+1)*Q+t-1)//t-(y*Q+t-1)//t for y in range(t)]
        require('quantizer_fiber_cases',[len(v) for v in buckets]==expected)
        require('quantizer_uniform_iff_divisible',len(set(expected))==1 if Q%t==0 else len(set(expected))==2)
        for bucket in buckets:
            require('quantizer_contiguous_fibers',bucket==list(range(bucket[0],bucket[-1]+1)))

# Binary infinite-carrier BBS on a finite occupied word with enough empty tail.
for length in range(1,11):
    for word in product((0,1),repeat=length):
        carrier=0; out=[]
        for u in (*word,*([0]*sum(word))):
            nxt=min(1-u,carrier)
            branch=0 if u==1 else (1 if carrier>0 else 0)
            require('bbs_local_recurrence_states',nxt==branch)
            carrier=carrier+u-nxt; out.append(nxt)
        require('bbs_flushed_words',carrier==0 and sum(out)==sum(word))

result={'status':'pass','scope':'exact finite clear-arithmetic models; original Rust programs not supplied',
        'counts':dict(counts),'piece_counts':piece_counts,
        'counterexamples':{
          'valuation_not_additive_min':{'p':3,'x':1,'y':2,'valuations':[0,0,1]},
          'mod_p_loses_valuation':{'p':3,'x':3,'y':9,'same_mod_p':0,'valuations':[1,2]},
          'mod_p_power_loses_higher_valuation':{'p':3,'precision':2,'x':9,'y':27,'same_mod_9':0,'valuations':[2,3]},
          'addition_run_count_needs_shift':{'p':11,'b':3,'values':[(i+3)%11 for i in range(11)],'runs':3},
          'unequal_quantizer_fibers':{'Q':5,'t':2,'sizes':[3,2],'H_C_given_Y':'(3*log2(3)+2*log2(2))/5'},
          'same_arities_do_not_imply_iid_carries':{'n':2,'M':36,'stationary_prob_0':'1/2','P_00':'37/72'},
          'wall_not_last_integral_chart_point':{'Q':5,'last_integral_chart_point':2,'analytic_wall':'5/2'}
        }}
Path(__file__).with_name('paper-math-checks.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
