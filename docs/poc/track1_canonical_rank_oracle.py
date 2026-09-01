# Reference oracle for Track 1 main-only canonical-rank base extension.
# Validates the contract formula against ground truth. Big ints allowed HERE
# (reference only); the Rust production path must avoid materializing X.
from fractions import Fraction
from math import gcd, prod
import random
random.seed(7)

def crt_residues(X, mods): return [X % m for m in mods]

def canonical_rank_and_project(x, mains, auxs):
    """x: residues mod mains. Returns (rho, [X mod a_j]) WITHOUT building X."""
    M = prod(mains)
    Mi = [M // m for m in mains]
    # c_i = x_i * (Mi^-1 mod m_i) mod m_i     (Garner coefficient in [0, m_i))
    c = [(x[i] * pow(Mi[i] % mains[i], -1, mains[i])) % mains[i] for i in range(len(mains))]
    # rho = floor( sum_i c_i / m_i )  -- exact via rationals (oracle)
    rho = int(sum(Fraction(c[i], mains[i]) for i in range(len(mains))))
    out = []
    for a in auxs:
        v = (sum(c[i] * (Mi[i] % a) for i in range(len(mains))) - rho * (M % a)) % a
        out.append(v)
    return rho, c, out

def brute_rho(X, mains):
    M = prod(mains); Mi=[M//m for m in mains]
    c=[(crt_residues(X,mains)[i]*pow(Mi[i]%mains[i],-1,mains[i]))%mains[i] for i in range(len(mains))]
    return sum(c[i]*Mi[i] for i in range(len(mains)))//M

# ---- Test 1: exhaustive small coprime bases ----
def exhaustive(mains, auxs):
    M=prod(mains); bad=0; rho_seen=set()
    for X in range(M):
        x=crt_residues(X,mains)
        rho,c,proj=canonical_rank_and_project(x,mains,auxs)
        rho_seen.add(rho)
        # ground truth
        if rho!=brute_rho(X,mains): bad+=1
        for j,a in enumerate(auxs):
            if proj[j]!=X%a: bad+=1
    return bad, sorted(rho_seen), M

for mains,auxs in [([3,5,7],[2013265921,11]), ([5,7,11,13],[2281701377,8]),
                   ([3,5,7,11],[2013265921,2281701377])]:
    bad,rho_seen,M=exhaustive(mains,auxs)
    assert 0 in rho_seen
    print(f"mains={mains} M={M}  aux={auxs}: mismatches={bad}  rho range={rho_seen} (max<lanes={len(mains)})")

# ---- Test 2: production main-prime prefix (random, large) ----
MAIN=[1073750017,1073753089,1073950721,1073958913]   # ~4x30-bit
AUX=[2013265921,2281701377,2483027969,2885681153,3221225473,3221422081,3222306817]
M=prod(MAIN); bad=0; rhos=set()
for _ in range(20000):
    X=random.randrange(M)
    x=crt_residues(X,MAIN)
    rho,c,proj=canonical_rank_and_project(x,MAIN,AUX)
    rhos.add(rho)
    for j,a in enumerate(AUX):
        if proj[j]!=X%a: bad+=1
    if rho!=brute_rho(X,MAIN): bad+=1
print(f"production prefix 4x30-bit, 20000 rand: mismatches={bad}  rho values seen={sorted(rhos)} (0..{len(MAIN)-1})")

# ---- Test 3: edge values 0,1,M/2 neighbors, M-2, M-1 ----
edges=[0,1,M//2-1,M//2,M//2+1,M-2,M-1]
bad=0
for X in edges:
    x=crt_residues(X,MAIN); rho,c,proj=canonical_rank_and_project(x,MAIN,AUX)
    for j,a in enumerate(AUX):
        if proj[j]!=X%a: bad+=1
print(f"edge values {len(edges)}: mismatches={bad}")

# ---- Test 4: permutation invariance of rho+projection ----
X=random.randrange(M); perm=[2,0,3,1]
mp=[MAIN[i] for i in perm]; xp=[X%m for m in mp]
r0,_,p0=canonical_rank_and_project([X%m for m in MAIN],MAIN,AUX)
r1,_,p1=canonical_rank_and_project(xp,mp,AUX)
print(f"permutation invariance: rho {r0}=={r1} -> {r0==r1}, projection equal -> {p0==p1}")
print("\nORACLE VALID: contract formula rho=floor(sum c_i/m_i), "
      "X mod a=(sum c_i*(Mi mod a) - rho*(M mod a)) mod a  reproduces ground truth exactly.")
