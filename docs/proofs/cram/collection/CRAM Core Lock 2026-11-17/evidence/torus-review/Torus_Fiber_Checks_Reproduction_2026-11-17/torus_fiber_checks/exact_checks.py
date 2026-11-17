#!/usr/bin/env python3
"""Exact (integer/rational) checks of claims in 'The Torus-Fiber Grammar of Exact Observability'. No floats."""
from fractions import Fraction
from itertools import combinations
from math import gcd
import networkx as nx

print("=== C1. Tropical theta: is argmin_n (Q n^2 + 2 n z) = -K for z = g + Q K ?  (section 3.3)")
tot = ok_floor = tie = bad = Tok = Ttot = 0
for Q in range(1, 41):
    for z in range(-600, 601):
        vals = {n: Q*n*n + 2*n*z for n in range(-700, 701)}
        m = min(vals.values()); arg = sorted(n for n, v in vals.items() if v == m)
        K, g = z // Q, z % Q                     # convention g in [0, Q)
        tot += 1
        if arg == [-K]: ok_floor += 1
        elif len(arg) == 2 and -K in arg: tie += 1
        else: bad += 1
        # the paper's value formula T = -2Kg - Q K^2 (valid iff n=-K attains the min)
        Ttot += 1; Tok += (m == -2*K*g - Q*K*K)
print(f"cases={tot}: argmin == -K uniquely: {ok_floor}; tie containing -K: {tie}; argmin is -K-1 (claim false): {bad}")
print(f"value formula T=-2Kg-QK^2 correct in {Tok} of {Ttot} cases")
# the exact condition: claim holds iff 2g < Q (tie iff 2g == Q)
viol = 0
for Q in range(1, 41):
    for z in range(-300, 301):
        vals = {n: Q*n*n + 2*n*z for n in range(-400, 401)}; m = min(vals.values())
        arg = sorted(n for n, v in vals.items() if v == m); K, g = z // Q, z % Q
        pred = [-K] if 2*g < Q else ([-K-1, -K] if 2*g == Q else [-K-1])
        viol += (arg != pred)
print(f"closed form (argmin=-K if 2g<Q; tie if 2g=Q; -K-1 if 2g>Q) violated in {viol} cases")

print("\n=== C2. Ramanujan: 'p(385m + 894) = 0 mod 385' (section 6.2)")
N = 40000; P = [0]*(N+1); P[0] = 1
pent = []
k = 1
while True:
    a = k*(3*k-1)//2
    if a > N: break
    pent.append((a, 1 if k % 2 else -1)); b = k*(3*k+1)//2
    if b <= N: pent.append((b, 1 if k % 2 else -1))
    k += 1
for n in range(1, N+1):
    s = 0
    for a, sg in pent:
        if a > n: break
        s += sg*P[n-a]
    P[n] = s % 385
# validate recurrence against exact big ints for small n (known: p(100)=190569292)
E = [1]
for n in range(1, 301):
    s = 0
    for a, sg in pent:
        if a > n: break
        s += sg*E[n-a]
    E.append(s)
assert E[100] == 190569292 and all(E[n] % 385 == P[n] for n in range(301)), "recurrence validation failed"
def frac(beta, mod):
    xs = [P[385*m+beta] for m in range(0, (N-beta)//385 + 1) if 385*m+beta <= N]
    return len(xs), sum(1 for v in xs if v % mod == 0)
for beta in (369, 894):
    n, _ = frac(beta, 385)
    row = []
    for mod in (5, 7, 11, 385):
        _, z = frac(beta, mod); row.append(f"mod {mod}: {z}/{n}")
    print(f"beta={beta} (beta mod 5,7,11 = {beta%5},{beta%7},{beta%11}):", "; ".join(row))
print("24^-1 mod 385 =", pow(24, -1, 385), "(the correct offset is the inverse of 24 mod 385)")

print("\n=== C3. F6: how special is 'irreducible remainder 23' for 11960 w.r.t. {2,3,5,7,13,37,73}?")
def fac(n):
    f = {}; d = 2
    while d*d <= n:
        while n % d == 0: f[d] = f.get(d, 0)+1; n //= d
        d += 1
    if n > 1: f[n] = f.get(n, 0)+1
    return f
print("11960 =", fac(11960), "; 11960 mod 378 =", 11960 % 378, "=", fac(11960 % 378))
S0 = (2, 3, 5, 7, 13, 37, 73)
def rem(n, S):
    for p in S:
        while n % p == 0: n //= p
    return n
primes = [p for p in range(2, 80) if all(p % d for d in range(2, p))]
cnt_total = cnt_23 = cnt_1 = 0
for S in combinations(primes, 7):
    r = rem(11960, S); cnt_total += 1; cnt_23 += (r == 23); cnt_1 += (r == 1)
print(f"all {cnt_total} 7-subsets of the {len(primes)} primes <80: remainder exactly 23 in {cnt_23}; remainder 1 in {cnt_1}")
print("remainder for alt sets: first-7-primes", rem(11960, (2,3,5,7,11,13,17)), "; S0 plus 23 ->", rem(11960, S0+(23,)))
lo, hi = 10000, 14000
isprime = lambda n: n > 1 and len(fac(n)) == 1 and list(fac(n).values())[0] == 1
rs = [rem(n, S0) for n in range(lo, hi+1)]
tot = len(rs); nz = sum(1 for r in rs if r != 1); single = sum(1 for r in rs if r > 1 and isprime(r))
print(f"null model N in [{lo},{hi}] vs S0: not S0-smooth {nz}/{tot}; remainder a single prime {single}/{tot}; remainder exactly 23: {sum(1 for r in rs if r == 23)}")

print("\n=== C4. F3: exact Ollivier-Ricci curvature (alpha=0, mu_x uniform on neighbours) on the lane graph")
def orc_product(basis):
    D = sum(1 if p == 2 else 2 for p in basis)
    def nbrs(x):
        out = []
        for i, p in enumerate(basis):
            for s in ((1,) if p == 2 else (1, -1)):
                y = list(x); y[i] = (y[i]+s) % p; out.append(tuple(y))
        return out
    def dist(u, v):
        return sum(min((a-b) % p, (b-a) % p) for a, b, p in zip(u, v, basis))
    res = {}
    x = tuple(0 for _ in basis)
    for i, p in enumerate(basis):
        y = list(x); y[i] = 1 % p; y = tuple(y)
        A, B = nbrs(x), nbrs(y)
        G = nx.DiGraph()
        for a in range(len(A)): G.add_node(('a', a), demand=-1)
        for b in range(len(B)): G.add_node(('b', b), demand=1)
        for a, u in enumerate(A):
            for b, v in enumerate(B): G.add_edge(('a', a), ('b', b), weight=dist(u, v), capacity=1)
        cost = nx.min_cost_flow_cost(G)
        res[p] = Fraction(D * dist(x, y) - cost, D * dist(x, y))
    return D, res
for basis in ([3], [4], [5], [7], [11], [13], [2, 3, 5, 7, 11, 13]):
    D, r = orc_product(basis)
    print("basis", basis, "degree", D, "kappa per lane:", {p: str(v) for p, v in r.items()})
