#!/usr/bin/env python3
"""Exhaustive small-ring check: reconstruction requires coprimality, not prime lanes."""
from math import gcd

# Every lane modulus is composite; they are pairwise coprime.
mods = [8, 9, 25, 49]
k = len(mods)
assert all(any(m % d == 0 for d in range(2, m)) for m in mods)
assert all(gcd(mods[i], mods[j]) == 1 for i in range(k) for j in range(i))
M = 1
for m in mods:
    M *= m

# Both redundant/witness moduli are also composite and coprime to the lane product.
A = 17 * 19
q2 = 23 * 29
assert gcd(M, A) == gcd(M, q2) == 1
assert q2 > k

def inv(a, m):
    # Python's three-argument pow uses the general extended-Euclid inverse.
    assert gcd(a, m) == 1
    return pow(a, -1, m)

# Precompute the CRT idempotent inverses and independent redundant inverses.
Mi = [M // m for m in mods]
Mi_inv = [inv(Mi[i], mods[i]) for i in range(k)]
M_inv_A = inv(M, A)
M_inv_q2 = inv(M, q2)
pair_inv = [[0] * k for _ in range(k)]
for i in range(k):
    for j in range(i + 1, k):
        pair_inv[i][j] = inv(mods[i], mods[j])

anchor_pairs = 0
for x in range(M):
    residues = [x % m for m in mods]

    # Garner mixed-radix digits, using inverses that exist by coprimality.
    digits = residues[:]
    for j in range(1, k):
        for i in range(j):
            digits[j] = ((digits[j] - digits[i]) * pair_inv[i][j]) % mods[j]
    garner = 0
    for i in reversed(range(k)):
        garner = garner * mods[i] + digits[i]
    assert garner == x

    # Redundant-modulus alpha readout.
    xi = [(residues[i] * Mi_inv[i]) % mods[i] for i in range(k)]
    S = sum(xi[i] * Mi[i] for i in range(k))
    alpha = (S - x) // M
    assert 0 <= alpha < k
    assert S - alpha * M == x

    # Independent composite q2 recovers alpha exactly because q2 > k and gcd(q2,M)=1.
    xq = garner % q2
    sq = sum(xi[i] * (Mi[i] % q2) for i in range(k)) % q2
    alpha_q = ((sq - xq) * M_inv_q2) % q2
    assert alpha_q == alpha

    # A composite coprime anchor identifies K modulo A; the unknown alpha leaves k candidates.
    SA = sum(xi[i] * (Mi[i] % A) for i in range(k)) % A
    for K in range(A):
        s = (x + K * M) % A
        c = ((s - SA) * M_inv_A) % A
        assert (alpha + c) % A == K
        candidates = {(a + c) % A for a in range(k)}
        assert K in candidates
        anchor_pairs += 1

print(f"lane moduli={mods}; product M={M}")
print(f"all lane moduli composite; pairwise gcds=1; composite anchors A={A}, q2={q2}; gcd(M,A)=gcd(M,q2)=1")
print(f"full exact CRT/Garner reconstruction cases={M}, failures=0")
print(f"independent composite-q2 alpha checks={M}, failures=0; alpha range=[0,{k-1}]")
print(f"composite-anchor (x,K) cases={anchor_pairs}, failures=0; anchor returns K modulo A with {k} alpha candidates")
