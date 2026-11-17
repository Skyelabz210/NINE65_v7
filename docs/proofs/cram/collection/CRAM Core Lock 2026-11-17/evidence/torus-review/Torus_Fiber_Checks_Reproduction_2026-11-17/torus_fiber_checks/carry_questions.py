#!/usr/bin/env python3
"""Questions raised by the audit, as exact experiments. Integer/rational only; no floats.
Q1: is the tropical 'boundary bit', the Theorem-5 carry, and the CRT overflow alpha one cocycle (floor of a sum of torus points)?
Q2: in LANE form (no positional shell), what does the anchor give: K, or K up to the overflow alpha?
Q3: what does exact alpha cost? (fixed-point truncation: when does it fail, and where)"""
from fractions import Fraction
from sympy import prevprime, nextprime
from math import gcd

class Rng:
    M64 = (1 << 64) - 1
    def __init__(self, s): self.s = s & self.M64 or 1
    def u64(self):
        x = self.s; x ^= x >> 12; x ^= (x << 25) & self.M64; x ^= x >> 27; self.s = x
        return (x * 0x2545F4914F6CDD1D) & self.M64
    def below(self, n):
        v = 0
        for _ in range((n.bit_length() + 63) // 64 + 1): v = (v << 64) | self.u64()
        return v % n
R = Rng(20261117)

print("=== Q1. One cocycle?  c(a,b) = floor(a+b) on the circle [0,1)")
v_h = v_t = v_q = n = 0
for Q in range(1, 61):
    T = lambda zz: min(Q*m*m + 2*m*zz for m in range(-1100, 1101))
    for z in range(-500, 501):
        K, g = z // Q, z % Q
        b = 1 if 2 * g >= Q else 0
        n += 1
        v_h += ((2 * z) // Q - z // Q != K + b)                    # Hermite: floor(2x) - floor(x) = floor(x + 1/2) = K + [frac(x) >= 1/2]
        vals = {m: Q*m*m + 2*m*z for m in range(-520, 521)}; lo = min(vals.values())
        arg = sorted(m for m, v in vals.items() if v == lo)
        v_t += (arg[0] != -(K + b))                                # tropical minimiser (the smaller one on a tie) = -(K + boundary bit)
        v_q += (T(z + Q) != T(z) - 2*z - Q)                        # tropical quasi-periodicity (automorphy factor)
print(f"{n} cases. Hermite floor(2z/Q)-floor(z/Q)=K+b: violations={v_h}; tropical minimiser=-(K+b): violations={v_t}; T(z+Q)=T(z)-2z-Q: violations={v_q}")
bad = n = 0
for M in range(2, 40):
    for r in range(M):
        for s in range(M):
            n += 1; bad += ((r + s) // M != (Fraction(r, M) + Fraction(s, M)) // 1)   # Thm-5 carry = floor of a sum of torus points
print(f"Theorem-5 carry == floor(r/M + s/M): {n} cases, violations={bad}")

def lanes(ps, x):  # residues
    return [x % p for p in ps]
def setup(ps):
    M = 1
    for p in ps: M *= p
    Mi = [M // p for p in ps]; inv = [pow(Mi[i] % ps[i], -1, ps[i]) for i in range(len(ps))]
    return M, Mi, inv
bad = n = 0
for ps in ([2,3,5,7,11,13], [5,7,11,13,17,19,23], [prevprime(2**16 - 40*i) for i in range(8)]):
    M, Mi, inv = setup(ps)
    for _ in range(3000):
        xm = R.below(M); xs = lanes(ps, xm); xi = [(xs[i] * inv[i]) % ps[i] for i in range(len(ps))]
        alpha = (sum(xi[i] * Mi[i] for i in range(len(ps))) - xm) // M
        tot = sum(Fraction(xi[i], ps[i]) for i in range(len(ps)))
        # alpha as an iterated carry: add torus points one at a time, summing the carries
        acc = Fraction(0); carries = 0
        for i in range(len(ps)):
            s = acc + Fraction(xi[i], ps[i]); carries += s // 1; acc = s - (s // 1)
        n += 1; bad += (tot // 1 != alpha or carries != alpha or acc != Fraction(xm, M))
print(f"CRT overflow alpha == floor(sum xi_i/p_i) == iterated carries, and the fractional part is X_M/M: {n} cases, violations={bad}")

print("\n=== Q2. Lane form: what does the anchor give?  K = alpha + c (mod A)")
bad = n = 0; amb_sizes = set(); contains = 0
for ps in ([2,3,5,7,11,13], [5,7,11,13,17,19,23], [prevprime(2**16 - 40*i) for i in range(8)]):
    M, Mi, inv = setup(ps); k = len(ps)
    anchors = [M + 1]
    A2 = nextprime(M + 5)
    anchors.append(A2)                                              # a generic coprime anchor
    for A in anchors:
        assert gcd(A, M) == 1
        for _ in range(3000):
            X = R.below(M * A); xm = X % M; xs = lanes(ps, xm); s = X % A; K = X // M
            xi = [(xs[i] * inv[i]) % ps[i] for i in range(k)]
            alpha = (sum(xi[i] * Mi[i] for i in range(k)) - xm) // M
            S_A = sum(xi[i] * (Mi[i] % A) for i in range(k)) % A
            c = ((s - S_A) * pow(M % A, -1, A)) % A                  # computable from lanes + anchor in O(k)
            n += 1; bad += ((alpha + c) % A != K % A)
            cands = {(a + c) % A for a in range(k)}                   # alpha unknown, 0<=alpha<k
            amb_sizes.add(len(cands)); contains += (K % A in cands)
print(f"K = alpha + c (mod A): {n} cases, violations={bad}; candidate-set sizes seen {sorted(amb_sizes)}; true K inside candidate set {contains}/{n}")

print("\n=== Q3. What does exact alpha cost?  fixed-point truncation alpha~_t = floor( sum floor(xi_i 2^t / p_i) / 2^t )")
ps = [prevprime(2**16 - 40*i) for i in range(8)]; M, Mi, inv = setup(ps); k = len(ps)
print(f"k={k} lanes, M has {M.bit_length()} bits")
def trial(xm, t):
    xs = lanes(ps, xm); xi = [(xs[i] * inv[i]) % ps[i] for i in range(k)]
    alpha = (sum(xi[i] * Mi[i] for i in range(k)) - xm) // M
    at = sum((xi[i] << t) // ps[i] for i in range(k)) >> t
    return alpha, at
print(f"{'t':>4} {'random fails /20000':>20} {'fails outside X_M < k*M/2^t':>28} {'adversarial fails /2000 (X_M<2000)':>36}")
minimal_t_adv = None
for t in (6, 8, 10, 12, 16, 24, 32, 64, 128, 136, 140):
    rf = outside = af = 0
    for _ in range(20000):
        xm = R.below(M); a, at = trial(xm, t)
        if at != a:
            rf += 1; outside += (not (xm * (1 << t) < k * M))      # theory: only X_M < k*M/2^t can fail
    for xm in range(1, 2001):
        a, at = trial(xm, t); af += (at != a)
    if af == 0 and minimal_t_adv is None: minimal_t_adv = t
    print(f"{t:>4} {rf:>20} {outside:>28} {af:>36}")
print("smallest t in this list with zero adversarial failures:", minimal_t_adv, "; M bits + bits(k) =", M.bit_length() + k.bit_length())
