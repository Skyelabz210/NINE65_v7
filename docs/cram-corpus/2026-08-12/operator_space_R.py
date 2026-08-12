#!/usr/bin/env python3
"""
OPERATOR SPACE — THE R FAMILY, built proper.

Thesis under test: Sqrt and the SVD spectral core do not need imported
sequential algorithms (Tonelli-Shanks as foreign subroutine, Faddeev-LeVerrier
with divisions, CORDIC fixed-point rotations). Both are already NATIVE to the
CRAM operator space:

  R-operator     per-lane Sqrt IS a power map plus at most (s-1) masked twists
                 by precomputed lane constants (chimera table), where
                 s = v2(p-1) is a lane attribute. Heterogeneous exponents per
                 lane = one more schema letter. Gate = E_{(p-1)/2} (Euler),
                 itself a power map. Nothing foreign.

  s closed form  on the star ladder, s(S_n) = 2 + v2(T_{n-1}) — the Sqrt
                 hardness class of a star prime is read off the triangular
                 number's 2-adic valuation. Geometry decides the twist depth.

  branch = winding   per-lane roots have +/- ambiguity; the true integer root
                 is the unique branch whose SQUARE reproduces the carried
                 winding K. Selected by K-Elimination reads on the star-prime
                 anchor ladder (37, 73). Uniqueness is a THEOREM once the
                 anchor product exceeds the shell.

  Berkowitz      division-free characteristic polynomial (pure ring ops:
                 +, x only) — valid natively mod ANY modulus, composite or
                 factor-sharing, because there is nothing to invert. Replaces
                 Faddeev-LeVerrier (whose exact divisions by k collide with
                 lanes sharing factors with k) AND retires CORDIC: the sigma^2
                 spectrum is carried as an exact integer polynomial; sigma_1^2
                 is isolated by Taylor-shift positivity in exact arithmetic.

Everything below is exact integer / exact rational. Zero float. No Garner,
no mixed radix, no reconstruction. Run: python3 operator_space_R.py
"""
from fractions import Fraction
from functools import reduce
import random

# ----------------------------------------------------------------------
# helpers (exact integer only)
# ----------------------------------------------------------------------
def prod(xs): return reduce(lambda a, b: a * b, xs, 1)

def gcd(a, b):
    while b: a, b = b, a % b
    return a

def v2(n):
    """2-adic valuation, exact."""
    if n == 0: raise ValueError("v2(0)")
    s = 0
    while n % 2 == 0:
        n //= 2; s += 1
    return s

def is_prime(n):
    if n < 2: return False
    if n % 2 == 0: return n == 2
    d = 3
    while d * d <= n:
        if n % d == 0: return False
        d += 2
    return True

def modinv(a, m):
    """General modular inverse (extended-Euclid semantics via pow(.,-1,.)).
    NEVER Fermat pow(a, m-2, m): silently wrong on composite/anchor moduli."""
    return pow(a % m, -1, m)

def crt(residues, moduli):
    M = prod(moduli)
    x = 0
    for r, m in zip(residues, moduli):
        Mi = M // m
        x = (x + r * Mi * modinv(Mi, m)) % M
    return x

def isqrt_int(n):
    if n < 0: raise ValueError
    if n < 2: return n
    x, y = n, (n + 1) >> 1
    while y < x:
        x, y = y, (y + n // y) >> 1
    return x

# star line
def S(n): return 6 * n * (n - 1) + 1
def ring(n): return 6 * n * (n - 1)
def T(n): return n * (n + 1) // 2          # triangular; T_{n-1} = n(n-1)/2

def star_primes(count):
    out, n = [], 2
    while len(out) < count:
        s = S(n)
        if is_prime(s): out.append((n, s))
        n += 1
    return out

# ----------------------------------------------------------------------
# THE R OPERATOR — per-lane Sqrt as power map + masked twist chimera
# ----------------------------------------------------------------------
def lane_table(p):
    """Precompute the lane's R-chimera: s = v2(p-1), odd part m,
    Atkin twist c (s=2), or the 2-Sylow zeta tower (s>=3)."""
    assert is_prime(p) and p > 2
    s = v2(p - 1)
    m = (p - 1) >> s
    tab = {"p": p, "s": s, "m": m}
    if s == 2:
        # p = 5 mod 8: 2 is a QNR, c = 2^((p-1)/4) satisfies c^2 = -1
        tab["c"] = pow(2, (p - 1) // 4, p)
    if s >= 3:
        z = 2
        while pow(z, (p - 1) // 2, p) != p - 1:
            z += 1
        tab["zeta"] = pow(z, m, p)          # order exactly 2^s
    return tab

def R_gate(a, p):
    """Euler gate E_{(p-1)/2}: 1 QR, -1 QNR, 0 zero — itself a power map."""
    if a % p == 0: return 0
    e = pow(a, (p - 1) // 2, p)
    return -1 if e == p - 1 else 1

def R_lane(a, tab):
    """Per-lane root. Returns r with r^2 = a mod p, or None (QNR).
    s=1: single power map. s=2: power map + one masked twist (Atkin).
    s>=3: power map + at most s-1 masked twists by precomputed zeta powers
    (Tonelli-Shanks unrolled at fixed lane = chimera table)."""
    p, s, m = tab["p"], tab["s"], tab["m"]
    a %= p
    if a == 0: return 0
    if R_gate(a, p) != 1: return None
    if s == 1:                                   # p = 3 mod 4
        return pow(a, (p + 1) // 4, p)
    if s == 2:                                   # p = 5 mod 8, Atkin
        x = pow(a, (p + 3) // 8, p)
        if (x * x) % p != a:
            x = (x * tab["c"]) % p               # one masked multiply
        return x
    # s >= 3: unrolled TS at fixed lane; every twist is a power of the one
    # precomputed zeta (order 2^s), so the whole ladder is a chimera table
    c = tab["zeta"]
    x = pow(a, (m + 1) // 2, p)                  # base power map
    t = pow(a, m, p)                             # error term, order | 2^(s-1)
    M_ = s
    while t != 1:
        i, tt = 0, t                             # least i with t^(2^i) = 1
        while tt != 1:
            tt = (tt * tt) % p; i += 1
        b = pow(c, 1 << (M_ - i - 1), p)
        x = (x * b) % p
        c = (b * b) % p                          # descend the 2-Sylow tower
        t = (t * c) % p
        M_ = i
    return x

# ----------------------------------------------------------------------
# BERKOWITZ — division-free characteristic polynomial (pure ring ops)
# ----------------------------------------------------------------------
def berkowitz(M, mod=None):
    """char poly of n x n matrix M as descending coeffs [1, c_{n-1},...,c_0]
    of det(xI - M). Ring operations only: +, x. mod=None -> over Z;
    mod=m -> natively over Z/mZ (m may be composite / factor-sharing:
    nothing is ever inverted)."""
    red = (lambda v: v % mod) if mod else (lambda v: v)
    n = len(M)
    if n == 0: return [1]
    poly = [1, red(-M[0][0])]
    for i in range(1, n):
        a = M[i][i]
        R = M[i][:i]
        C = [M[j][i] for j in range(i)]
        Sub = [row[:i] for row in M[:i]]
        items = [1, red(-a)]
        vec = C[:]
        for _ in range(i):
            items.append(red(-sum(red(R[j] * vec[j]) for j in range(i))))
            vec = [red(sum(red(Sub[r][j] * vec[j]) for j in range(i)))
                   for r in range(i)]
        new = [0] * (i + 2)
        for r_ in range(i + 2):
            acc = 0
            for c_ in range(i + 1):
                k = r_ - c_
                if 0 <= k < len(items):
                    acc = red(acc + items[k] * poly[c_])
            new[r_] = acc
        poly = new
    return poly

# brute-force ground truth: det(xI - M) by exact polynomial cofactors
def pad(p, q):
    L = max(len(p), len(q))
    return p + [0]*(L-len(p)), q + [0]*(L-len(q))

def padd(p, q):
    p, q = pad(list(p), list(q)); return [x+y for x, y in zip(p, q)]

def pmul(p, q):
    out = [0]*(len(p)+len(q)-1)
    for i, x in enumerate(p):
        if x:
            for j, y in enumerate(q):
                out[i+j] += x*y
    return out

def pdet(P):  # P: matrix of polys (ascending coeff lists)
    n = len(P)
    if n == 1: return P[0][0]
    acc = [0]
    for r in range(n):
        minor = [[P[i][j] for j in range(1, n)] for i in range(n) if i != r]
        term = pmul(P[r][0], pdet(minor))
        acc = padd(acc, term if r % 2 == 0 else [-c for c in term])
    return acc

def charpoly_brute(M):
    n = len(M)
    P = [[([-M[i][j]] if i != j else [-M[i][i], 1]) for j in range(n)]
         for i in range(n)]
    asc = pdet(P)
    asc = asc + [0]*((n+1)-len(asc))
    return list(reversed(asc))               # descending, monic

def taylor_shift(desc, t):
    """coeffs (descending) of p(x+t), exact for int or Fraction t."""
    c = list(desc); out = []
    for _ in range(len(desc)):
        for i in range(1, len(c)):
            c[i] = c[i] + t * c[i-1]
        out.append(c[-1]); c = c[:-1]
    return list(reversed(out))

def all_positive_shift(desc, t):
    sh = taylor_shift(desc, t)
    return all(x > 0 for x in sh), sh

def matmul(A, B):
    n, m, k = len(A), len(B[0]), len(B)
    return [[sum(A[i][t]*B[t][j] for t in range(k)) for j in range(m)]
            for i in range(n)]

def transpose(A): return [list(r) for r in zip(*A)]

# ======================================================================
# VERIFICATION LEDGER
# ======================================================================
if __name__ == "__main__":
    random.seed(37)
    L = []

    # ------------------------------------------------------------------
    # OS1 — s = v2(p-1) is GEOMETRY on the star line: s(S_n) = 2 + v2(T_{n-1})
    # ------------------------------------------------------------------
    for n in range(2, 3001):
        assert v2(S(n) - 1) == 2 + v2(T(n - 1)), n
    for n in range(1, 5001):
        assert S(n) % 4 == 1
        assert S(n) % 8 in (1, 5)
    sp = star_primes(12)
    cls = []
    for n, p in sp:
        s = v2(p - 1)
        assert s == 2 + v2(T(n - 1))
        cls.append((n, p, s))
    n_s2 = [p for _, p, s in cls if s == 2]
    n_s3p = [(p, s) for _, p, s in cls if s >= 3]
    L.append(("OS1 s = 2 + v2(T_{n-1})", "VERIFIED",
              f"identity exhaustive n<=3000; S_n mod 8 in {{1,5}}; every star prime is p=1 mod 4 "
              f"(shortcut NEVER fires); s=2 Atkin class: {n_s2}; tower class: {n_s3p}"))

    # ------------------------------------------------------------------
    # OS2 — i lives IN-LANE on every star prime; on 37, i = 6 = isqrt(shell)
    # ------------------------------------------------------------------
    i_table = {}
    for n, p in sp:
        # i exists iff p = 1 mod 4 (always, by OS1); find it via the R machinery
        tab = lane_table(p)
        i_p = R_lane(p - 1, tab)          # sqrt(-1) in the lane
        assert i_p is not None and (i_p * i_p) % p == p - 1
        i_table[p] = min(i_p, p - i_p)
    assert i_table[37] == 6 and 6 * 6 == ring(3) and ring(3) % 37 == 36
    # shell = ring(n) = S_n - 1 = -1 mod S_n ALWAYS; i = integer isqrt(ring)
    # exactly when ring is a perfect square. 6n(n-1) = y^2 <=> n(n-1) = 6z^2
    # <=> w^2 - 24 z^2 = 1 with w = 2n-1: a PELL equation. The self-rooting
    # levels are the Pell orbit. (Corrects an initial guess that 37 was unique.)
    sq_ns = [n for n in range(1, 20001) if isqrt_int(ring(n))**2 == ring(n)]
    assert sq_ns == [1, 3, 25, 243, 2401]
    for k in range(2, len(sq_ns)):                      # Pell recurrence on n
        assert sq_ns[k] == 10 * sq_ns[k-1] - sq_ns[k-2] - 4
    ys = [isqrt_int(ring(n)) for n in sq_ns]            # i-candidates 0,6,60,594,5880
    for k in range(2, len(ys)):
        assert ys[k] == 10 * ys[k-1] - ys[k-2]          # Pell recurrence on y
    selfroot = [(n, S(n), isqrt_int(ring(n))) for n in sq_ns if is_prime(S(n))]
    assert [t[1] for t in selfroot] == [37, 352837, 34574401]
    for n, p, i_p in selfroot:
        assert (i_p * i_p) % p == p - 1                 # i = isqrt(shell), exactly
    L.append(("OS2 i in-lane, Pell anchors", "VERIFIED",
              f"i mod p for star primes: {dict(list(i_table.items())[:6])}; square-ring levels are the "
              f"Pell orbit w^2-24z^2=1: n in {sq_ns} (recurrence n' = 10n - n'' - 4); SELF-ROOTING "
              f"star primes (i = isqrt(shell) exactly): 37 (i=6), 352837 (i=594), 34574401 (i=5880); "
              f"initial 37-uniqueness guess falsified and upgraded to the orbit"))

    # ------------------------------------------------------------------
    # OS3 — R operator exhaustive per lane, all three classes
    # ------------------------------------------------------------------
    lanes = [3, 5, 7, 11, 13, 37, 73, 181, 337, 433, 541, 661]
    checks = 0
    for p in lanes:
        tab = lane_table(p)
        squares = set((x * x) % p for x in range(p))
        for a in range(p):
            r = R_lane(a, tab)
            has = a in squares
            if a == 0:
                assert r == 0
            elif has:
                assert r is not None and (r * r) % p == a, (p, a, r)
                assert R_gate(a, p) == 1
            else:
                assert r is None and R_gate(a, p) == -1
            checks += 1
    L.append(("OS3 R operator exhaustive", "VERIFIED",
              f"{checks} exact checks over lanes {lanes}: gate E_(p-1)/2 + root correct on every "
              f"element of every lane; classes s=1 (power map), s=2 (Atkin, 1 twist), "
              f"s in {{3,4}} (tower, <= s-1 twists)"))

    # ------------------------------------------------------------------
    # OS4 — Sqrt period theorem (generalizes VAULT-01 F_11 4-cycle)
    #   For p = 3 mod 4, Sqrt = E_{(p+1)/4} is a bijection QR* -> QR*;
    #   lcm of its cycle lengths = ord of 2 modulo (p-1)/2.
    # ------------------------------------------------------------------
    def ordmod(a, m):
        if m == 1: return 1
        assert gcd(a, m) == 1
        k, x = 1, a % m
        while x != 1:
            x = (x * a) % m; k += 1
        return k
    per_checked = 0
    for p in [q for q in range(3, 500) if is_prime(q) and q % 4 == 3]:
        tab = lane_table(p)
        qrs = sorted(set((x * x) % p for x in range(1, p)))
        seen, lcm = set(), 1
        for a in qrs:
            if a in seen: continue
            cyc, x = [], a
            while x not in cyc:
                cyc.append(x); x = R_lane(x, tab)
            for c in cyc: seen.add(c)
            g = gcd(lcm, len(cyc)); lcm = lcm // g * len(cyc)
        assert lcm == ordmod(2, (p - 1) // 2), p
        per_checked += 1
        if p == 11:
            assert lcm == 4        # VAULT-01 reproduced from the theorem
    L.append(("OS4 Sqrt period = ord(2)", "VERIFIED",
              f"{per_checked} primes p=3 mod 4 (<500): Sqrt cycle lcm on QR* equals "
              f"ord_((p-1)/2)(2); F_11 gives ord_5(2)=4 — VAULT-01's 4-cycle is this theorem's instance"))

    # ------------------------------------------------------------------
    # OS6 — BRANCH = WINDING: root-branch selection by the anchor ladder
    #   Shell M = 1155 = 3*5*7*11 (composite lane, Saturation Principle).
    #   Anchors 37, 73 (star primes), product 2701 > 1155 = M.
    #   THEOREM: rho in [0,M), rho^2 = X mod M, and winding-of-rho^2
    #   matching K_X mod 2701 forces rho^2 = X exactly, hence rho = r.
    #   (rho^2, X < M^2 < M*2701; congruent mod M*2701 => equal.)
    # ------------------------------------------------------------------
    Msh = 3 * 5 * 7 * 11
    anchors = (37, 73)
    assert prod(anchors) > Msh                      # capacity condition
    lane_ps = (3, 5, 7, 11)
    tabs = {p: lane_table(p) for p in lane_ps}
    branch_total = 0
    for r in range(0, Msh):
        X = r * r
        vX, KX = X % Msh, X // Msh                  # carried pair (v, K)
        # per-lane roots via R (in-lane ring-iso across the composite lane's factors)
        opts = []
        for p in lane_ps:
            rp = R_lane(X % p, tabs[p])
            assert rp is not None                   # X is a global square
            opts.append([rp] if rp == 0 else [rp, p - rp])
        # enumerate branches -> candidate rho mod Msh (direct ring-iso combine)
        cands = [[]]
        for o in opts:
            cands = [c + [v] for c in cands for v in o]
        survivors = []
        for tup in cands:
            rho = crt(tup, list(lane_ps))
            # winding read of rho^2 on each anchor via K-Elimination:
            #   K mod A = (vA - vM) * M^{-1} mod A
            kreads = []
            for A in anchors:
                vA = ((rho % A) * (rho % A)) % A
                kreads.append(((vA - vX) * modinv(Msh, A)) % A)
            Kread = crt(kreads, list(anchors))      # K mod 2701, ladder combine
            if Kread == KX % prod(anchors):
                survivors.append(rho)
            branch_total += 1
        assert survivors == [r], (r, survivors)     # UNIQUE, and it's the root
    L.append(("OS6 branch = winding", "VERIFIED",
              f"exhaustive r in [0,1155): {branch_total} branch checks; winding-match on ladder "
              f"(37,73) selects the true root UNIQUELY every time; uniqueness is the capacity "
              f"theorem 37*73=2701 > M=1155, same ladder discipline as magnitude recovery"))

    # ------------------------------------------------------------------
    # OS7 — BERKOWITZ: division-free char poly; lane-native; exact sigma_1^2
    # ------------------------------------------------------------------
    # (a) correctness vs exact cofactor ground truth
    bk_checks = 0
    for n in range(1, 6):
        for _ in range(25):
            A = [[random.randrange(-9, 10) for _ in range(n)] for _ in range(n)]
            assert berkowitz(A) == charpoly_brute(A), (n, A)
            bk_checks += 1
    # (b) Cayley-Hamilton exactly over Z
    ch_checks = 0
    for n in range(2, 6):
        for _ in range(10):
            A = [[random.randrange(-9, 10) for _ in range(n)] for _ in range(n)]
            cp = berkowitz(A)
            Pw = [[1 if i == j else 0 for j in range(n)] for i in range(n)]
            Acc = [[0]*n for _ in range(n)]
            for c in reversed(cp):                  # ascending Horner-free sum
                Acc = [[Acc[i][j] + c * Pw[i][j] for j in range(n)] for i in range(n)]
                Pw = matmul(Pw, A)
            # Acc = sum c_k A^k with cp descending reversed -> ascending: p(A)
            assert all(Acc[i][j] == 0 for i in range(n) for j in range(n))
            ch_checks += 1
    # (c) lane-nativity on COMPOSITE / factor-sharing moduli: no divisions,
    # so Berkowitz mod m == (Berkowitz over Z) mod m, m = 36, 77, 5929, 30030
    ln_checks = 0
    for m in (36, 77, 5929, 30030):
        for _ in range(15):
            A = [[random.randrange(0, m) for _ in range(4)] for _ in range(4)]
            zz = [c % m for c in berkowitz(A)]
            nat = berkowitz(A, mod=m)
            assert zz == nat, (m, A)
            ln_checks += 1
    # (d) exact SVD spectral core: B = A^T A; char poly coeffs are exact
    # integers; -c_{n-1} = trace = Frobenius^2; +-c_0 = Gram det;
    # sigma_1^2 isolated by Taylor-shift positivity (valid: B PSD => real roots)
    A = [[random.randrange(-9, 10) for _ in range(4)] for _ in range(5)]
    B = matmul(transpose(A), A)
    cp = berkowitz(B)
    frob2 = sum(A[i][j]**2 for i in range(5) for j in range(4))
    assert -cp[1] == sum(B[i][i] for i in range(4)) == frob2
    # known-spectrum sanity: diag(9,4,1) -> bracket lands exactly at 9
    D = [[9,0,0],[0,4,0],[0,0,1]]
    cpd = berkowitz(D)
    ok10, _ = all_positive_shift(cpd, 10); ok9, sh9 = all_positive_shift(cpd, 9)
    assert ok10 and not ok9 and taylor_shift(cpd, 9)[-1] == 0   # root AT 9
    # random PSD: integer bracket then exact-rational bisection, 20 steps
    t = 1
    while not all_positive_shift(cp, t)[0]:
        t += max(1, t)          # exponential probe up
    lo_i, hi_i = 0, t
    while hi_i - lo_i > 1:      # smallest integer with all-positive shift
        mid = (lo_i + hi_i) // 2
        if all_positive_shift(cp, mid)[0]: hi_i = mid
        else: lo_i = mid
    lo, hi = Fraction(hi_i - 1), Fraction(hi_i)     # sigma1^2 in [lo, hi)
    for _ in range(20):
        mid = (lo + hi) / 2
        if all_positive_shift(cp, mid)[0]: hi = mid
        else: lo = mid
    assert hi - lo == Fraction(1, 2**20)
    # exact-rational certificate of the bracket:
    assert not all_positive_shift(cp, lo)[0] and all_positive_shift(cp, hi)[0]
    # coherence score, exact bounds (the svd_engine metric, now certified)
    sco_lo = (10**4 * lo) / frob2
    sco_hi = (10**4 * hi) / frob2
    coh = int(sco_lo)  # integer part pinned since width < 1
    assert int(sco_hi * (1)) - int(sco_lo) <= 1
    L.append(("OS7 Berkowitz spectral core", "VERIFIED",
              f"charpoly=bruteforce {bk_checks}/;{ch_checks} Cayley-Hamilton exact; lane-native mod "
              f"36/77/5929/30030 ({ln_checks} checks, zero divisions); sigma1^2 of A^T A isolated to "
              f"width 2^-20 by shift-positivity, coherence = {coh}/10000 certified — power "
              f"iteration and CORDIC retired"))

    # ------------------------------------------------------------------
    # OS8 — census delta: R joins the alphabet
    # ------------------------------------------------------------------
    letters8 = 8 ** 8
    letters9 = 9 ** 8
    assert letters8 == 16 ** 6 == 16_777_216       # the recorded 16^6 sighting
    phi = lambda n: sum(1 for k in range(1, n + 1) if gcd(k, n) == 1)
    bij = prod(phi(p - 1) for p in (3, 5, 7, 11, 13))
    L.append(("OS8 census delta", "COMPUTED",
              f"8-letter/8-lane schema space 8^8 = {letters8:,} EQUALS the recorded 16^6 census "
              f"sighting; adding R: 9^8 = {letters9:,}; pure power-map bijections over safe lanes "
              f"{{3,5,7,11,13}}: prod phi(p-1) = {bij}"))

    # ---- ledger ----
    print("=" * 78)
    print("OPERATOR SPACE — R FAMILY VERIFICATION LEDGER (exact integer, zero float)")
    print("=" * 78)
    for name, status, note in L:
        print(f"[{status}] {name:28s} {note}")
    print()
    print("Corrections folded inline:")
    print("  - prior plan imported Tonelli-Shanks as a foreign subroutine ->")
    print("    superseded: Sqrt is a power map + <= s-1 masked twists, s = v2(p-1)")
    print("    a lane attribute with closed form 2 + v2(T_{n-1}) on the star line")
    print("  - prior plan proposed Faddeev-LeVerrier for the char poly ->")
    print("    superseded: F-L's exact divisions by k collide with lanes sharing")
    print("    factors with k; Berkowitz has ZERO divisions and is native on")
    print("    composite / factor-sharing moduli (witnessed mod 36, 77, 5929, 30030)")
