#!/usr/bin/env python3
"""
STAR LIFT — the real mechanism, built proper.

Corrects an earlier generic-RNS fixture that (a) used arbitrary shell/anchor
subsets instead of the star-number/star-prime objects, (b) wrote the "+1" as a
generic remainder instead of THE LIFT, and (c) claimed O(1) FULL winding recovery
from a single anchor — which the framework's own anchor-hygiene guard forbids:
a single star-prime anchor recovers only K mod A, never the full K.

The honest mechanism (all verified below, exact integer, zero float):

  star number line   S_n = 6n(n-1) + 1        (centered hexagram numbers)
  hexagram ring      6n(n-1) = S_n - 1        (the shell; cast-out geometry)
  the LIFT           S_n = ring(n) + 1        (ring raised by its center point;
                                               the +1 is the substrate unit carry,
                                               NOT an incidental remainder)
  star primes        S_n that are prime: 13,37,73,181,...  (the coprime ANCHOR
                                                             LADDER)
  star shell         M = 36 = 6·3·2 = S_4 - S_3   (hexagram ring at n=3)
  anchor of record   A = 37 = S_3 = 36 + 1 (star prime, the lift of the shell)
  {1,13} lattice     S_n mod 36 ∈ {1,13} for all n ; S_n ≡ 1 (mod 12) for all n
  K-Elimination      K mod A = (vA - vM)·M^{-1} (mod A)     [needs gcd(M,A)=1]
  self-inverse       36^{-1} ≡ 36 ≡ -1 (mod 37): K-elim collapses to subtract-negate
  HYGIENE            one anchor -> K mod A only. FULL K needs the LADDER:
                     CRT over several star-prime anchors, capacity = product of
                     anchors; K recovered exactly once product > K.

Run: python3 star_lift.py    (asserts every claim, prints the ledger)
"""
from functools import reduce
from math import isqrt

def prod(xs): return reduce(lambda a, b: a * b, xs, 1)
def gcd(a, b):
    while b: a, b = b, a % b
    return a
def modinv(a, m): return pow(a % m, -1, m)
def is_prime(n):
    if n < 2: return False
    if n % 2 == 0: return n == 2
    d = 3
    while d * d <= n:
        if n % d == 0: return False
        d += 2
    return True

# ----------------------------------------------------------------------
# STAR NUMBER LINE
# ----------------------------------------------------------------------
def S(n): return 6 * n * (n - 1) + 1
def ring(n): return 6 * n * (n - 1)               # the hexagram ring (shell) at n
def star_index(N):
    """n if N = S_n (n>=1), else None. Exact via isqrt."""
    if N < 1: return None
    # N = 6n^2 - 6n + 1  ->  n = (6 + sqrt(36 + 24(N-1)))/12
    disc = 36 + 24 * (N - 1)
    r = isqrt(disc)
    if r * r != disc: return None
    if (6 + r) % 12 != 0: return None
    n = (6 + r) // 12
    return n if S(n) == N else None

STAR_SHELL = 36            # ring(3) = S_4 - S_3
ANCHOR = 37                # S_3, the lift of the shell

def star_primes(count):
    """First `count` star primes S_n (n>=2), the coprime anchor ladder."""
    out, n = [], 2
    while len(out) < count:
        s = S(n)
        if is_prime(s): out.append(s)
        n += 1
    return out

# ----------------------------------------------------------------------
# THE LIFT — a star number IS a ring plus the single center point
# ----------------------------------------------------------------------
def lift_decompose(n):
    """S_n as (ring, lift). The lift is always exactly 1 (the center point)."""
    return ring(n), 1

# ----------------------------------------------------------------------
# K-ELIMINATION — winding residue from shell+anchor residues (no reconstruction)
# ----------------------------------------------------------------------
def k_elim(vM, vA, M, A):
    """K mod A = (vA - vM)*M^{-1} mod A.  Requires gcd(M,A)=1."""
    if gcd(M, A) != 1:
        raise ValueError("k_elim requires gcd(M,A)=1")
    return ((vA - vM) * modinv(M, A)) % A

def k_elim_star_collapsed(vM, vA):
    """Star shell 36 / anchor 37: 36 self-inverse mod 37 -> K = (vM - vA) mod 37,
    pure subtract-and-negate, no multiply."""
    return (vM - vA) % 37

# ----------------------------------------------------------------------
# THE LADDER — full winding recovery via CRT over star-prime anchors.
# One anchor gives K mod A (hygiene limit). Stacking coprime star-prime anchors
# recovers K mod (product); once product > K, K is recovered EXACTLY.
# ----------------------------------------------------------------------
def crt(residues, moduli):
    """CRT combine: returns x mod prod(moduli) (moduli pairwise coprime)."""
    M = prod(moduli)
    x = 0
    for r, m in zip(residues, moduli):
        Mi = M // m
        x = (x + r * Mi * modinv(Mi, m)) % M
    return x

def recover_winding(N, shell=STAR_SHELL, anchors=None):
    """Recover K = floor(N/shell) from residues over the star-prime anchor ladder,
    WITHOUT reconstructing N. Auto-sizes the ladder until capacity > K.
    Returns (K_recovered, anchors_used, capacity)."""
    vM = N % shell
    K_true_bound = N // shell            # used only to size the ladder honestly
    if anchors is None:
        anchors, ladder = [], 2
        while prod(anchors) <= K_true_bound:
            s = S(ladder)
            if is_prime(s) and gcd(s, shell) == 1:
                anchors.append(s)
            ladder += 1
    # per-anchor K-elimination (each yields K mod A_i), then CRT
    kres = [k_elim(vM, N % A, shell, A) for A in anchors]
    K = crt(kres, anchors)
    return K, anchors, prod(anchors)

def recover_number_line(N, shell=STAR_SHELL):
    """X = shell*K + vM, with K from the star-prime ladder. Exact."""
    vM = N % shell
    K, anchors, cap = recover_winding(N, shell)
    return shell * K + vM

# ======================================================================
# VERIFICATION LEDGER — asserts on run
# ======================================================================
if __name__ == "__main__":
    import random
    L = []

    # SL1 — star number line + telescoping (climbing = adding rings)
    assert S(2) == 13 and S(3) == 37 and S(4) == 73 and S(77) == 35113
    assert 13 * 37 * 73 == 35113                       # capstone = product of first 3 star primes
    bad = sum(1 for n in range(1, 300)
              if 1 + sum(12 * (k - 1) for k in range(2, n + 1)) != S(n))
    assert bad == 0                                     # S_n = center + all nested rings
    assert all(star_index(S(n)) == n for n in range(1, 200))
    assert star_index(36) is None and star_index(100) is None
    L.append(("SL1 star number line", "VERIFIED",
              "S_n=6n(n-1)+1; S2,3,4=13,37,73; S77=35113=13·37·73; telescoping exact"))

    # SL2 — the {1,13} mod-36 lattice, and ≡1 mod 12, exhaustive over n
    resset = set(S(n) % 36 for n in range(1, 2000))
    assert resset == {1, 13}
    assert all(S(n) % 12 == 1 for n in range(1, 2000))
    L.append(("SL2 {1,13} lattice", "VERIFIED",
              "S_n mod 36 ∈ {1,13} ∀n; S_n ≡ 1 (mod 12) ∀n — exhaustive to n=2000"))

    # SL3 — the lift: ring + center point = star (the +1 is structure)
    for n in range(2, 100):
        r, lift = lift_decompose(n)
        assert r + lift == S(n) and lift == 1 and r == S(n) - 1
    assert ring(3) == 36 and 36 + 1 == 37                # shell lifted by center = anchor
    assert S(4) - S(3) == 36                             # cast-out ring between stars = shell
    L.append(("SL3 the lift", "VERIFIED",
              "S_n = ring(n)+1; ring(3)=36, 36+1=37=A; cast-out S4-S3=36 = the shell"))

    # SL4 — star primes are a valid coprime anchor ladder, all coprime to shell 36
    sp = star_primes(8)
    assert sp[:3] == [13, 37, 73]
    assert all(gcd(sp[i], sp[j]) == 1 for i in range(len(sp)) for j in range(i + 1, len(sp)))
    assert all(gcd(s, STAR_SHELL) == 1 for s in sp)      # every star prime ⊥ shell 36
    L.append(("SL4 anchor ladder", "VERIFIED",
              f"star primes {sp} pairwise coprime AND each coprime to shell 36"))

    # SL5 — single-anchor K-elim + self-inverse collapse on the star shell
    assert modinv(36, 37) == 36                          # 36 ≡ -1, self-inverse
    for N in (36, 37, 73, 6585, 6586):
        assert k_elim(N % 36, N % 37, 36, 37) == (N // 36) % 37
        assert k_elim_star_collapsed(N % 36, N % 37) == (N // 36) % 37
    L.append(("SL5 K-elim + collapse", "VERIFIED",
              "36⁻¹≡36 mod 37; k_elim = (vM-vA) mod 37 (subtract-negate); matches floor%37"))

    # SL6 — HYGIENE: a single anchor recovers ONLY K mod A, never full K
    N = 35113                                            # = S_77
    K_true = N // 36                                     # 975
    single = k_elim(N % 36, N % 37, 36, 37)              # 975 mod 37 = 13
    assert K_true == 975 and single == 13 and single != K_true
    L.append(("SL6 anchor hygiene", "VERIFIED",
              f"single anchor 37 on 35113 -> K mod 37 = 13, NOT K=975 (hygiene guard holds)"))

    # SL7 — the LADDER recovers full winding once capacity > K
    #   {37,73}: product 2701 > 975 -> recovers 975 exactly.
    kres = [k_elim(N % 36, N % A, 36, A) for A in (37, 73)]
    Kfull = crt(kres, [37, 73])
    assert Kfull == 975 and prod([37, 73]) > 975
    # and the auto-sized recovery agrees
    Kr, anchors_used, cap = recover_winding(35113)
    assert Kr == 975 and cap > 975
    L.append(("SL7 ladder full recovery", "VERIFIED",
              f"CRT over star primes {anchors_used} (cap {cap}>975) recovers K=975 exactly"))

    # SL8 — general winding + number-line recovery on random N, ladder auto-sized
    random.seed(11)
    for _ in range(20000):
        N = random.randrange(0, 10**7)
        K, anchors_used, cap = recover_winding(N)
        assert K == N // 36 and cap > (N // 36)
        assert recover_number_line(N) == N
    # boundary: exact star numbers and shell multiples
    for n in range(2, 500):
        assert recover_number_line(S(n)) == S(n)
    L.append(("SL8 general recovery", "VERIFIED",
              "20000 random N in [0,1e7) + all S_n to n=500: winding & number-line exact"))

    # ---- ledger ----
    print("=" * 76)
    print("STAR LIFT — VERIFICATION LEDGER  (exact integer, zero float)")
    print("=" * 76)
    for name, status, note in L:
        print(f"[{status}] {name:26s} {note}")
    print("\nThe corrections over the earlier generic fixture:")
    print("  • shell/anchors are star-number/star-prime objects, not arbitrary subsets")
    print("  • the +1 is the LIFT (ring + center point), represented as structure")
    print("  • single anchor = K mod A ONLY (hygiene); FULL K needs the star-prime LADDER")
    print("  • winding recovered from residues, no reconstruction, no Garner, no float")
