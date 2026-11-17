#!/usr/bin/env python3
"""Exact-integer CRT/K-readout regression tests for arbitrary composite moduli."""
from math import gcd
from random import Random


def inv(a: int, m: int) -> int:
    if m <= 1 or gcd(a, m) != 1:
        raise ValueError(f"inverse does not exist for {a=} mod {m=}")
    return pow(a, -1, m)


def assert_pairwise(moduli):
    assert all(m > 1 for m in moduli)
    for i, a in enumerate(moduli):
        for b in moduli[:i]:
            assert gcd(a, b) == 1, (a, b, gcd(a, b))


def prepare(moduli):
    k = len(moduli)
    assert k >= 1
    M = 1
    for m in moduli:
        assert m > 1
        M *= m
    Mi = [M // m for m in moduli]
    Mi_inv = [inv(Mi[i], moduli[i]) for i in range(k)]
    pair_inv = [[0] * k for _ in range(k)]
    for j in range(1, k):
        for i in range(j):
            pair_inv[i][j] = inv(moduli[i], moduli[j])
    return {"M": M, "Mi": Mi, "Mi_inv": Mi_inv, "pair_inv": pair_inv}


def garner(residues, moduli, ctx):
    k = len(moduli)
    assert k >= 1 and len(residues) == k
    assert all(0 <= r < m for r, m in zip(residues, moduli))
    digits = list(residues)
    for j in range(1, k):
        for i in range(j):
            digits[j] = ((digits[j] - digits[i]) * ctx["pair_inv"][i][j]) % moduli[j]
    x = 0
    for i in reversed(range(k)):
        x = x * moduli[i] + digits[i]
    return x, digits


def crt_data(x, moduli, ctx):
    k = len(moduli)
    M, Mi = ctx["M"], ctx["Mi"]
    assert 0 <= x < M
    residues = [x % m for m in moduli]
    reconstructed, digits = garner(residues, moduli, ctx)
    assert reconstructed == x
    xi = [(residues[i] * ctx["Mi_inv"][i]) % moduli[i] for i in range(k)]
    S = sum(xi[i] * Mi[i] for i in range(k))
    alpha, rem = divmod(S - x, M)
    assert rem == 0 and 0 <= alpha < k
    assert alpha == S // M
    assert S - alpha * M == x
    return residues, digits, xi, S, alpha


def read_alpha(x, M, Mi, xi, S, q, M_inv_q):
    assert gcd(M, q) == 1
    S_q = sum(xi[i] * (Mi[i] % q) for i in range(len(xi))) % q
    x_q = x % q  # residue of the canonical CRT lift, reduced independently from x
    return ((S_q - x_q) * M_inv_q) % q


def x_for_xi(xi, moduli, ctx):
    residues = [(xi[i] * ctx["Mi"][i]) % moduli[i] for i in range(len(moduli))]
    x, _ = garner(residues, moduli, ctx)
    return x


# A: exhaustive reconstruction/witness recovery with a squareful even lane, a
# prime square, and a three-distinct-factor lane; anchor and witness are squares.
mods_a = [8, 9, 25, 7 * 11 * 13]
A_a, q_a = 17**2, 19**2
assert_pairwise([*mods_a, A_a, q_a])
ctx_a = prepare(mods_a)
M_a = ctx_a["M"]
inv_A_a, inv_q_a = inv(M_a, A_a), inv(M_a, q_a)
seen_a = set()
K_samples_a = [0, 1, A_a - 1, A_a, -1]
for x in range(M_a):
    residues, digits, xi, S, alpha = crt_data(x, mods_a, ctx_a)
    assert all(x % m == r for m, r in zip(mods_a, residues))
    assert read_alpha(x, M_a, ctx_a["Mi"], xi, S, q_a, inv_q_a) == alpha
    seen_a.add(alpha)
    for K in K_samples_a:
        s = (x + K * M_a) % A_a
        c = ((s - (S % A_a)) * inv_A_a) % A_a
        assert (alpha + c) % A_a == K % A_a
assert seen_a == set(range(len(mods_a)))
print(f"A exhaustive mixed-shape CRT cases={M_a:,}; lanes={mods_a}; A={A_a}, q2={q_a}; alpha values={sorted(seen_a)}; failures=0")

# B: exhaust every (x,K) anchor pair with a square anchor and square witness.
mods_b = [8, 9, 25]
A_b, q_b = 11**2, 13**2
assert_pairwise([*mods_b, A_b, q_b])
ctx_b = prepare(mods_b)
M_b = ctx_b["M"]
inv_A_b, inv_q_b = inv(M_b, A_b), inv(M_b, q_b)
anchor_pairs = 0
for x in range(M_b):
    _, _, xi, S, alpha = crt_data(x, mods_b, ctx_b)
    assert read_alpha(x, M_b, ctx_b["Mi"], xi, S, q_b, inv_q_b) == alpha
    for K in range(A_b):
        s = (x + K * M_b) % A_b
        c = ((s - (S % A_b)) * inv_A_b) % A_b
        assert (alpha + c) % A_b == K
        anchor_pairs += 1
print(f"B exhaustive square-anchor pairs={anchor_pairs:,}; lanes={mods_b}; A={A_b}, q2={q_b}; failures=0")

# C: q2 == k is sufficient, even for composite q2. A and q2 may share factors
# with each other; each needs only to be coprime to the lane product M.
mods_c = [9, 25, 49, 121]
ctx_c = prepare(mods_c)
M_c = ctx_c["M"]
q_equal, q_greater, A_c = 4, 169, 8
assert gcd(M_c, q_equal) == gcd(M_c, q_greater) == gcd(M_c, A_c) == 1
inv_q_equal, inv_q_greater = inv(M_c, q_equal), inv(M_c, q_greater)
xi_cases = []
for target_alpha in range(len(mods_c)):
    # With these large-enough moduli, sum(1/m_i)<1; this constructs each alpha.
    xi_cases.append([m - 1 if i <= target_alpha else 0 for i, m in enumerate(mods_c)])
rng = Random(0xC0A1E)
xi_cases += [[rng.randrange(m) for m in mods_c] for _ in range(512)]
seen_c = set()
for xi_target in xi_cases:
    x = x_for_xi(xi_target, mods_c, ctx_c)
    _, _, xi, S, alpha = crt_data(x, mods_c, ctx_c)
    assert read_alpha(x, M_c, ctx_c["Mi"], xi, S, q_equal, inv_q_equal) == alpha
    assert read_alpha(x, M_c, ctx_c["Mi"], xi, S, q_greater, inv_q_greater) == alpha
    seen_c.add(alpha)
assert seen_c == set(range(4))
print(f"C q2 boundary cases={len(xi_cases)}; k=q2={q_equal} and q2={q_greater}>k; A={A_c}; alpha values={sorted(seen_c)}; failures=0")

# D: q2<k cannot identify alpha throughout its range: 0 and k-1 collide mod 4.
mods_d = [9, 25, 49, 121, 169]
ctx_d = prepare(mods_d)
M_d = ctx_d["M"]
q_small = 4
assert gcd(M_d, q_small) == 1 and q_small < len(mods_d)
xs_d = [x_for_xi([0] * len(mods_d), mods_d, ctx_d),
        x_for_xi([m - 1 for m in mods_d], mods_d, ctx_d)]
vals = []
for x in xs_d:
    _, _, xi, S, alpha = crt_data(x, mods_d, ctx_d)
    vals.append((alpha, read_alpha(x, M_d, ctx_d["Mi"], xi, S, q_small, inv(M_d, q_small))))
assert vals == [(0, 0), (len(mods_d) - 1, 0)]
print(f"D q2<k ambiguity: k={len(mods_d)}, q2={q_small}; alpha/readout pairs={vals}; non-uniqueness confirmed")

# E: the witness residue must correspond to canonical x. For X=x+K*M, the same
# expression returns alpha-K mod q2, not alpha.
mods_e = [8, 9, 25, 49]
ctx_e = prepare(mods_e)
M_e = ctx_e["M"]
x_e = 12345 % M_e
_, _, xi_e, S_e, alpha_e = crt_data(x_e, mods_e, ctx_e)
q_e = 19**2
assert gcd(M_e, q_e) == 1 and q_e > len(mods_e)
inv_q_e = inv(M_e, q_e)
for K in [0, 1, 2, q_e + 3, -1, 10**12 + 9]:
    canonical = read_alpha(x_e, M_e, ctx_e["Mi"], xi_e, S_e, q_e, inv_q_e)
    shifted_xq = (x_e + K * M_e) % q_e
    S_q = sum(xi_e[i] * (ctx_e["Mi"][i] % q_e) for i in range(len(mods_e))) % q_e
    shifted = ((S_q - shifted_xq) * inv_q_e) % q_e
    assert canonical == alpha_e
    assert shifted == (alpha_e - K) % q_e
print("E canonical/shifted residue: x mod q2 returns alpha; (x+K*M) mod q2 returns alpha-K mod q2")

# F: large-u64 arbitrary composites exercise the range the old u64 additions missed.
high_prime = 3_037_000_493
high_even = 2 * high_prime * high_prime
assert high_even > 2**63 and high_even < 2**64
mods_lane_high = [high_even, 9, 25, 343]
mr_low, q_low = 11 * 13 * 17, 19**2 * 23
assert_pairwise([*mods_lane_high, mr_low, q_low])
ctx_f = prepare(mods_lane_high)
M_f = ctx_f["M"]
inv_q_low = inv(M_f, q_low)
for x in [0, 1, M_f // 2, M_f - 1, 98765432101234567890 % M_f]:
    _, _, xi, S, alpha = crt_data(x, mods_lane_high, ctx_f)
    assert read_alpha(x, M_f, ctx_f["Mi"], xi, S, q_low, inv_q_low) == alpha

# Put >2^63 composite moduli in each redundant slot too; each is independently
# coprime to the odd lane product. A and q2 need not be coprime to each other.
check_prime_1, check_prime_2 = 4_294_967_291, 4_294_967_279
high_odd_1, high_odd_2 = check_prime_1**2, check_prime_2**2
mods_check = [9, 25, 49, 121]
ctx_check = prepare(mods_check)
M_check = ctx_check["M"]
assert high_odd_1 > 2**63 and high_odd_2 > 2**63
assert gcd(M_check, high_even) == gcd(M_check, high_odd_1) == gcd(M_check, high_odd_2) == 1
for x in [0, 1, M_check // 2, M_check - 1, 1234567]:
    _, _, xi, S, alpha = crt_data(x, mods_check, ctx_check)
    for q in [high_even, high_odd_1, high_odd_2]:
        assert read_alpha(x, M_check, ctx_check["Mi"], xi, S, q, inv(M_check, q)) == alpha
print(f"F >2^63 composite lane/check cases pass; high_even={high_even}; high_odd_checks={[high_odd_1, high_odd_2]}")

# G: k=1 has alpha=0 for every canonical residue.
mods_g, q_g = [8], 9
ctx_g = prepare(mods_g)
for x in range(8):
    _, _, xi, S, alpha = crt_data(x, mods_g, ctx_g)
    assert alpha == 0 and read_alpha(x, ctx_g["M"], ctx_g["Mi"], xi, S, q_g, inv(ctx_g["M"], q_g)) == 0
print("G single-lane boundary k=1: all 8 canonical residues pass")

# H: reject inverse requests that are not units, including zero and non-coprime values.
for a, m in [(2, 8), (0, 25), (15, 45)]:
    try:
        inv(a, m)
    except ValueError:
        pass
    else:
        raise AssertionError(f"accepted invalid inverse {a=} {m=}")
print("H non-unit inverse requests rejected: 3/3")
