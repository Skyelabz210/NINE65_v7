"""
grover_exact.py — CRAM-clean exact Grover dynamics. A1: pure integers + Fraction.
State collapses to the 2D invariant subspace: track scaled integer pair (U, W)
(unmarked, marked amplitudes, common denominator N^k * sqrt(N) held implicitly).
Oracle+diffusion per step:  U' = (N-2M)U - 2M W ;  W' = 2(N-M)U + (N-2M)W.
Invariant (exact, every step): (N-M)U^2 + M W^2 = N^(2k+1).
Success probability p_k = M W^2 / N^(2k+1) as an exact rational.
Optimal stopping found by exact Fraction argmax — no pi, no sqrt, no floats.
"""

import io
import sys
import time
import tokenize
from fractions import Fraction

from cramlab import gen_lanes


def step(U, W, N, M):
    return (N - 2 * M) * U - 2 * M * W, 2 * (N - M) * U + (N - 2 * M) * W


# ---------------------------------------------------------------- battery G1
def g1_full_vector_witness():
    """Full scaled-integer state vector vs pair recurrence: every index, every
    step, exact equality + exact norm. Witnesses the 2D collapse structurally."""
    checks = breaks = 0
    for (N, M) in ((8, 1), (16, 1), (16, 3), (32, 1), (32, 2), (64, 5)):
        v = [1] * N                       # scaled uniform start
        U, W = 1, 1
        for k in range(1, 41):
            v = [-x if i < M else x for i, x in enumerate(v)]   # oracle (marked first)
            s = sum(v)
            v = [2 * s - N * x for x in v]                       # diffusion, rescaled by N
            U, W = step(U, W, N, M)
            for i, x in enumerate(v):
                want = W if i < M else U
                if x != want:
                    breaks += 1
                checks += 1
            if sum(x * x for x in v) != (N - M) * U * U + M * W * W:
                breaks += 1
            if (N - M) * U * U + M * W * W != N ** (2 * k + 1):
                breaks += 1
            checks += 2
    return "G1 pair==full-vector, all indices+norm", checks, breaks


# ---------------------------------------------------------------- battery G2
def g2_deep_exact_norm():
    """Depth battery: N=2^20, M=1, 2000 iterations. Exact invariant asserted at
    every step — the zero-decoherence statement, held to arbitrary depth."""
    N, M = 1 << 20, 1
    U, W = 1, 1
    checks = breaks = 0
    target = N
    for k in range(1, 2001):
        U, W = step(U, W, N, M)
        target *= N * N
        if (N - M) * U * U + M * W * W != target:
            breaks += 1
        checks += 1
    return "G2 depth-2000 exact norm, N=2^20", checks, breaks


# ---------------------------------------------------------------- battery G3
def g3_lane_tracked():
    """CRAM lane mode: the same trajectory tracked in residue lanes at O(lanes)
    word-ops per step, depth- and N-independent cost; lanewise invariant every
    step. Cross-checked against the bignum trajectory at checkpoints."""
    N, M = 1 << 20, 1
    lanes, _ = gen_lanes(300)
    up = [1] * len(lanes)
    wp = [1] * len(lanes)
    tp = [N % p for p in lanes]
    n2 = [(N * N) % p for p in lanes]
    U, W = 1, 1
    checks = breaks = 0
    depth = 20000
    for k in range(1, depth + 1):
        for i, p in enumerate(lanes):
            u, w = up[i], wp[i]
            up[i] = ((N - 2 * M) * u - 2 * M * w) % p
            wp[i] = (2 * (N - M) * u + (N - 2 * M) * w) % p
            tp[i] = (tp[i] * n2[i]) % p
            if ((N - M) * up[i] * up[i] + M * wp[i] * wp[i]) % p != tp[i]:
                breaks += 1
            checks += 1
        if k <= 400:                                   # bignum cross-check window
            U, W = step(U, W, N, M)
            for i, p in enumerate(lanes):
                if up[i] != U % p or wp[i] != W % p:
                    breaks += 1
                checks += 1
    return "G3 lane-tracked depth-20000 + bignum cross-check", checks, breaks


# ---------------------------------------------------------------- battery G4
def g4_exact_optimal_stopping():
    """Optimal k by exact rational argmax: scan until first decrease. No pi,
    no square root — the stopping point emerges from integer comparisons."""
    N, M = 1 << 20, 1
    U, W = 1, 1
    best_k, best_p = 0, Fraction(M, N)
    den = N
    k = 0
    while True:
        k += 1
        U, W = step(U, W, N, M)
        den *= N * N
        p = Fraction(M * W * W, den)
        if p < best_p:
            break
        best_k, best_p = k, p
    shortfall = 1 - best_p
    return best_k, best_p, shortfall


# ---------------------------------------------------------------- timing
def time_ns(fn, reps=3):
    fn()
    ts = []
    for _ in range(reps):
        t0 = time.perf_counter_ns()
        fn()
        ts.append(time.perf_counter_ns() - t0)
    ts.sort()
    return ts[len(ts) // 2]


def timings():
    N, M = 1 << 20, 1
    lanes, _ = gen_lanes(300)
    kL = len(lanes)

    def lane_iters():
        up = [1] * kL
        wp = [1] * kL
        for _ in range(5000):
            for i, p in enumerate(lanes):
                u, w = up[i], wp[i]
                up[i] = ((N - 2 * M) * u - 2 * M * w) % p
                wp[i] = (2 * (N - M) * u + (N - 2 * M) * w) % p
    lane_ns = time_ns(lane_iters) // 5000

    Nv = 4096
    def vector_iters():
        v = [1] * Nv
        for _ in range(20):
            v = [-x if i < 1 else x for i, x in enumerate(v)]
            s = sum(v)
            v = [2 * s - Nv * x for x in v]
    vec_ns = time_ns(vector_iters) // 20
    return lane_ns, vec_ns, kL, Nv


def lint_self():
    with open("grover_exact.py", "rb") as f:
        toks = list(tokenize.tokenize(f.readline))
    bad = [t for t in toks if
           (t.type == tokenize.NAME and t.string in ("float", "numpy", "statistics")) or
           (t.type == tokenize.NUMBER and not t.string.lower().startswith("0x")
            and ("." in t.string or "e" in t.string.lower())) or
           (t.type == tokenize.OP and t.string == "/")]
    return len(toks), len(bad)


def main():
    sys.set_int_max_str_digits(200000)
    total_c = total_b = 0
    for battery in (g1_full_vector_witness, g2_deep_exact_norm, g3_lane_tracked):
        name, c, b = battery()
        total_c += c
        total_b += b
        print("[%s] %-46s checks=%-7d breaks=%d" %
              ("PASS" if b == 0 else "BREAK", name, c, b))
    toks, bad = lint_self()
    total_c += toks
    total_b += bad
    print("[%s] %-46s checks=%-7d breaks=%d" %
          ("PASS" if bad == 0 else "BREAK", "G5 A1 tokenizer lint (self)", toks, bad))

    k_star, p_star, short = g4_exact_optimal_stopping()
    print("\nExact optimal stopping, N=2^20, M=1:")
    print("  k* = %d iterations (exact rational argmax, no pi, no sqrt)" % k_star)
    num, den = short.numerator, short.denominator
    scaled = (num * 10 ** 12) // den
    print("  p(k*) exact = %d-digit-num / %d-digit-den rational; "
          "shortfall 1 - p = %d.%012d x 10^-... (= %s / %s exactly)" %
          (len(str(p_star.numerator)), len(str(p_star.denominator)),
           scaled // 10 ** 12, scaled % 10 ** 12,
           str(num)[:12] + "...", str(den)[:12] + "..."))
    print("  shortfall as scaled integer: %d parts per 10^12" % scaled)

    lane_ns, vec_ns, kL, Nv = timings()
    print("\nPer-iteration cost:")
    print("  lane-tracked (%d lanes, any N, any depth): %d ns" % (kL, lane_ns))
    print("  full state vector at N=%d:                %d ns" % (Nv, vec_ns))
    print("  (vector cost scales with N; lane cost does not)")
    print("\nTOTAL checks=%d breaks=%d" % (total_c, total_b))


if __name__ == "__main__":
    main()
