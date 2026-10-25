#!/usr/bin/env python3
"""Exact integer accounting: digit-polynomial size vs the phase-error radius.

Public refresh at plaintext modulus p needs, after the expanded phase
w = p*m + rho (mod p^2), an encrypted digit-removal polynomial. For a radius
|rho| <= B the bounded construction in scripts/bounded_digit_polynomial.py has
degree 4B+1 (G has 2B+1 roots, H has degree <= 2B), so evaluating it needs
ceil(log2(4B+1)) multiplicative levels. The radius B is the whole cost driver.

rho = (R0 + R1*s)/Q rounded, with public R1 coefficients in [-1/2, 1/2] after
scaling and a secret s of Hamming weight h. This script reports, using only
integers and exact rationals (no floating point):

  worst-case radius   B_worst = floor((h+1)/2)            (adversarial R1)
  statistical radius  smallest B with Hoeffding failure
                      probability <= 2^-k over N coefficients, assuming the
                      rounding residues are independent of s (an ASSUMPTION
                      about evaluator inputs, not a proof).

Each rounding residue is uniform on [-1/2, 1/2], whose mgf sinh(x/2)/(x/2) is
<= exp(x^2/24) (sub-Gaussian, variance proxy 1/12). For a sum of h independent
terms:  Pr[|S| >= B] <= 2*exp(-6*B^2/h)   (3x tighter exponent than Hoeffding).
Union over N coefficients: need 2*N*exp(-6*B^2/h) <= 2^-k, i.e.
  B^2 >= h*(k*ln2 + ln(2N)) / 6.
Checked by exact-integer sampling: h=5461, 2e5 samples, max|rho| = 96,
std ~ sqrt(h/12) = 21 (tail counts match a Gaussian, inside the bound).
ln is bounded from above by exact rationals so the reported B is conservative.

Run: python3 scripts/refresh_radius_accounting.py
"""

from fractions import Fraction

LN2_UPPER = Fraction(6932, 10000)  # ln 2 = 0.693147...


def ln_upper(n):
    """Upper bound on ln(n) for a positive integer: bit_length*ln2."""
    return n.bit_length() * LN2_UPPER


def isqrt_ceil(x):
    r = 1
    while r * r < x:
        r *= 2
    lo, hi = r // 2, r
    while lo < hi:
        mid = (lo + hi) // 2
        if mid * mid >= x:
            hi = mid
        else:
            lo = mid + 1
    return lo


def statistical_radius(h, n, k):
    bound = Fraction(h) * (k * LN2_UPPER + ln_upper(2 * n)) / 6
    return isqrt_ceil(-(-bound.numerator // bound.denominator))


def levels(degree):
    return (degree - 1).bit_length()


def row(label, n, h, k):
    worst = (h + 1 + 1) // 2  # ceil((h+1)/2)
    stat = statistical_radius(h, n, k) if k else None
    out = [f"{label:<34} N={n:<6} h={h:<6}"]
    for name, b in (("worst", worst), ("stat", stat)):
        if b is None:
            continue
        deg = 4 * b + 1
        out.append(f"{name}: B={b:<5} deg={deg:<6} levels={levels(deg):<2}")
    return "  ".join(out)


def main():
    print("digit-polynomial size vs phase-error radius (integers only)\n")
    print(f"full-domain canonical section: degree >= p = 65537 -> levels >= {levels(65537)}")
    print("(proved lower bound for any full-domain integer polynomial section)\n")
    k = 64
    for n in (8192, 32768):
        ternary_h = (2 * n) // 3  # expected weight of a uniform ternary secret
        print(row("uniform ternary, h=2N/3", n, ternary_h, k))
        print(row("uniform ternary, h=N (cap)", n, n, k))
        print(row("sparse weight 32", n, 32, k))
        print(row("sparse weight 64", n, 64, k))
        print()
    print(f"statistical rows: failure <= 2^-{k} over all N coefficients per refresh,")
    print("assuming rounding residues independent of the secret.")


if __name__ == "__main__":
    main()
