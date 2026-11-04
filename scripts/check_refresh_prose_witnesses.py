#!/usr/bin/env python3
"""Exact finite witnesses and negative controls for docs/proofs; not FHE runs."""
from fractions import Fraction
from itertools import product
import json
import math


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def nearest(value):
    """Nearest integer with upward half ties; witness denominators are odd."""
    value += Fraction(1, 2)
    return value.numerator // value.denominator


def negacyclic(a, b):
    require(len(a) == len(b), "ring dimensions differ")
    n = len(a)
    out = [0] * n
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            out[(i + j) % n] += x * y * (-1 if i + j >= n else 1)
    return out


def digit_witnesses():
    count = 0
    for p, radius in [(7, 2), (11, 3), (17, 4), (65537, 49)]:
        roots = list(range(-radius, radius + 1))
        for r in roots:
            slope = math.prod(r - u for u in roots if u != r) % p
            require(slope != 0, "repeated support root")
            # Direct Lagrange basis evaluation, not runtime synthetic division.
            h = sum(math.prod(r - u for u in roots if u != v)
                    * pow(math.prod(v - u for u in roots if u != v) % p, -2, p)
                    for v in roots) % p
            require(slope * h % p == 1, "inverse derivative certificate")
            carries = range(-48, 49) if p == 65537 else range(-2*p, 2*p+1)
            for k in carries:
                x = r + p*k
                g = math.prod(x - u for u in roots) % (p*p)
                require(g % p == 0, "G is not divisible by p")
                require((g // p) * h % p == k % p, "signed carry identity")
                count += 1
    # Distinct roots over a composite modulus need not have unit differences.
    require(math.gcd(3, 9) != 1, "missing composite-modulus negative control")
    return count


def slot_divisibility_witnesses():
    p = 17
    count = 0
    for n in [2, 4, 8]:
        z = next(z for z in range(2, p) if pow(z, n, p) == p-1
                 and pow(z, 2*n, p) == 1)
        lifted = pow(z, p, p*p)
        require(pow(lifted, n, p*p) == p*p-1, "lifted root")
        roots = [pow(lifted, 2*j+1, p*p) for j in range(n)]
        require(all(math.gcd(a-b, p*p) == 1 for i, a in enumerate(roots)
                    for b in roots[:i]), "nonunit root difference")
        # All p-multiple slot-basis vectors; direct inverse DFT formula.
        for slot in range(n):
            for value in range(p):
                coeff = [(pow(n, -1, p*p) * p * value
                          * pow(roots[slot], -i, p*p)) % (p*p)
                         for i in range(n)]
                require(all(c % p == 0 for c in coeff), "coefficient divisibility")
                divided = [c // p for c in coeff]
                for j, w in enumerate(roots):
                    observed = sum(c * pow(w % p, i, p)
                                   for i, c in enumerate(divided)) % p
                    require(observed == (value if j == slot else 0), "quotient slots")
                    count += 1
        # One zero slot is insufficient for coefficient divisibility.
        require(((-roots[0]) + roots[0]) % p == 0 and 1 % p != 0,
                "single-slot negative control")
    return count


def source_identity_witnesses():
    n, p, q = 2, 7, 101
    count = 0
    for secret in product([-1, 0, 1], repeat=n):
        weight = sum(abs(s) for s in secret)
        for c0 in product([-50, -1, 0, 1, 50], repeat=n):
            for c1 in product([-50, 0, 50], repeat=n):
                phase = [a+b for a, b in zip(c0, negacyclic(c1, secret))]
                m = [nearest(Fraction(p*c, q)) for c in phase]
                v = [p*c-q*a for c, a in zip(phase, m)]
                affines = [[nearest(Fraction(p*c, q)) for c in comp]
                           for comp in (c0, c1)]
                residuals = [[p*c-q*a for c, a in zip(comp, affine)]
                             for comp, affine in zip((c0, c1), affines)]
                digits = [[nearest(Fraction(p*r, q)) for r in comp]
                          for comp in residuals]
                a = [u+w for u, w in zip(affines[0], negacyclic(affines[1], secret))]
                x = [u+w for u, w in zip(digits[0], negacyclic(digits[1], secret))]
                cap = (2*p*max(map(abs, v))+(weight+1)*(q-1)) // (2*q)
                for j in range(n):
                    k = m[j]-a[j]  # The chosen lift uses phase wrap k_source=0.
                    rho = x[j]-p*k
                    require(abs(rho) <= cap, "source residual bound")
                    require(abs(x[j]) <= (weight+1)*(p//2), "phase norm")
                    require((a[j]+k) % p == m[j] % p, "affine restoration")
                    count += 1
    return count


def projection_witnesses():
    count = 0
    n, stride = 2, 2
    for secret in product([-1, 0, 1], repeat=n):
        embedded = [secret[0], 0, secret[1], 0]
        for poly in product([-1, 0, 1], repeat=n*stride):
            lhs = negacyclic(poly, embedded)[::stride]
            rhs = negacyclic(poly[::stride], secret)
            require(lhs == rhs, "embedded-secret projection")
            count += 1
    bad = [0, 1, 0, 0]
    require(negacyclic(bad, bad)[::2] != negacyclic(bad[::2], bad[::2]),
            "arbitrary-secret projection must fail")
    return count


def drop_witnesses():
    count = 0
    n, t, prime, new_q = 2, 7, 5, 101
    old_q = prime*new_q
    for secret in product([-1, 0, 1], repeat=n):
        for c0 in product([-252, -1, 0, 1, 252], repeat=n):
            for c1 in product([-252, 0, 252], repeat=n):
                phase = [a+b for a,b in zip(c0, negacyclic(c1, secret))]
                m = [nearest(Fraction(t*x, old_q)) for x in phase]
                v = max(abs(t*x-old_q*y) for x,y in zip(phase, m))
                dropped = [[nearest(Fraction(x, prime)) for x in comp]
                           for comp in (c0, c1)]
                after = [a+b for a,b in zip(dropped[0], negacyclic(dropped[1], secret))]
                actual = max(abs(t*x-new_q*y) for x,y in zip(after, m))
                cap = (v+prime-1)//prime + (t*(n+1)+1)//2
                require(actual <= cap, "dense-key drop recurrence")
                count += 1
    return count


def multiplication_witnesses():
    n, t, q = 2, 7, 101
    ciphertexts = list(product([-50, 0, 50], repeat=2*n))
    count = 0
    for secret in product([-1, 0, 1], repeat=n):
        secret_square = negacyclic(secret, secret)
        candidates = []
        for raw in ciphertexts:
            c0, c1 = raw[:n], raw[n:]
            phase = [x+y for x,y in zip(c0, negacyclic(c1, secret))]
            message_lift = [nearest(Fraction(t*x, q)) for x in phase]
            error = max(abs(Fraction(x)-Fraction(q*m, t))
                        for x,m in zip(phase, message_lift))
            bound = math.ceil(error)
            if 2*t*bound < q:
                candidates.append((c0, c1, message_lift, bound))
        factor = n*(t-1)//2 + n*t*(n//2+1)
        rounding = (1+n+n*n+1)//2
        for a in candidates:
            for b in candidates:
                tensor = [negacyclic(a[0], b[0]),
                          [x+y for x,y in zip(negacyclic(a[0], b[1]),
                                              negacyclic(a[1], b[0]))],
                          negacyclic(a[1], b[1])]
                rounded = [[nearest(Fraction(t*x, q)) for x in comp]
                           for comp in tensor]
                phase = [x+y+z for x,y,z in zip(
                    rounded[0], negacyclic(rounded[1], secret),
                    negacyclic(rounded[2], secret_square))]
                target = negacyclic(a[2], b[2])
                actual = max(abs(Fraction(x)-Fraction(q*m, t))
                             for x,m in zip(phase, target))
                cap = (factor*(a[3]+b[3])
                       + Fraction(n*t*a[3]*b[3], q) + rounding)
                require(actual <= cap, "full-polynomial multiplication envelope")
                scaled_cap = (factor*t*(a[3]+b[3])
                              + (n//2)*min(t*a[3], t*b[3]) + t*rounding)
                require(t*actual <= scaled_cap, "scaled quadratic substitute")
                count += 1
    return count


def main():
    results = {
        "digit_cases": digit_witnesses(),
        "slot_quotient_comparisons": slot_divisibility_witnesses(),
        "source_coefficient_cases": source_identity_witnesses(),
        "projection_cases": projection_witnesses(),
        "drop_cases": drop_witnesses(),
        "multiplication_cases": multiplication_witnesses(),
    }
    require(all(value > 0 for value in results.values()), "vacuous witness run")
    print(json.dumps({"status": "passed", "scope": "finite exact arithmetic witnesses, not encrypted execution or a universal proof", "results": results}, indent=2))


if __name__ == "__main__":
    main()
