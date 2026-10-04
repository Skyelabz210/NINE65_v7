#!/usr/bin/env python3
"""Exact public-constant construction for a bounded p-adic digit polynomial.

This constructs a polynomial, not a ciphertext evaluator or an input-noise
certificate. It does not authorize NINE65's currently disabled public refresh.
All calculations use integers. Run with --self-test for independent checks.
"""

import argparse
import json
import math


def multiply(a, b, modulus):
    out = [0] * (len(a) + len(b) - 1)
    for i, left in enumerate(a):
        for j, right in enumerate(b):
            out[i + j] = (out[i + j] + left * right) % modulus
    return out


def evaluate(coefficients, x, modulus):
    out = 0
    for coefficient in reversed(coefficients):
        out = (out * x + coefficient) % modulus
    return out


def derivative(coefficients):
    return [i * coefficients[i] for i in range(1, len(coefficients))]


def construct(p, bound):
    if p < 3 or p % 2 == 0 or any(p % d == 0 for d in range(3, math.isqrt(p) + 1, 2)):
        raise ValueError("p must be an odd prime")
    if not 0 <= 2 * bound < p:
        raise ValueError("support must satisfy 0 <= 2B < p")
    modulus = p * p
    roots = range(-bound, bound + 1)
    g = [1]
    for root in roots:
        g = multiply(g, [-root, 1], modulus)
    # H(r)=1/G'(r) over F_p. The Lagrange basis for r is
    # G(X)/((X-r)G'(r)), giving the squared inverse below.
    h = [0] * (len(g) - 1)
    for root in roots:
        quotient = [0] * (len(g) - 1)
        quotient[-1] = g[-1] % p
        for i in range(len(quotient) - 2, -1, -1):
            quotient[i] = (g[i + 1] + root * quotient[i + 1]) % p
        assert (g[0] + root * quotient[0]) % p == 0
        inverse = pow(evaluate(quotient, root, p), -1, p)
        for i, coefficient in enumerate(quotient):
            h[i] = (h[i] + coefficient * inverse * inverse) % p
    f = [(-coefficient) % modulus for coefficient in multiply(g, h, modulus)]
    if len(f) < 2:
        f.append(0)
    f[1] = (f[1] + 1) % modulus
    while len(f) > 1 and f[-1] == 0:
        f.pop()
    return f


def certify(coefficients, p, bound):
    # These finite exact identities imply the claim for EVERY m, by
    # F(r+pm)=F(r)+pm F'(r) mod p^2. This is stronger than sampling m.
    d = derivative(coefficients)
    values = all(evaluate(coefficients, r, p * p) == r % (p * p)
                 for r in range(-bound, bound + 1))
    slopes = all(evaluate(d, r, p) == 0 for r in range(-bound, bound + 1))
    if not values or not slopes:
        raise ValueError("polynomial failed its exact value/derivative certificate")
    return {
        "value_identities": 2 * bound + 1,
        "derivative_identities": 2 * bound + 1,
        "implied_domain_elements": p * (2 * bound + 1),
        "identity": "F(r+p*m) = r (mod p^2), for -B <= r <= B and every m",
    }


def self_test():
    # Exhaustive independent evaluation, including wrapped negative residues.
    checks = 0
    for p in [3, 5, 7, 17, 31]:
        for bound in range((p - 1) // 2 + 1):
            f = construct(p, bound)
            certify(f, p, bound)
            for r in range(-bound, bound + 1):
                for m in range(p):
                    assert evaluate(f, r + p * m, p * p) == r % (p * p)
                    checks += 1
            corrupt = f.copy()
            corrupt[0] = (corrupt[0] + 1) % (p * p)
            try:
                certify(corrupt, p, bound)
            except ValueError:
                pass
            else:
                raise AssertionError("corrupted polynomial was accepted")
            # Preserve all root values while corrupting their derivatives.
            g = [1]
            for r in range(-bound, bound + 1):
                g = multiply(g, [-r, 1], p * p)
            corrupt = f + [0] * max(0, len(g) - len(f))
            for i, coefficient in enumerate(g):
                corrupt[i] = (corrupt[i] + coefficient) % (p * p)
            try:
                certify(corrupt, p, bound)
            except ValueError:
                pass
            else:
                raise AssertionError("corrupted derivative was accepted")
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--p", type=int, default=65537)
    parser.add_argument("--bound", type=int, default=32)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.p > 65537 or args.bound > 128:
        parser.error("this research tool limits p to 65537 and B to 128")
    f = construct(args.p, args.bound)
    result = {
        "schema": "nine65-bounded-digit-polynomial-v1",
        "p": args.p, "bound": args.bound, "degree": len(f) - 1,
        "degree_upper_bound": 4 * args.bound + 1,
        "coefficients_ascending_mod_p_squared": f,
        "certificate": certify(f, args.p, args.bound),
        "exhaustive_small_prime_checks": self_test() if args.self_test else None,
        "required_unproved_input_condition": "actual hidden phase error lies in [-B,B]",
        "native_ciphertext_evaluator_implemented": False,
        "public_refresh_enabled": False,
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
