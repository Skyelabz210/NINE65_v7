"""Finite integer witnesses from ARITHMETIC_CRYPTO_CONNECTIONS.md.
Not an encrypted execution or formal proof.
"""
from math import gcd, prod

for x in range(-200, 201):
    for d in range(2, 14):
        for e in range(2, 14):
            q, r = divmod(x, d)
            qq, rr = divmod(q, e)
            assert qq == x // (d*e) == (x // e) // d
            assert x % (d*e) == r + d*rr

nearest = lambda x, d: (x + d//2) // d
assert nearest(nearest(2, 3), 2) == 1
assert nearest(2, 6) == 0

for w in range(1, 8):
    for a in range(1 << w):
        for b in range(1 << w):
            x, y = a, b
            for _ in range(2*w):
                q, r = divmod(x, y) if y else (0, x)
                x, y = (y, r) if y else (x, 0)
            assert y == 0 and x == gcd(a, b)

for p in (5, 7, 11):
    for B in range(1, (p-1)//2 + 1):
        roots = list(range(-B, B+1))
        def G(x):
            return prod(x-r for r in roots)
        def H(x):
            total = 0
            for r in roots:
                derivative = prod(r-s for s in roots if s != r) % p
                numerator = prod(x-s for s in roots if s != r) % p
                total = (total + numerator*pow(derivative, -2, p)) % p
            return total
        def F(x):
            return (x-G(x)*H(x)) % (p*p)
        for r in roots:
            for k in range(-p, p+1):
                x = r+p*k
                assert ((G(x) % (p*p))//p * H(x)) % p == k % p
                assert F(x) == r % (p*p)
                assert F(F(x)) == F(x)
print("PASS: floor=57744; fixed_euclid=21844; GH_retraction=1118; rounding_negative=1")
