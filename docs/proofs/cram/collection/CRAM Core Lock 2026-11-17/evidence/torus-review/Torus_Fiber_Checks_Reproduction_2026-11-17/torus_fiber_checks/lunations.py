# Where does the 'shadow prime' 23 come from?  Integer-only: synodic month as the exact rational 29530589/1000000 days.
def fac(n):
    f = {}; d = 2
    while d * d <= n:
        while n % d == 0: f[d] = f.get(d, 0) + 1; n //= d
        d += 1
    if n > 1: f[n] = f.get(n, 0) + 1
    return f
S0 = {2, 3, 5, 7, 13, 37, 73}
print("lunations n | days D(n)=round(n*29.530589) | factorization | primes outside S0 | n*29530589 mod 10^6 offset (millionths of a day)")
for n in range(398, 412):
    num = n * 29530589; D = (2 * num + 1000000) // 2000000         # round half up of num/10^6, integers only
    f = fac(D); out = sorted(p for p in f if p not in S0)
    print(f"{n:>11} | {D:>8} | {str(f):<34} | {out} | {num - D * 1000000}")
from math import gcd
g = gcd(11960, 405); print("11960/405 reduced =", f"{11960 // g}/{405 // g}", "; numerator factors", fac(11960 // g), "; denominator", fac(405 // g))
# check the 'one rule' behind the Ramanujan classes
print("24*beta mod l for (l,beta)=(5,4),(7,5),(11,6):", [(24 * b) % l for l, b in ((5, 4), (7, 5), (11, 6))], "; 24^-1 mod 385 =", pow(24, -1, 385))
