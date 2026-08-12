"""Shim for missing cramlab: gen_lanes(n) -> (first n odd primes >= 3, product)."""
def gen_lanes(count):
    lanes, n = [], 3
    while len(lanes) < count:
        p = n
        d = 3
        ok = p % 2 == 1
        while ok and d * d <= p:
            if p % d == 0: ok = False
            d += 2
        if ok and p > 2: lanes.append(p)
        n += 2
    prod = 1
    for p in lanes: prod *= p
    return lanes, prod
