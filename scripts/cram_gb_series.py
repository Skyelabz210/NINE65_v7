"""Exact lazy first-negative coefficient for the upstream GB cost model.

F(z) = prod((1-z**d)**m)/(1-z)**n.  With Q(z)=(1-z)*prod(1-z**d),
logarithmic differentiation gives Q F' = P F.  Equating coefficients
computes each integer coefficient using a fixed sparse recurrence and stops
at the SAME first negative coefficient as the full rational power series.
This changes evaluation cost, not the estimator's attack or cost model.
"""

from math import comb


def _times_one_minus_power(values, degree):
    result = values + [0] * degree
    for i, value in enumerate(values):
        result[i + degree] -= value
    return result


def first_negative(n, equations, precision=None):
    if not isinstance(n, int) or n < 0:
        raise ValueError("nonnegative integer dimension required")
    precision = 2 * n if precision is None else precision
    if not isinstance(precision, int) or precision < 0:
        raise ValueError("nonnegative integer precision required")
    multiplicities = {}
    for degree, count in equations:
        if not isinstance(degree, int) or degree < 1 or not isinstance(count, int) or count < 0:
            raise ValueError("positive integer degrees and nonnegative integer multiplicities required")
        if count and degree < precision:
            multiplicities[degree] = multiplicities.get(degree, 0) + count
    product = [1]
    for degree in multiplicities:
        product = _times_one_minus_power(product, degree)
    denominator = _times_one_minus_power(product, 1)
    numerator = [n * value for value in product]
    for degree, count in multiplicities.items():
        other = [1, -1]
        for other_degree in multiplicities:
            if other_degree != degree:
                other = _times_one_minus_power(other, other_degree)
        required = degree - 1 + len(other)
        numerator.extend([0] * max(0, required - len(numerator)))
        for i, value in enumerate(other):
            numerator[i + degree - 1] -= count * degree * value
    support = []
    for i in range(1, max(len(denominator), len(numerator) + 1)):
        p = numerator[i - 1] if i - 1 < len(numerator) else 0
        q = denominator[i] if i < len(denominator) else 0
        if p or q:
            support.append((i, p, q))
    coefficients = [1]
    for k in range(1, precision):
        total = sum((p - q * (k - i)) * coefficients[k - i]
                    for i, p, q in support if i <= k)
        coefficient, remainder = divmod(total, k)
        if remainder:
            raise ArithmeticError("formal integer coefficient recurrence was not exact")
        if coefficient < 0:
            return k
        coefficients.append(coefficient)
    return None


def upstream_compatibility_cases():
    # Includes coincident degrees, zero counts, non-default precision and
    # series with no negative coefficient before the cutoff.
    return [(n, [(d, m), (3, n)], 2, None)
            for n in (4, 8, 16, 32)
            for d, m in ((2, 0), (2, n), (3, 2*n), (5, n**5))] + [
                (12, [(2, 24)], 3, 32), (16, [(40, 100)], 2, 20)]


def install_verified_upstream_adapter(module):
    """Sage-only adapter: verify against the pinned ORIGINAL implementation."""
    from sage.all import binomial, oo
    original = module.gb_cost
    calls = {"count": 0, "maximum_dimension": 0}

    def accelerated(n, D, omega=2, prec=None):
        dimension = int(n)
        converted = [(int(d), int(m)) for d, m in D]
        if dimension != n or any(d != old_d or m != old_m
                                 for (d, m), (old_d, old_m) in zip(converted, D)):
            return original(n, D, omega=omega, prec=prec)
        precision = None if prec is None else int(prec)
        if precision is not None and precision != prec:
            return original(n, D, omega=omega, prec=prec)
        dreg = first_negative(dimension, converted, precision)
        result = module.Cost(rop=oo, dreg=oo)
        result.register_impermanent({"rop": True, "dreg": False, "mem": False})
        if dreg is not None:
            result["dreg"] = dreg
            result["rop"] = binomial(n + dreg, dreg) ** omega
            result["mem"] = binomial(n + dreg, dreg) ** 2
        calls["count"] += 1
        calls["maximum_dimension"] = max(calls["maximum_dimension"], dimension)
        return result

    cases = upstream_compatibility_cases()
    for n, equations, omega, precision in cases:
        expected = original(n, equations, omega=omega, prec=precision)
        actual = accelerated(n, equations, omega=omega, prec=precision)
        if dict(expected) != dict(actual):
            raise ArithmeticError("exact series recurrence disagreed with pinned upstream GB cost")
    module.gb_cost = accelerated
    return {"method": "exact_sparse_logarithmic_derivative_recurrence",
            "upstream_cost_model_unchanged": True,
            "original_upstream_compatibility_cases": len(cases), "calls": calls}


def direct_first_negative(n, equations, precision):
    """Independent truncated binomial expansion, for small verification cases."""
    values = [comb(n + k - 1, k) if n else int(k == 0) for k in range(precision)]
    for degree, count in equations:
        result = [0] * precision
        for j in range(min(count, (precision - 1) // degree) + 1):
            scalar = (-1)**j * comb(count, j)
            for k in range(precision - degree * j):
                result[k + degree*j] += scalar * values[k]
        values = result
    return next((i for i, value in enumerate(values) if value < 0), None)
