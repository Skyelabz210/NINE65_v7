"""Executable discovery models; integer/rational research, not FHE code.

The query compiler imports verified integer normal-form certificates. Runtime
readouts receive observations only. Full sources are used by the test oracle.
"""
from dataclasses import dataclass
from fractions import Fraction
from math import gcd, comb


def matmul(a, b):
    if not a or not b or any(len(row) != len(b) for row in a):
        raise ValueError("incompatible matrices")
    return [[sum(x*y for x, y in zip(row, col)) for col in zip(*b)] for row in a]


def determinant(a):
    n = len(a)
    if any(len(row) != n for row in a):
        raise ValueError("matrix must be square")
    if n == 0:
        return 1
    if n == 1:
        return a[0][0]
    return sum((-1)**j * a[0][j] * determinant(
        [row[:j] + row[j+1:] for row in a[1:]]) for j in range(n))


@dataclass(frozen=True)
class QueryDecoder:
    modulus: int
    weights: tuple[int, ...]

    def evaluate(self, observation):
        if len(observation) != len(self.weights):
            raise ValueError("wrong observation dimension")
        if any(type(x) is not int for x in observation):
            raise ValueError("integer observations required")
        return sum(w*y for w, y in zip(self.weights, observation)) % self.modulus


@dataclass(frozen=True)
class QueryObstruction:
    modulus: int
    kernel_witness: tuple[int, ...]
    target_delta: int


def compile_integer_query(b, c, modulus, u, v):
    """Compile c*x mod modulus from B*x mod modulus, or return a collision.

    U,V are public integer unimodular certificates with U*B*V diagonal.
    Constructing those certificates is an upstream normal-form operation.
    This small reference verifier supports dimensions 1..6 and uses cofactor
    determinants; it is not a polynomial-time implementation claim.
    """
    if type(modulus) is not int or modulus < 1:
        raise ValueError("positive modulus required")
    r, n = len(b), len(c)
    if not (1 <= r <= 6 and 1 <= n <= 6):
        raise ValueError("reference dimensions must be 1..6")
    if (any(len(row) != n for row in b) or len(u) != r or
            any(len(row) != r for row in u) or len(v) != n or
            any(len(row) != n for row in v)):
        raise ValueError("invalid matrix dimensions")
    if any(type(x) is not int for matrix in (b, u, v) for row in matrix for x in row):
        raise ValueError("integer matrices required")
    if any(type(x) is not int for x in c):
        raise ValueError("integer query required")
    if abs(determinant(u)) != 1 or abs(determinant(v)) != 1:
        raise ValueError("normal-form multipliers must be unimodular")
    s = matmul(matmul(u, b), v)
    if any(s[i][j] != 0 for i in range(r) for j in range(n) if i != j):
        raise ValueError("certificate does not diagonalize B")
    t = matmul([list(c)], v)[0]
    w = [0] * r
    for j in range(n):
        diagonal = s[j][j] if j < r else 0
        g = gcd(diagonal, modulus)
        if t[j] % g:
            z = [0] * n
            z[j] = modulus // g
            witness = tuple(sum(v[i][k] * z[k] for k in range(n)) % modulus
                            for i in range(n))
            delta = sum(ci * xi for ci, xi in zip(c, witness)) % modulus
            assert delta != 0
            return QueryObstruction(modulus, witness, delta)
        reduced = modulus // g
        if j < r and reduced != 1:
            w[j] = (t[j] // g * pow(diagonal // g, -1, reduced)) % reduced
    weights = tuple(x % modulus for x in matmul([w], u)[0])
    return QueryDecoder(modulus, weights)


@dataclass(frozen=True)
class AdjacentFrame:
    main: int

    def __post_init__(self):
        if type(self.main) is not int or self.main < 2:
            raise ValueError("main must be at least 2")

    @property
    def anchor(self):
        return self.main + 1

    @property
    def capacity(self):
        return self.main * self.anchor


def observe_point(point, frame):
    """Declared clear ingress; consumers below do not receive this point."""
    return tuple(tuple(x % m for x in point) for m in (frame.main, frame.anchor))


def orientation_from_views(points, coordinate_bound, frame):
    """Return sign of oriented area, without constructing its full determinant.

    Producer contract: three points have coordinates within [-H,H].
    The public conservative determinant bound is B=8H².
    """
    if type(coordinate_bound) is not int or coordinate_bound < 0:
        raise ValueError("nonnegative coordinate bound required")
    bound = 8 * coordinate_bound**2
    if 2 * bound >= frame.capacity:
        raise ValueError("insufficient signed determinant capacity")
    if len(points) != 3 or any(len(p) != 2 or any(len(lane) != 2 for lane in p) for p in points):
        raise ValueError("three two-lane planar observations required")
    observed = []
    for lane, modulus in enumerate((frame.main, frame.anchor)):
        a, b, c = (p[lane] for p in points)
        if any(type(x) is not int or not 0 <= x < modulus for point in (a,b,c) for x in point):
            raise ValueError("noncanonical lane input")
        determinant_residue = ((b[0]-a[0])*(c[1]-a[1]) -
                               (b[1]-a[1])*(c[0]-a[0])) % modulus
        observed.append((determinant_residue + bound) % modulus)
    remainder, anchor = observed
    quotient = (remainder-anchor) % frame.anchor
    actual_pair = (quotient, remainder)
    threshold_pair = divmod(bound, frame.main)
    return (actual_pair > threshold_pair) - (actual_pair < threshold_pair)


def bbs_residue_step(bits, frame):
    """Actual one-sided empty-carrier BBS evolution using only residue state.

    At most len(bits) balls may be carried. End-of-buffer carry is allowed;
    append at least that many empty boxes to observe all outgoing balls.
    """
    if len(bits) >= frame.capacity or any(type(x) is not int or x not in (0,1) for x in bits):
        raise ValueError("binary input and sufficient public carrier capacity required")
    main = anchor = 0
    result = []
    readings = [(main, anchor)]
    for bit in bits:
        empty = main == 0 and anchor == 0
        outgoing = int(bit == 0 and not empty)
        increment = bit-outgoing
        main = (main+increment) % frame.main
        anchor = (anchor+increment) % frame.anchor
        result.append(outgoing)
        readings.append((main, anchor))
    return tuple(result), tuple(readings)


def heights(bits):
    result = [0]
    for bit in bits:
        result.append(result[-1] + 1 - 2*bit)
    return tuple(result)


def discrete_pitman(path):
    maximum = path[0]
    result = []
    for h in path:
        maximum = max(maximum, h)
        result.append(2*maximum-h)
    return tuple(result)


def interpolate(path, t):
    t = Fraction(t)
    if not 0 <= t <= len(path)-1:
        raise ValueError("outside interpolation domain")
    n = t.numerator // t.denominator
    if n == len(path)-1:
        return Fraction(path[n])
    return Fraction(path[n]) + (t-n)*(path[n+1]-path[n])


def continuous_pitman(path, t):
    t = Fraction(t)
    value = interpolate(path, t)
    n = t.numerator // t.denominator
    maximum = max(*path[:n+1], value)
    return 2*maximum-value


def centered_theta_indices(q, z):
    """Independent finite bracket containing all minimizers for Q>0."""
    if q <= 0:
        raise ValueError("positive Q required")
    center = (-z) // q
    candidates = range(center-2, center+3)
    values = {n: q*n*n+2*n*z for n in candidates}
    optimum = min(values.values())
    return tuple(n for n in candidates if values[n] == optimum)


def hensel_step(coefficients, p, exponent, a):
    """One simple-root precision step, public clear polynomial model."""
    if p < 2 or exponent < 1:
        raise ValueError("modulus>=2 and positive exponent required")
    evaluate = lambda x: sum(c*x**i for i,c in enumerate(coefficients))
    derivative = sum(i*c*a**(i-1) for i,c in enumerate(coefficients) if i)
    power = p**exponent
    if evaluate(a) % power or gcd(derivative, p) != 1:
        raise ValueError("root or derivative-unit certificate failed")
    correction = (-(evaluate(a)//power)*pow(derivative, -1, p)) % p
    return (a + power*correction) % (power*p)


def hasse_at(coefficients, point, order, modulus):
    if order < 0 or modulus < 2:
        raise ValueError("nonnegative order and modulus>=2 required")
    return sum(comb(i,order)*c*point**(i-order)
               for i,c in enumerate(coefficients) if i >= order) % modulus


def jet_quotient_query(source_jet, reference_jet, multiplier_jet, modulus):
    """Given authentic order-nu jets and lower vanishing of multiplier M.

    If M=(t-a)^nu U and U(a) is a unit, return K(a) from X=r+M*K.
    This function cannot validate the external lower-jet/source certificates.
    """
    if modulus < 2 or gcd(multiplier_jet, modulus) != 1:
        raise ValueError("unit multiplier jet required")
    return ((source_jet-reference_jet)*pow(multiplier_jet,-1,modulus)) % modulus
