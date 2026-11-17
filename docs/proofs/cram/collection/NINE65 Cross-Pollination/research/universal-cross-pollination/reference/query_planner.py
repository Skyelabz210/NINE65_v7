"""Public-parameter reference planner for exact integer queries.

This module consumes moduli, query descriptions and public costs, never a
secret value, a residue reading, or a winding. It does not create new source
observations. It is research tooling, not a ciphertext evaluator.
"""

from dataclasses import asdict, dataclass
from functools import reduce
from math import gcd, lcm
from typing import Iterable


def positive(value: int, name: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


@dataclass(frozen=True)
class LinearQuery:
    """The query x |-> (coefficient*x + offset) mod modulus on all Z."""

    coefficient: int
    modulus: int
    offset: int = 0

    def __post_init__(self) -> None:
        positive(self.modulus, "modulus")
        if type(self.coefficient) is not int or type(self.offset) is not int:
            raise ValueError("coefficient and offset must be integers")

    @property
    def period(self) -> int:
        return self.modulus // gcd(self.coefficient, self.modulus)

    def before_affine(self, scale: int, shift: int) -> "LinearQuery":
        """Pull query demand backward through x |-> scale*x + shift."""
        if type(scale) is not int or type(shift) is not int:
            raise ValueError("scale and shift must be integers")
        return LinearQuery(self.coefficient * scale, self.modulus,
                           self.coefficient * shift + self.offset)


@dataclass(frozen=True)
class QuotientQuery:
    """The Euclidean quotient query x |-> floor(x/divisor) mod modulus."""

    divisor: int
    modulus: int

    def __post_init__(self) -> None:
        positive(self.divisor, "divisor")
        positive(self.modulus, "modulus")

    @property
    def period(self) -> int:
        return 1 if self.modulus == 1 else self.divisor * self.modulus


Query = LinearQuery | QuotientQuery


def observation_period(moduli: Iterable[int]) -> int:
    """LCM accounts for overlap; empty observations have period 1."""
    return reduce(lcm, (positive(m, "observation modulus") for m in moduli), 1)


def demand_period(queries: Iterable[Query]) -> int:
    return reduce(lcm, (q.period for q in queries), 1)


def minimal_extra_anchor(period: int, demand: int) -> int:
    """Least anchor under divisibility with demand | lcm(period, anchor).

    No factorization is required: start from the missing factor, then saturate
    its prime support inside demand by repeated gcd(demand, anchor**2).
    The loop uses public integers only. 1 means no new observation is needed.
    """
    positive(period, "period")
    positive(demand, "demand")
    anchor = demand // gcd(period, demand)
    while True:
        enlarged = gcd(demand, anchor * anchor)
        if enlarged == anchor:
            return anchor
        anchor = enlarged


@dataclass(frozen=True)
class QueryPlan:
    source_moduli: tuple[int, ...]
    queries: tuple[Query, ...]
    source_period: int
    demand: int
    extra_anchor: int
    combined_period: int

    def verifies(self) -> bool:
        """Recompute the public certificate; does not attest actual readings."""
        try:
            p = observation_period(self.source_moduli)
            d = demand_period(self.queries)
            a = minimal_extra_anchor(p, d)
            return (self.source_period, self.demand, self.extra_anchor,
                    self.combined_period) == (p, d, a, lcm(p, a))
        except (ValueError, TypeError, AttributeError):
            return False


def plan_queries(moduli: Iterable[int], queries: Iterable[Query]) -> QueryPlan:
    moduli, queries = tuple(moduli), tuple(queries)
    p, d = observation_period(moduli), demand_period(queries)
    a = minimal_extra_anchor(p, d)
    return QueryPlan(moduli, queries, p, d, a, lcm(p, a))


@dataclass(frozen=True)
class Candidate:
    """An available authentic observation producer and its public cost."""

    name: str
    modulus: int
    cost: int

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("candidate needs a name")
        positive(self.modulus, "candidate modulus")
        positive(self.cost, "candidate cost")


@dataclass(frozen=True)
class Selection:
    selected: tuple[str, ...]
    cost: int
    combined_period: int
    demand: int


def choose_available(moduli: Iterable[int], queries: Iterable[Query],
                     candidates: Iterable[Candidate]) -> Selection | None:
    """Exact minimum public-cost subset; tie-break by count then name.

    DP state is gcd(current_period, demand). Work is O(n*s) state transitions,
    where s <= min(2**n, number_of_divisors(demand)). Big-int costs are extra.
    A candidate means the producer is available, not that its reading exists.
    """
    p, d = observation_period(moduli), demand_period(queries)
    candidates = tuple(sorted(candidates, key=lambda c: c.name))
    if len({c.name for c in candidates}) != len(candidates):
        raise ValueError("candidate names must be unique")
    states: dict[int, tuple[int, tuple[str, ...]]] = {gcd(p, d): (0, ())}
    for c in candidates:
        previous = tuple(states.items())
        for coverage, (cost, names) in previous:
            next_coverage = lcm(coverage, gcd(c.modulus, d))
            proposed = (cost + c.cost, names + (c.name,))
            incumbent = states.get(next_coverage)
            key = lambda item: (item[0], len(item[1]), item[1])
            if incumbent is None or key(proposed) < key(incumbent):
                states[next_coverage] = proposed
    if d not in states:
        return None
    cost, names = states[d]
    selected = set(names)
    achieved = lcm(p, observation_period(c.modulus for c in candidates
                                        if c.name in selected))
    return Selection(names, cost, achieved, d)


def examples() -> dict:
    return {
        "overlap_requires_full_prime_power": asdict(plan_queries(
            [12], [LinearQuery(1, 18)])),
        "linear_consumer_needs_less": asdict(plan_queries(
            [12], [LinearQuery(6, 18)])),
        "division_consumer": asdict(plan_queries(
            [12], [QuotientQuery(5, 7)])),
        "backward_affine_demand": asdict(plan_queries(
            [3], [LinearQuery(1, 18).before_affine(6, 1)])),
        "safe_basis_shadow_already_sufficient": asdict(plan_queries(
            [2, 3, 5, 7, 11, 13, 17, 19], [LinearQuery(1, 77)])),
        "available_producers": asdict(choose_available(
            [12], [LinearQuery(1, 18)],
            [Candidate("three", 3, 1), Candidate("nine", 9, 3),
             Candidate("eighteen", 18, 5)])),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(examples(), indent=2, sort_keys=True))
