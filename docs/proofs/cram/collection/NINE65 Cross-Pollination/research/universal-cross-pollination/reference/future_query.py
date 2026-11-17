"""Finite public-model compiler for the least future-query sufficient partition.

This is a specification/experiment tool. Explicit finite-state enumeration is
not a secret-dependent execution strategy or an encrypted evaluator.
"""

from dataclasses import dataclass


def classify(signatures):
    seen = {}
    return tuple(seen.setdefault(s, len(seen)) for s in signatures)


@dataclass(frozen=True)
class FutureQueryModel:
    classes: tuple[int, ...]
    quotient_transitions: dict[str, tuple[int, ...]]
    quotient_outputs: tuple[tuple[int, ...], ...]
    strict_refinements: int


def compile_future_queries(outputs, transitions) -> FutureQueryModel:
    """outputs[x] is a tuple of demanded observations at state x.

    Each named total transition is an explicit table on 0..n-1. Result is the
    coarsest partition determining all outputs after every finite word of
    these transitions. No transition availability/control is inferred.
    """
    outputs = tuple(tuple(row) for row in outputs)
    n = len(outputs)
    if not n or len({len(row) for row in outputs}) != 1:
        raise ValueError("need a nonempty rectangular output table")
    if any(type(value) is not int for row in outputs for value in row):
        raise ValueError("output labels must be integers")
    transitions = {name: tuple(table) for name, table in transitions.items()}
    if any(not isinstance(name, str) or not name for name in transitions):
        raise ValueError("transitions need nonempty names")
    for table in transitions.values():
        if len(table) != n or any(type(x) is not int or not 0 <= x < n for x in table):
            raise ValueError("transition must be total on the admitted finite domain")
    tables = tuple(transitions[name] for name in sorted(transitions))
    classes = classify(outputs)
    rounds = 0
    while True:
        refined = classify((classes[x], *(classes[t[x]] for t in tables))
                           for x in range(n))
        if refined == classes:
            break
        classes = refined
        rounds += 1
    representatives = [classes.index(c) for c in range(max(classes) + 1)]
    return FutureQueryModel(
        classes,
        {name: tuple(classes[t[x]] for x in representatives)
         for name, t in sorted(transitions.items())},
        tuple(outputs[x] for x in representatives),
        rounds,
    )
