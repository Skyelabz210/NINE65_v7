#!/usr/bin/env python3
"""Bounded arrow audit of actual operation traces.

This repairs the supplied a2-arrow-emission-suite's unused-operation IID/arrow
checks and custody self-comparison. G1--G4 examine operation outputs, inverses,
schedule variants, and independent expected outputs. G3 checks the complete
joint distribution, not merely pairs or the input moduli's coprimality.

PASS means evidence on the stated finite domain only. Independence and
reversibility cannot distinguish every synthetic-emission implementation:
Garner digits, for example, can also biject a uniform finite product. G5 must
therefore compare a separately observed structural trace against an explicit
policy. G6 compares separately referenced lineage records; it does not prove
cryptographic custody. Missing independent evidence is UNVERIFIED, never PASS.

JSON schema: name, input_moduli, output_moduli, exhaustive_product, rows.
Each row has input/output and optional restored/expected/order_outputs arrays.
Optional source_policy has observed_emissions, allowed_emissions, observed_ref,
policy_ref. Optional lineage has observed, authorized, observed_ref,
authorized_ref. Distinct references identify the two evidence sources; their
authenticity remains an external obligation.
"""
from __future__ import annotations

import argparse
from collections import Counter
import itertools
import json
from math import prod
from pathlib import Path


def _integers(values, name, *, minimum=0):
    if not isinstance(values, (list, tuple)) or not values:
        raise ValueError(f"{name} must be a nonempty integer array")
    if any(type(value) is not int or value < minimum for value in values):
        raise ValueError(f"{name} contains an invalid integer")
    return tuple(values)


def _state(values, moduli, name):
    state = _integers(values, name)
    if len(state) != len(moduli) or any(x >= m for x, m in zip(state, moduli)):
        raise ValueError(f"{name} has a shape or canonical-residue error")
    return state


def _gate(gate, verdict, detail, checks=0):
    return dict(gate=gate, verdict=verdict, detail=detail, checks=checks)


def _independent_records(evidence, left, right, left_ref, right_ref):
    if not isinstance(evidence, dict):
        return None
    refs = evidence.get(left_ref), evidence.get(right_ref)
    if not all(isinstance(ref, str) and ref for ref in refs) or refs[0] == refs[1]:
        return None
    first, second = evidence.get(left), evidence.get(right)
    if not isinstance(first, list) or not isinstance(second, list):
        return None
    if any(not isinstance(item, str) for item in first + second):
        return None
    return first, second


def audit_trace(trace):
    """Audit supplied observations without treating trace metadata as custody.

    An exhaustive input product is verified from canonical, unique input rows
    and their cardinality. A partial/sample census cannot certify IID and is
    explicitly UNVERIFIED, even when its observed counts happen to factorize.
    """
    if not isinstance(trace, dict):
        raise ValueError("trace must be an object")
    source = _integers(trace.get("input_moduli"), "input_moduli", minimum=1)
    target = _integers(trace.get("output_moduli"), "output_moduli", minimum=1)
    rows = trace.get("rows")
    if not isinstance(rows, list) or not rows:
        raise ValueError("rows must be a nonempty array")
    inputs, outputs = [], []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("every row must be an object")
        inputs.append(_state(row.get("input"), source, "input"))
        outputs.append(_state(row.get("output"), target, "output"))
    if len(set(inputs)) != len(inputs):
        raise ValueError("duplicate input states bias the finite census")
    complete = len(inputs) == prod(source)
    if trace.get("exhaustive_product", False) and not complete:
        raise ValueError("claimed exhaustive_product is incomplete")
    exhaustive = complete and trace.get("exhaustive_product", False) is True
    gates = []

    collisions = len(outputs) - len(set(outputs))
    restored_present = all("restored" in row for row in rows)
    inverse_bad = 0
    if restored_present:
        inverse_bad = sum(
            _state(row["restored"], source, "restored") != state
            for row, state in zip(rows, inputs)
        )
    if collisions or inverse_bad:
        gates.append(_gate("G1", "FAIL", f"{collisions} output collisions; {inverse_bad} inverse mismatches", len(rows)))
    elif not restored_present:
        gates.append(_gate("G1", "UNVERIFIED", "injective observed image; actual inverse observations absent", len(rows)))
    else:
        gates.append(_gate("G1", "PASS", "injective observed image and actual inverse restores every input; domain scope only", len(rows)))

    alternatives = 0
    schedule_bad = 0
    schedules_complete = True
    for row, output in zip(rows, outputs):
        variants = row.get("order_outputs")
        if not isinstance(variants, list) or not variants:
            schedules_complete = False
            continue
        for variant in variants:
            alternatives += 1
            schedule_bad += _state(variant, target, "order_output") != output
    if schedule_bad:
        gates.append(_gate("G2", "FAIL", f"{schedule_bad} actual schedule outputs differ", alternatives))
    elif not schedules_complete:
        gates.append(_gate("G2", "UNVERIFIED", "actual alternative lane-schedule observations missing for some inputs", alternatives))
    else:
        gates.append(_gate("G2", "PASS", "actual outputs agree for the supplied lane schedules; no universal schedule proof", alternatives))

    if not exhaustive:
        gates.append(_gate("G3", "UNVERIFIED", "IID requires an exhaustive uniform input-product census; supplied domain is partial or sampled", len(rows)))
    else:
        n = len(rows)
        joint = Counter(outputs)
        marginals = [Counter(output[i] for output in outputs) for i in range(len(target))]
        uniform = all(
            len(counts) == modulus and all(count * modulus == n for count in counts.values())
            for counts, modulus in zip(marginals, target)
        )
        factorizes = all(
            count * n ** (len(target) - 1) == prod(marginals[i][point[i]] for i in range(len(target)))
            for point, count in joint.items()
        )
        verdict = "PASS" if uniform and factorizes else "FAIL"
        gates.append(_gate("G3", verdict,
                           f"actual full joint factorization={factorizes}; uniform declared-lane marginals={uniform}; exhaustive finite input product",
                           n))

    if not all("expected" in row for row in rows):
        gates.append(_gate("G4", "UNVERIFIED", "independently expected operation outputs absent"))
    else:
        bad = sum(_state(row["expected"], target, "expected") != out for row, out in zip(rows, outputs))
        gates.append(_gate("G4", "FAIL" if bad else "PASS", f"{bad} mismatches against independently supplied operation semantics", len(rows)))

    policy = _independent_records(trace.get("source_policy"), "observed_emissions", "allowed_emissions", "observed_ref", "policy_ref")
    if policy is None:
        gates.append(_gate("G5", "UNVERIFIED", "separately referenced structural-emission observation and policy required; IID/reversibility do not establish this"))
    else:
        observed, allowed = policy
        prohibited = [item for item in observed if item not in set(allowed)]
        gates.append(_gate("G5", "FAIL" if prohibited else "PASS", f"{len(prohibited)} policy-prohibited observed emissions; supplied structural evidence only", len(observed)))

    custody = _independent_records(trace.get("lineage"), "observed", "authorized", "observed_ref", "authorized_ref")
    if custody is None:
        gates.append(_gate("G6", "UNVERIFIED", "separately referenced observed and authorized lineage required; no cryptographic-custody claim"))
    else:
        observed, authorized = custody
        matches = observed == authorized
        gates.append(_gate("G6", "PASS" if matches else "FAIL", "observed lineage matches independently supplied authorized sequence" if matches else "lineage sequence differs (including order, duplicates, or missing steps)", len(observed)))

    verdicts = {gate["verdict"] for gate in gates}
    status = "FAIL" if "FAIL" in verdicts else "INCOMPLETE" if "UNVERIFIED" in verdicts else "PASS_FINITE_DOMAIN"
    return dict(name=str(trace.get("name", "unnamed")), status=status,
                scope="exhaustive finite product" if exhaustive else "explicit finite observations",
                input_states=len(rows), output_states=len(set(outputs)), gates=gates,
                limitations="Finite operation evidence; structural trace and lineage authenticity are external obligations. No universal IID, no-synthetic-emission, or cryptographic-custody proof.")


def audit_construct(*, name, input_moduli, output_moduli, step, inverse=None,
                    expected=None, domain=None, orders=None, max_states=100_000,
                    source_policy=None, lineage=None):
    """Execute the real operation and inverse, then audit the collected trace.

    `step(state_tuple, lane_order_tuple)` must return output residues in the
    declared output order. Explicit domains are finite observations rather
    than exhaustive-product declarations. The callback is invoked for every
    input and supplied schedule; G3/G4 never substitute an input-only census.
    """
    source = _integers(input_moduli, "input_moduli", minimum=1)
    if domain is None:
        if prod(source) > max_states:
            raise ValueError("exhaustive input product exceeds max_states")
        domain = itertools.product(*(range(modulus) for modulus in source))
        exhaustive = True
    else:
        exhaustive = False
    schedules = orders if orders is not None else [tuple(range(len(source))), tuple(reversed(range(len(source))))]
    if not schedules:
        raise ValueError("at least one evaluation order required")
    for order in schedules:
        if not isinstance(order, (list, tuple)) or sorted(order) != list(range(len(source))):
            raise ValueError("evaluation order must be a permutation of lane indices")
    rows = []
    for state in domain:
        if len(rows) >= max_states:
            raise ValueError("explicit domain exceeds max_states")
        state = tuple(state)
        actual = [list(step(state, tuple(order))) for order in schedules]
        row = dict(input=list(state), output=actual[0], order_outputs=actual[1:])
        if inverse is not None:
            row["restored"] = list(inverse(tuple(actual[0])))
        if expected is not None:
            row["expected"] = list(expected(state))
        rows.append(row)
    return audit_trace(dict(name=name, input_moduli=list(source), output_moduli=list(output_moduli),
                            exhaustive_product=exhaustive, rows=rows,
                            source_policy=source_policy, lineage=lineage))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        report = audit_trace(json.loads(args.trace.read_text()))
    except (ValueError, TypeError, KeyError) as error:
        parser.error(str(error))
    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered)
    print(rendered, end="")
    return 1 if report["status"] == "FAIL" else 2 if report["status"] == "INCOMPLETE" else 0


if __name__ == "__main__":
    raise SystemExit(main())
