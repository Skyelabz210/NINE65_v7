#!/usr/bin/env python3
"""Classify CRAM/FHE roadmap hypotheses from generated evidence.

The analyzer never upgrades an accounting model, source comment, or candidate
counter into a mathematical witness. Verdicts describe only what the supplied
artifacts support.
"""

from __future__ import annotations

import argparse
import json
import math
import pathlib
from collections import defaultdict
from typing import Any, Iterable

SUPPORTED = "SUPPORTED_BY_SUPPLIED_EVIDENCE"
CONTRADICTED = "CONTRADICTED_BY_SUPPLIED_EVIDENCE"
INCONCLUSIVE = "INCONCLUSIVE"
EXTERNAL = "REQUIRES_EXTERNAL_VALIDATION"


def load_json(path: pathlib.Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"top-level JSON object required: {path}")
    return value


def discover(paths: Iterable[pathlib.Path]) -> list[pathlib.Path]:
    discovered: list[pathlib.Path] = []
    for path in paths:
        if path.is_dir():
            discovered.extend(sorted(path.rglob("*.json")))
        else:
            discovered.append(path)
    return discovered


def exact_median(values: list[int]) -> dict[str, int] | None:
    if not values:
        return None
    ordered = sorted(values)
    midpoint = len(ordered) // 2
    if len(ordered) % 2:
        return {"numerator": ordered[midpoint], "denominator": 1}
    numerator = ordered[midpoint - 1] + ordered[midpoint]
    divisor = math.gcd(numerator, 2)
    return {"numerator": numerator // divisor, "denominator": 2 // divisor}


def claim(
    claim_id: str,
    statement: str,
    verdict: str,
    evidence: list[dict[str, object]],
    note: str,
) -> dict[str, object]:
    return {
        "claim_id": claim_id,
        "statement": statement,
        "verdict": verdict,
        "evidence": evidence,
        "note": note,
    }


def trace_records(payloads: list[tuple[pathlib.Path, dict[str, Any]]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path, payload in payloads:
        schema = payload.get("schema")
        if schema == "nine65-cram-exploratory-probe-v1":
            for entry in payload.get("trace", []):
                if isinstance(entry, dict):
                    records.append({"source": str(path), "schema": schema, **entry})
        elif schema == "nine65-comparative-probe-v1":
            depth = payload.get("ct_mul_depth", {})
            if isinstance(depth, dict):
                for entry in depth.get("entries", []):
                    if isinstance(entry, dict):
                        records.append(
                            {
                                "source": str(path),
                                "schema": schema,
                                "operation": "mul_ct",
                                **entry,
                            }
                        )
    return records


def analyze_budget_as_winding(
    payloads: list[tuple[pathlib.Path, dict[str, Any]]],
) -> dict[str, object]:
    verified: list[dict[str, object]] = []
    unverified: list[dict[str, object]] = []
    for path, payload in payloads:
        if payload.get("schema") != "nine65-cram-exploratory-probe-v1":
            continue
        metadata = payload.get("metadata", {})
        if not isinstance(metadata, dict):
            continue
        item = {
            "source": str(path),
            "candidate_winding_is_verified": bool(
                metadata.get("candidate_winding_is_verified", False)
            ),
            "noise_budget_is_accounting_model": bool(
                metadata.get("noise_budget_is_accounting_model", False)
            ),
        }
        if item["candidate_winding_is_verified"]:
            verified.append(item)
        else:
            unverified.append(item)
    if verified and not unverified:
        return claim(
            "H01",
            "The reported noise budget is an exact CRAM winding witness.",
            SUPPORTED,
            verified,
            "Every supplied probe explicitly marks its winding field as verified.",
        )
    return claim(
        "H01",
        "The reported noise budget is an exact CRAM winding witness.",
        INCONCLUSIVE,
        verified + unverified,
        (
            "The current probe marks the budget as an accounting model and the candidate "
            "winding counter as unverified. Correlation may be tested, but identity is not established."
        ),
    )


def analyze_addition_cost(traces: list[dict[str, Any]]) -> dict[str, object]:
    evidence = []
    costs = []
    for entry in traces:
        if entry.get("operation") not in {"add_ct", "add_plain"}:
            continue
        value = entry.get("accounting_cost_mb")
        if isinstance(value, int) and not isinstance(value, bool):
            costs.append(value)
            evidence.append(
                {
                    "source": entry["source"],
                    "operation": entry.get("operation"),
                    "accounting_cost_mb": value,
                }
            )
    if not costs:
        return claim(
            "H02",
            "Addition consumes zero units in the current budget ledger.",
            INCONCLUSIVE,
            [],
            "No addition accounting transitions were present in the supplied artifacts.",
        )
    if all(value == 0 for value in costs):
        verdict = SUPPORTED
        note = "Every observed addition transition has zero recorded accounting cost."
    else:
        verdict = CONTRADICTED
        note = "At least one observed addition transition carries a nonzero accounting cost."
    return claim(
        "H02",
        "Addition consumes zero units in the current budget ledger.",
        verdict,
        evidence,
        note,
    )


def analyze_constant_mul_step(traces: list[dict[str, Any]]) -> dict[str, object]:
    transitions: list[dict[str, object]] = []
    deltas: list[int] = []
    for entry in traces:
        if entry.get("operation") not in {"mul_ct", "mul_plain"}:
            continue
        before = entry.get("budget_before_mb")
        after = entry.get("budget_after_mb")
        refreshed = bool(entry.get("refreshed_pre") or entry.get("refreshed_post"))
        if (
            isinstance(before, int)
            and not isinstance(before, bool)
            and isinstance(after, int)
            and not isinstance(after, bool)
            and not refreshed
        ):
            delta = before - after
            deltas.append(delta)
            transitions.append(
                {
                    "source": entry["source"],
                    "operation": entry.get("operation"),
                    "before_mb": before,
                    "after_mb": after,
                    "delta_mb": delta,
                }
            )
    if len(deltas) < 2:
        return claim(
            "H03",
            "Each multiplication produces one constant budget decrement.",
            INCONCLUSIVE,
            transitions,
            "At least two non-refresh multiplication transitions are required.",
        )
    unique = sorted(set(deltas))
    if len(unique) == 1:
        return claim(
            "H03",
            "Each multiplication produces one constant budget decrement.",
            SUPPORTED,
            transitions,
            (
                f"The supplied accounting transitions share one decrement: {unique[0]} millibits. "
                "This supports the ledger pattern, not yet a physical winding identity."
            ),
        )
    return claim(
        "H03",
        "Each multiplication produces one constant budget decrement.",
        CONTRADICTED,
        transitions,
        f"Observed multiplication decrements are not constant: {unique}.",
    )


def analyze_off_by_one(traces: list[dict[str, Any]]) -> dict[str, object]:
    failures = []
    deltas = []
    for entry in traces:
        correct = entry.get("correct")
        operation_error = entry.get("operation_error")
        if correct is not False and not operation_error:
            continue
        delta = entry.get("mismatch_delta_mod_t")
        item = {
            "source": entry["source"],
            "operation": entry.get("operation"),
            "step": entry.get("step", entry.get("depth")),
            "mismatch_delta_mod_t": delta,
            "operation_error": operation_error,
        }
        failures.append(item)
        if isinstance(delta, int) and not isinstance(delta, bool):
            deltas.append(delta)
    if not failures:
        return claim(
            "H04",
            "Observed arithmetic failures are exactly an off-by-one mismatch.",
            INCONCLUSIVE,
            [],
            "No arithmetic failure was present in the supplied traces.",
        )
    if deltas and len(deltas) == len(failures) and all(value in {1, 65_536} for value in deltas):
        return claim(
            "H04",
            "Observed arithmetic failures are exactly an off-by-one mismatch.",
            SUPPORTED,
            failures,
            "Every supplied mismatch is one step modulo the recorded plaintext modulus convention.",
        )
    return claim(
        "H04",
        "Observed arithmetic failures are exactly an off-by-one mismatch.",
        CONTRADICTED,
        failures,
        "At least one failure is an operation error or has a mismatch delta other than one.",
    )


def analyze_key_material(
    payloads: list[tuple[pathlib.Path, dict[str, Any]]],
) -> dict[str, object]:
    evidence = []
    for path, payload in payloads:
        schema = payload.get("schema")
        if schema == "nine65-comparative-probe-v1":
            structure = payload.get("key_structure", {})
            if isinstance(structure, dict):
                evidence.append(
                    {
                        "source": str(path),
                        "relinearization_components": structure.get(
                            "relinearization_components"
                        ),
                        "decomposition_base": structure.get("decomposition_base"),
                        "decomposition_digits": structure.get("decomposition_digits"),
                    }
                )
        elif schema == "nine65-cram-exploratory-probe-v1":
            structure = payload.get("key_structure", {})
            if isinstance(structure, dict):
                evidence.append(
                    {
                        "source": str(path),
                        "relinearization_components": structure.get(
                            "eval_key_relinearization_components"
                        ),
                        "decomposition_base": structure.get(
                            "eval_key_decomposition_base"
                        ),
                        "decomposition_digits": structure.get(
                            "eval_key_decomposition_digits"
                        ),
                    }
                )
    if not evidence:
        return claim(
            "H05",
            "The active ciphertext multiplication path uses zero auxiliary relinearization components.",
            INCONCLUSIVE,
            [],
            "No runtime key-structure evidence was supplied.",
        )
    zero = all(
        item.get("relinearization_components") == 0
        and item.get("decomposition_digits") == 0
        for item in evidence
    )
    return claim(
        "H05",
        "The active ciphertext multiplication path uses zero auxiliary relinearization components.",
        SUPPORTED if zero else CONTRADICTED,
        evidence,
        (
            "Every observed key structure is empty."
            if zero
            else "The current runtime key structure contains relinearization components or decomposition digits."
        ),
    )


def analyze_refresh(traces: list[dict[str, Any]]) -> tuple[dict[str, object], dict[str, object]]:
    refreshes = []
    timings = []
    for entry in traces:
        kind = entry.get("refresh_kind")
        refreshed = bool(entry.get("refreshed_pre") or entry.get("refreshed_post"))
        if not refreshed:
            continue
        pre = entry.get("pre_refresh_ns")
        post = entry.get("post_refresh_ns")
        timing = pre if isinstance(pre, int) and pre > 0 else post
        item = {
            "source": entry["source"],
            "operation": entry.get("operation"),
            "refresh_kind": kind,
            "refresh_ns": timing,
        }
        refreshes.append(item)
        if isinstance(timing, int) and not isinstance(timing, bool) and timing > 0:
            timings.append(timing)
    if not refreshes:
        real_claim = claim(
            "H06",
            "Every reported refresh is a real bootstrap execution.",
            INCONCLUSIVE,
            [],
            "No refresh event was present in the supplied traces.",
        )
    elif all(item.get("refresh_kind") == "real_bootstrap" for item in refreshes):
        real_claim = claim(
            "H06",
            "Every reported refresh is a real bootstrap execution.",
            SUPPORTED,
            refreshes,
            "Every observed refresh is explicitly labeled as a real bootstrap.",
        )
    else:
        real_claim = claim(
            "H06",
            "Every reported refresh is a real bootstrap execution.",
            CONTRADICTED,
            refreshes,
            "At least one observed refresh is not labeled as a real bootstrap.",
        )
    latency_claim = claim(
        "H07",
        "Refresh latency is approximately 143 microseconds.",
        INCONCLUSIVE if not timings else SUPPORTED,
        refreshes,
        (
            "No real refresh latency sample was supplied."
            if not timings
            else (
                "Observed refresh timing is reported without adopting the 143 microsecond target: "
                f"median={exact_median(timings)} nanoseconds, samples={len(timings)}."
            )
        ),
    )
    return real_claim, latency_claim


def analyze_wall(
    payloads: list[tuple[pathlib.Path, dict[str, Any]]],
) -> dict[str, object]:
    evidence = []
    for path, payload in payloads:
        if payload.get("schema") != "nine65-cram-exploratory-probe-v1":
            continue
        metadata = payload.get("metadata", {})
        if not isinstance(metadata, dict):
            continue
        evidence.append(
            {
                "source": str(path),
                "candidate_wall": metadata.get("candidate_wall"),
                "candidate_winding_is_verified": metadata.get(
                    "candidate_winding_is_verified"
                ),
                "completed_steps": payload.get("result", {}).get("completed_steps")
                if isinstance(payload.get("result"), dict)
                else None,
                "first_error": payload.get("result", {}).get("first_error")
                if isinstance(payload.get("result"), dict)
                else None,
            }
        )
    return claim(
        "H08",
        "Depth failure occurs exactly at the CRAM wall p-1.",
        INCONCLUSIVE,
        evidence,
        (
            "The present candidate multiplication counter is explicitly unverified. "
            "A wall claim requires a residue-native winding witness and boundary-aligned failure sweep."
        ),
    )


def analyze_comparisons(
    payloads: list[tuple[pathlib.Path, dict[str, Any]]],
) -> dict[str, object]:
    allowed = []
    blocked = []
    for path, payload in payloads:
        if payload.get("schema") != "fhe-comparison-analysis-v1":
            continue
        for group in payload.get("groups", []):
            if not isinstance(group, dict):
                continue
            for comparison in group.get("comparisons", []):
                if not isinstance(comparison, dict):
                    continue
                item = {
                    "source": str(path),
                    "operation": group.get("operation"),
                    "left": comparison.get("left"),
                    "right": comparison.get("right"),
                    "ratio": comparison.get("left_over_right_median"),
                    "ranking_allowed": comparison.get("ranking_allowed"),
                    "correctness_gate": comparison.get("correctness_gate"),
                }
                (allowed if item["ranking_allowed"] else blocked).append(item)
    if allowed:
        return claim(
            "H09",
            "A same-machine v6/v7 performance regression can be ranked.",
            SUPPORTED,
            allowed + blocked,
            "At least one exact compatibility group passed the correctness gate and has a median ratio.",
        )
    return claim(
        "H09",
        "A same-machine v6/v7 performance regression can be ranked.",
        INCONCLUSIVE,
        blocked,
        "No supplied comparison passed both exact compatibility and correctness gates.",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("inputs", nargs="+", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()

    payloads: list[tuple[pathlib.Path, dict[str, Any]]] = []
    errors: list[dict[str, str]] = []
    for path in discover(args.inputs):
        try:
            payloads.append((path, load_json(path)))
        except (OSError, ValueError, json.JSONDecodeError) as error:
            errors.append({"path": str(path), "error": str(error)})

    traces = trace_records(payloads)
    refresh_claim, refresh_latency = analyze_refresh(traces)
    claims = [
        analyze_budget_as_winding(payloads),
        analyze_addition_cost(traces),
        analyze_constant_mul_step(traces),
        analyze_off_by_one(traces),
        analyze_key_material(payloads),
        refresh_claim,
        refresh_latency,
        analyze_wall(payloads),
        analyze_comparisons(payloads),
        claim(
            "H10",
            "The validity product alone establishes the stated RLWE security bits.",
            EXTERNAL,
            [],
            "Security requires a pinned RLWE estimator and declared attack model; timing and residue occupancy do not establish it.",
        ),
    ]
    verdict_counts: dict[str, int] = defaultdict(int)
    for item in claims:
        verdict_counts[str(item["verdict"])] += 1

    output = {
        "schema": "cram-fhe-hypothesis-analysis-v1",
        "input_count": len(payloads),
        "input_errors": errors,
        "trace_count": len(traces),
        "verdict_counts": dict(sorted(verdict_counts.items())),
        "claims": claims,
        "interpretation_rule": (
            "Verdicts are limited to supplied artifacts. Accounting correlation is not promoted "
            "to a winding theorem, and security claims require external estimator evidence."
        ),
    }
    rendered = json.dumps(output, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
