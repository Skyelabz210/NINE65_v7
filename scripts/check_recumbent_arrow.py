#!/usr/bin/env python3
"""Audit actual Rust recumbent traces against an independent finite oracle.

Generate traces with the recumbent_arrow_trace example in modes drop and rank.
The native drop passes the finite logical-state arrow gates. The full-basis
quotient plus remainder is a negative control for the stronger joint-output
uniformity diagnostic. That diagnostic is not the user's Holte driving-digit
IID/detailed-balance criterion. Fixture lineage is not ciphertext custody.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

from a2_arrow_suite import audit_trace
from check_residue_native_architecture import executable_fragment, production_lines

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = re.compile(r"\b(?:garner\w*|mixed_radix\w*)\s*(?:::|\()", re.I)
SOURCE_FILES = (
    "crates/nine65/src/arithmetic/recumbent.rs",
    "crates/nine65/src/arithmetic/rank_residue_divider.rs",
)


def digest(value):
    return hashlib.sha256(json.dumps(value, separators=(",", ":")).encode()).hexdigest()


def inspect_sources():
    findings = []
    hashes = {}
    for relative in SOURCE_FILES:
        path = ROOT / relative
        text = path.read_text()
        hashes[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        for number, line in production_lines(text):
            for hit in FORBIDDEN.finditer(executable_fragment(line)):
                findings.append(f"{relative}:{number}:{hit.group()}")
    return dict(
        observed_emissions=findings,
        allowed_emissions=[],
        observed_ref="lexical-source-audit:" + digest(hashes),
        policy_ref="user-clarification:2026-10-27:forbid-Garner-and-mixed-radix",
        source_hashes=hashes,
        scope="Named executable calls in the two implementation files; aliases and hidden emissions require separate review.",
    )


def audit_fixture(path, mode, source_policy):
    trace = json.loads(path.read_text())
    main = [2, 3, 5, 7]
    output_moduli = [3, 5, 7, 2] if mode == "drop" else [2, 3, 5, 7, 2]
    if trace.get("input_moduli") != main or trace.get("output_moduli") != output_moduli:
        raise ValueError("trace basis does not match the independently specified fixture")
    rows = trace.get("rows", [])
    if len(rows) != 210:
        raise ValueError("fixture requires all 210 source states")
    expected_inputs = [[x % m for m in main] for x in range(210)]
    expected_outputs = [
        [x // 2 % m for m in output_moduli[:-1]] + [x % 2]
        for x in range(210)
    ]
    for row, source, expected in zip(rows, expected_inputs, expected_outputs):
        if row.get("input") != source:
            raise ValueError("Rust input trace differs from the independent fixture")
        # Do not trust the expected field emitted by the Rust example.
        row["expected"] = expected
        if len(row.get("order_outputs", [])) != 6:
            raise ValueError("fixture requires six actual lane orders")
    observed_records = [
        digest([row["input"] for row in rows]),
        digest([row["output"] for row in rows]),
        digest([row["restored"] for row in rows]),
    ]
    authorized_records = [digest(expected_inputs), digest(expected_outputs), digest(expected_inputs)]
    trace["source_policy"] = source_policy
    trace["lineage"] = dict(
        observed=observed_records,
        authorized=authorized_records,
        observed_ref="actual-rust-trace:" + hashlib.sha256(path.read_bytes()).hexdigest(),
        authorized_ref="independent-python-fixture:floor-X-by-2-on-[0,209]",
    )
    report = audit_trace(trace)
    report["profile"] = "logical-state reversal and joint-output uniformity diagnostic"
    report["carry_process_scope"] = "This trace does not construct a Holte carry chain; driving-digit IID and detailed balance are checked separately."
    report["lineage_scope"] = "Known deterministic test fixture only; no authenticated ciphertext history or custody claim."
    report["source_policy_evidence"] = source_policy
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace_directory", type=Path)
    args = parser.parse_args()
    directory = args.trace_directory
    source_policy = inspect_sources()
    reports = {}
    for mode in ("drop", "rank"):
        report = audit_fixture(directory / f"{mode}-trace.json", mode, source_policy)
        (directory / f"{mode}-report.json").write_text(json.dumps(report, indent=2) + "\n")
        reports[mode] = report
    native_passes = reports["drop"]["status"] == "PASS_FINITE_DOMAIN"
    rank_gates = {gate["gate"]: gate["verdict"] for gate in reports["rank"]["gates"]}
    negative_control = rank_gates == {
        "G1": "PASS", "G2": "PASS", "G3": "FAIL",
        "G4": "PASS", "G5": "PASS", "G6": "PASS",
    }
    summary = dict(
        native_drop=reports["drop"]["status"],
        redundant_full_basis_rank=reports["rank"]["status"],
        expected_joint_output_diagnostic_failure=negative_control,
        rank_policy_admission="Not decided by the stronger joint-output diagnostic; use the declared driving-variable/carry model.",
        acceptance="PASS_FINITE_FIXTURE" if native_passes and negative_control else "FAIL",
        scope="210 states; six lane orders; quotient+remainder. Joint-output diagnostic only; not the Holte carry-process acceptance criterion.",
    )
    (directory / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0 if native_passes and negative_control else 1


if __name__ == "__main__":
    raise SystemExit(main())
