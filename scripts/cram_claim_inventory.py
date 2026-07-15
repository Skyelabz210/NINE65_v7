#!/usr/bin/env python3
"""Inventory source evidence relevant to CRAM/FHE exploratory claims.

This script does not decide mathematical truth. It records whether active source
contains structures that support, contradict, or complicate specific claims.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
from dataclasses import dataclass
from typing import Iterable

ROOT = pathlib.Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Probe:
    claim_id: str
    evidence_id: str
    path: str
    pattern: str
    interpretation: str
    expected_presence: bool = True


PROBES = (
    Probe(
        "H05",
        "evaluation_key_relinearization_components",
        "crates/nine65/src/ops/rns_fhe.rs",
        r"pub\s+rlk\s*:\s*Vec<",
        "Active evaluation-key type contains public relinearization components.",
    ),
    Probe(
        "H05",
        "evaluation_key_decomposition_base",
        "crates/nine65/src/ops/rns_fhe.rs",
        r"pub\s+decomp_base\s*:\s*u64",
        "Active evaluation-key type contains an explicit decomposition base.",
    ),
    Probe(
        "H05",
        "evaluation_key_digit_count",
        "crates/nine65/src/ops/rns_fhe.rs",
        r"pub\s+num_digits\s*:\s*usize",
        "Active evaluation-key type contains an explicit decomposition digit count.",
    ),
    Probe(
        "H04",
        "simulated_refresh_branch",
        "crates/nine65/src/bin/nine65_bench.rs",
        r"SIMULATED\s+REFRESH|Simulate\s+Clockwork\s+Bootstrap",
        "Benchmark can report a budget reset that is not a real bootstrap.",
    ),
    Probe(
        "H04",
        "real_bootstrap_branch",
        "crates/nine65/src/bin/nine65_bench.rs",
        r"REAL\s+BOOTSTRAP\s+REFRESH|boot\.bootstrap",
        "Benchmark also contains an explicit real-bootstrap path.",
    ),
    Probe(
        "H01",
        "noise_budget_is_estimator",
        "crates/nine65/src/noise/budget.rs",
        r"Estimate\s+cost|approximately|Approximate\s+log2",
        "Current noise budget is an integer accounting estimator, not yet a verified winding witness.",
    ),
    Probe(
        "H02",
        "addition_has_nonzero_accounting_cost",
        "crates/nine65/src/noise/budget.rs",
        r"pub\s+fn\s+add_cost\(\).*?1000",
        "Current accounting model assigns a nonzero cost to ciphertext addition.",
    ),
    Probe(
        "H02",
        "plain_add_has_nonzero_accounting_cost",
        "crates/nine65/src/noise/budget.rs",
        r"pub\s+fn\s+add_plain_cost\(\).*?100",
        "Current accounting model assigns a nonzero cost to plaintext addition.",
    ),
    Probe(
        "H06",
        "security_estimate_marked_rough",
        "crates/nine65/src/params/validation.rs",
        r"rough.*use\s+LWE\s+estimator",
        "Repository parameter validator explicitly marks its security estimate as rough.",
    ),
    Probe(
        "H03",
        "benchmark_float_percentage",
        "crates/nine65/src/bin/nine65_bench.rs",
        r"\bas\s+f64\b|\bf64\b",
        "Current benchmark derives some display metrics through floating-point conversion.",
    ),
    Probe(
        "H05",
        "exact_value_reconstruction_language",
        "crates/nine65/src/ops/rns_fhe.rs",
        r"exact_value\s*=\s*v_main\s*\+\s*k\s*[×*]\s*M|reconstruct\s+the\s+EXACT\s+value",
        "Active source documentation describes forming an exact value after K-Elimination; runtime reachability requires separate tracing.",
    ),
)


def git_output(*args: str) -> str:
    try:
        return subprocess.check_output(
            ["git", *args], cwd=ROOT, text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def line_matches(text: str, pattern: str) -> list[dict[str, object]]:
    regex = re.compile(pattern, re.IGNORECASE | re.DOTALL)
    matches: list[dict[str, object]] = []
    for match in regex.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        excerpt = " ".join(match.group(0).split())[:240]
        matches.append({"line": line, "excerpt": excerpt})
    return matches


def file_digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def evaluate_probe(probe: Probe) -> dict[str, object]:
    path = ROOT / probe.path
    if not path.exists():
        return {
            "claim_id": probe.claim_id,
            "evidence_id": probe.evidence_id,
            "path": probe.path,
            "status": "MISSING_FILE",
            "interpretation": probe.interpretation,
            "matches": [],
        }
    text = path.read_text(encoding="utf-8")
    matches = line_matches(text, probe.pattern)
    present = bool(matches)
    status = "PRESENT" if present else "ABSENT"
    return {
        "claim_id": probe.claim_id,
        "evidence_id": probe.evidence_id,
        "path": probe.path,
        "sha256": file_digest(path),
        "status": status,
        "expected_presence": probe.expected_presence,
        "interpretation": probe.interpretation,
        "matches": matches,
    }


def summarize(records: Iterable[dict[str, object]]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for record in records:
        status = str(record["status"])
        summary[status] = summary.get(status, 0) + 1
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()

    records = [evaluate_probe(probe) for probe in PROBES]
    payload = {
        "schema": "nine65-cram-claim-inventory-v1",
        "repository": git_output("config", "--get", "remote.origin.url"),
        "commit": git_output("rev-parse", "HEAD"),
        "branch": git_output("rev-parse", "--abbrev-ref", "HEAD"),
        "dirty": git_output("status", "--porcelain") != "",
        "scope": "source_structure_only",
        "summary": summarize(records),
        "records": records,
        "interpretation_rule": (
            "Presence or absence is source evidence only. Runtime behavior and mathematical "
            "claims require the corresponding execution harness."
        ),
    }
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
