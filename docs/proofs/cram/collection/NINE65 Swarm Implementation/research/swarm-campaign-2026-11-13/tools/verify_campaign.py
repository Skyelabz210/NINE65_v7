#!/usr/bin/env python3
"""Check campaign coverage and evidence integrity; optionally rerun exact models.

This does not convert model checks into Lean proofs or ciphertext evidence.
Runtime integration and original-repository builds retain their own logs.
"""
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def read_json(path):
    return json.loads((ROOT / path).read_text())


def read_lines(path):
    return [json.loads(line) for line in (ROOT / path).read_text().splitlines() if line]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--models", action="store_true")
    parser.add_argument("--complete", action="store_true", help="Require integrated runtime, original Lean, ledger and review evidence")
    args = parser.parse_args()
    previous = ROOT / "evidence/campaign-verification.json"
    executed = json.loads(previous.read_text()).get("model_commands", []) if previous.exists() else []
    if args.models:
        executed = []
        for name in ("discovery/run_models.py", "reviews/independent_oracles.py"):
            result = subprocess.run([sys.executable, str(ROOT / name)], cwd=ROOT,
                                    capture_output=True, text=True)
            log = ROOT / "evidence" / (Path(name).stem + "-integrated.log")
            log.write_text(result.stdout + result.stderr)
            require(result.returncode == 0, f"Model failed: {name}")
            executed.append({"command": [sys.executable, name], "exit_code": 0,
                             "log": str(log.relative_to(ROOT))})

    sources = read_lines("registry/sources.jsonl")
    ids = [row["source_id"] for row in sources]
    require(len(ids) == len(set(ids)), "Duplicate source identifiers")
    kinds = Counter(row["source_type"] for row in sources)
    require(kinds["uploaded_top_level"] == 42, "Original upload coverage changed")
    require(kinds["extracted_artifact"] == 108, "Extracted artifact coverage changed")
    require(kinds["repository"] == 8, "Seven repositories plus Guide required")
    corpus = read_json("registry/corpus_validation.json")
    require(corpus["sources_jsonl_sha256"] == sha(ROOT / "registry/sources.jsonl"),
            "Stale source-registry validation")

    graph = read_json("discovery/discoverygraph.json")
    families = {row["id"] for row in graph["families"]}
    require(len(families) == 22, "Expected 22 initial contribution families")
    pairs = graph["pairs"]
    expected = {tuple(sorted((a, b))) for a in families for b in families if a != b}
    observed = [tuple(sorted(row["families"])) for row in pairs]
    require(len(observed) == 231 and set(observed) == expected, "Incomplete pair screen")
    for row in pairs:
        a, b = row["families"]
        require({(d["from"], d["to"]) for d in row["directions"]} == {(a,b),(b,a)},
                "Missing directional screen")
    candidates = read_lines("discovery/candidates.jsonl")
    require(len(candidates) == 12 and len({r["id"] for r in candidates}) == 12,
            "Expected twelve distinct initial candidates")
    require(Counter(r["category"] for r in candidates) == {
        "practical_return": 4, "frontier_generalization": 4, "internal_composition": 4},
        "Candidate allocation differs from accepted plan")
    for row in candidates:
        require(bool(row["forward_impact"]) and bool(row["return_impact"]),
                f"Missing bidirectional analysis: {row['id']}")
        for score in ("potential", "readiness"):
            require(len(row[score]) == 5 and all(type(v) is int and 0 <= v <= 5
                                               for v in row[score].values()),
                    f"Invalid separate score: {row['id']}")

    proof = read_json("proofs/verification.json")
    require(proof["status"] == "PASS", "Proof audit not passing")
    names = []
    for row in proof["files"]:
        require(sha(ROOT / "proofs" / row["file"]) == row["sha256"],
                f"Stale proof evidence: {row['file']}")
        for theorem in row["theorems"]:
            names.append(theorem["name"])
            require(set(theorem["axioms"]) <= {"propext", "Classical.choice", "Quot.sound"},
                    "Unexpected proof axiom")
    require(len(names) == len(set(names)) == proof["theorem_declarations"],
            "Theorem count is not unique and complete")
    require(proof["reused_dependency_theorems"] == 144, "Prior proof baseline changed")
    require(proof["theorem_declarations"] == 144 + proof["new_theorem_declarations"],
            "Imported theorems counted as new")

    model = read_json("discovery/model-evidence.json")
    require(model["status"] == "PASS", "Discovery model evidence not passing")
    for name, digest in model["source_sha256"].items():
        require(sha(ROOT / "discovery" / name) == digest, f"Stale model evidence: {name}")

    completion = {}
    if args.complete:
        original = read_json("proofs/original-repo-verification.json")
        require(original["status"] == "PASS" and not original["custom_project_axioms"]
                and not original["admissions"], "Original Lean repository not verified")
        require(original["inventory"]["new_total"] == 49, "New proof count changed")
        require(sha(ROOT / "proofs" / original["patch"]) == original["patch_sha256"],
                "Original Lean patch differs from verified patch")
        original_detail = read_json("proofs/original-repository/verification.json")
        original_names = [r["name"] for r in original_detail["theorems"]]
        require(len(original_names) == len(set(original_names)) == 223, "Original proof count is not unique")
        for row in original_detail["theorems"]:
            require(set(row["axioms"]) <= {"propext", "Classical.choice", "Quot.sound"},
                    "Unexpected original proof axiom")
        runtime = read_json("evidence/integrated-runtime.json")
        require(runtime["status"] == "PASS", "Combined runtime not passing")
        for name, digest in runtime["source_sha256"].items():
            require(sha(ROOT.parents[1] / name) == digest, f"Runtime evidence stale: {name}")
        for row in runtime["runs"]:
            require(row["exit_code"] == 0 and row["passed"] == row["expected_passed"] > 0,
                    "Runtime command failed or executed wrong test count")
            require(sha(ROOT / row["log"]) == row["log_sha256"], "Runtime log changed")
        review = read_json("reviews/reviewer_scope.json")
        require(review["status"] == "ACCEPTED_WITH_DECLARED_RESEARCH_SCOPE" and
                not review["blocking_findings"], "Independent review not accepted")
        ledger = read_lines("registry/contributions.jsonl")
        require({r["id"] for r in ledger} == {r["id"] for r in candidates}, "Incomplete final ledger")
        for row in ledger:
            require(bool(row["execution"]["next_action"]), "Missing continuation obligation")
            for name in row["execution"]["evidence"]:
                require((ROOT / name).is_file(), f"Missing contribution evidence: {name}")
        for row in read_lines("registry/evidence.jsonl"):
            require(sha(ROOT / row["path"]) == row["sha256"], f"Stale evidence index: {row['path']}")
        completion = {"integrated_lean_declarations": 223, "new_total_declarations": 49,
                      "combined_runtime_tests": sum(r["passed"] for r in runtime["runs"]),
                      "independent_review": review["status"], "resolved_candidate_records": len(ledger)}

    report = {
        "status": "PASS", "executed_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "Coverage and evidence integrity plus explicitly selected exact model execution",
        "sources": len(sources), "source_type_counts": dict(kinds),
        "families": len(families), "unordered_pair_screens": len(pairs),
        "directional_screens": 2*len(pairs), "selected_candidates": len(candidates),
        "standalone_theorem_declarations": len(names),
        "new_standalone_theorems": proof["new_theorem_declarations"],
        "model_commands": executed,
        "completion_checks": completion,
        "separate_evidence": {
            "original_lean_repository": "proofs/original-repo-verification.json",
            "rust_integration": "evidence/integrated-runtime.json",
            "independent_review": "reviews/REVIEW.md",
            "delivery": "evidence/drive-delivery.json",
        },
    }
    (ROOT / "evidence/campaign-verification.json").write_text(json.dumps(report, indent=2)+"\n")
    print(json.dumps({k: report[k] for k in ("status", "sources", "unordered_pair_screens",
          "selected_candidates", "standalone_theorem_declarations", "new_standalone_theorems")}, indent=2))


if __name__ == "__main__":
    main()
