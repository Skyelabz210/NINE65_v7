#!/usr/bin/env python3
"""Join discovery hypotheses to scoped implementation/proof outcomes.

The original discovery scores remain the planning snapshot. A checked component
does not promote every claim in its candidate to a theorem or production result.
"""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]

OUTCOMES = {
    "C01": ("SUPPORTED_WITH_SCOPE", "Implemented and tested",
        "Producer-owned clear residue states, source/frame/epoch-bound plans, public demand and producer selection, native add/multiply/square, and opt-in compiler/UNHAL integration.",
        ["runtime-residue/adapter-tests.json", "evidence/integrated-runtime.json"],
        "Refine the Rust implementation against Lean contracts; add an authentic ciphertext producer before claiming encrypted residue-query execution."),
    "C02": ("SUPPORTED_WITH_SCOPE", "Written proof and executed reference compiler",
        "Verified diagonal certificates over composite moduli emit query weights or an explicit kernel collision. Nonunit observations can still answer selected queries.",
        ["discovery/REPORT.md", "discovery/model-evidence.json"],
        "Implement a scalable normal-form producer and formal certificate checker; current reference dimension is at most six."),
    "C03": ("SUPPORTED_WITH_SCOPE", "Written proof and executed reference consumer",
        "Exact bounded integer orientation from determinant residues, using a transient quotient/remainder comparison without full determinant reconstruction.",
        ["discovery/REPORT.md", "discovery/model-evidence.json"],
        "Connect the geometry producer to the typed Rust path and benchmark matched exact-predicate workloads."),
    "C04": ("REPAIRED_AND_SUPPORTED_WITH_SCOPE", "Implemented encrypted query plus rational reference",
        "Fixed 2w-round Euclid is retained; a direct small-width target circuit reduces depth and admits native N=8192 two-bit GCD where the composed circuit refuses. Rational normalization and multiplication are separate exact clear reference operations.",
        ["runtime-gcd/evidence/verification.json", "runtime-gcd/evidence/rational-pair.json", "evidence/integrated-runtime.json"],
        "Extend admitted encrypted widths with measured noise and cost; implement encrypted rational normalization without replacing the current admission policy."),
    "C05": ("SUPPORTED_WITH_SCOPE", "General written proof and independent finite checks",
        "Piecewise-linear embedding intertwines actual nearest-neighbor BBS evolution and the continuous-space Pitman path transform, with explicit carrier boundary conditions.",
        ["discovery/REPORT.md", "discovery/model-evidence.json", "reviews/REVIEW.md"],
        "Formalize interpolation/running-maximum commutation in Lean; a continuum-time PDE limit is a separate theorem."),
    "C06": ("SUPPORTED_WITH_SCOPE", "Local precision reference construction",
        "Simple-root Hensel correction exposes the extra observation and unit premise at each precision step; this supplies a disciplined route for G/H extensions.",
        ["discovery/REPORT.md", "discovery/model-evidence.json"],
        "Construct authentic higher-order observations and prove their actual encrypted precision/noise behavior."),
    "C07": ("SUPPORTED_WITH_SCOPE", "Lean-checked mathematical construction",
        "All-future observation equivalence induces actual quotient query and transition maps; finite refinement and maximal invisible additive subgroups characterize admissible state reduction.",
        ["proofs/FutureQuotient.lean", "proofs/verification.json", "reviews/reviewer_scope.json"],
        "Refine an executable transition-family closure checker; arbitrary gate sets need not preserve a proposed compressed family."),
    "C08": ("SUPPORTED_WITH_SCOPE", "Written proof and executed local-algebra model",
        "The first nonzero Hasse jet of a multiplier recovers a quotient evaluation at a shared root when its leading local coefficient is a unit; ordinary derivatives can fail in positive characteristic.",
        ["discovery/REPORT.md", "discovery/model-evidence.json"],
        "Formalize the jet constructor and provide authenticated polynomial/jet producers with explicit acquisition cost."),
    "C09": ("SUPPORTED_WITH_SCOPE", "Lean-checked invariants and executed composition model",
        "The four-coordinate reflection is involutive and preserves the Descartes polynomial over any commutative ring. A smaller orbit observation still needs dynamic kernel closure.",
        ["proofs/ReflectionInvariant.lean", "proofs/verification.json", "discovery/model-evidence.json"],
        "Compile an invariant orbit-query representation and certify its transition closure and machine bounds."),
    "C10": ("SUPPORTED_WITH_SCOPE", "Executed centered-chart query model",
        "StarLift reads the negative winding class needed by a centered theta minimizer; walls have two minima and require a tie or set-valued policy.",
        ["discovery/REPORT.md", "discovery/model-evidence.json"],
        "Carry authentic centered references and explicit wall policy into a consumer; unbounded minimizers still require range information."),
    "C11": ("REPAIRED", "Exact counterexample and retained valid invariant",
        "Energy preservation does not imply maximum-coordinate contraction. The rational rotation counterexample preserves the quadratic invariant while invalidating that stronger inference.",
        ["discovery/REPORT.md", "discovery/model-evidence.json", "registry/SOURCE_COVERAGE.md"],
        "Use a proved norm conversion or stronger monotonicity bound; continuum regularity remains open in the later source blueprint."),
    "C12": ("SUPPORTED_WITH_SCOPE", "Executed conservation model and existing encrypted consumer check",
        "Largest-remainder normalization preserves the exact integer total. The existing private-feedback encrypted aggregate also passes its unchanged eight-slot check; these are separate components, not an encrypted sorting implementation.",
        ["discovery/model-evidence.json", "runtime-gcd/evidence/verification.json"],
        "Select an explicit normalization policy and account for encrypted sorting/selection before composing the two components."),
}


def main():
    rows = [json.loads(s) for s in (ROOT / "discovery/candidates.jsonl").read_text().splitlines() if s]
    for row in rows:
        disposition, level, result, evidence, next_action = OUTCOMES[row["id"]]
        row["planning_snapshot_status"] = row.pop("status")
        row["planning_snapshot_next_action"] = row.pop("next_action")
        row["status"] = disposition
        row["execution"] = {"level": level, "result": result, "evidence": evidence,
                            "next_action": next_action, "historical_priority": "UNADJUDICATED"}
    (ROOT / "registry/contributions.jsonl").write_text("".join(json.dumps(r, ensure_ascii=False)+"\n" for r in rows))
    evidence = []
    for name in (
        "registry/corpus_validation.json", "proofs/verification.json",
        "proofs/original-repo-verification.json", "discovery/execution-evidence.json",
        "discovery/model-evidence.json", "runtime-residue/adapter-tests.json",
        "runtime-residue/matched-cost.json", "runtime-gcd/evidence/verification.json",
        "runtime-gcd/evidence/rational-pair.json", "reviews/reviewer_scope.json",
        "reviews/REVIEW.md", "evidence/integrated-runtime.json",
    ):
        path = ROOT / name
        if not path.is_file():
            raise FileNotFoundError(f"Required campaign evidence missing: {name}")
        evidence.append({"path": name, "bytes": path.stat().st_size,
                         "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    (ROOT / "registry/evidence.jsonl").write_text("".join(json.dumps(r)+"\n" for r in evidence))
    print(json.dumps({"contributions": len(rows), "evidence_records": len(evidence)}))


if __name__ == "__main__":
    main()
