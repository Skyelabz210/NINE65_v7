"""Build and evidence rules for seeded comparison-only correctness probes."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any


def build_command(binary: str, cargo_profile: str = "debug", *, insecure: bool = True) -> list[str]:
    if cargo_profile != "debug":
        raise ValueError(
            "seeded comparison probes support debug correctness only; release "
            "performance requires a separate admitted tuple and secure-RNG producer"
        )
    return [
        "cargo", "build", "--locked", "-p", "nine65", "--bin", binary,
        "--features", "serde,allow_insecure" if insecure else "serde",
    ]


def file_sha256(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def evidence_contract(root: Path, binary: Path) -> dict[str, Any]:
    return {
        "cargo_profile": "debug",
        "features": ["serde", "allow_insecure"],
        "purpose": "comparison-only correctness",
        "security_equivalence": "NON_SECURITY_EQUIVALENT",
        "performance_ranking_allowed": False,
        "cargo_lock_sha256": file_sha256(root / "Cargo.lock"),
        "binary_sha256": file_sha256(binary),
        "harness_source_sha256": {
            name: file_sha256(root / name) for name in (
                "scripts/benchmark_contract.py",
                "scripts/run_nine65_v7_scale_sweep.py",
                "scripts/run_nine65_v6_v7_compare.py",
                "scripts/cram_compare_results.py",
                "crates/nine65/src/bin/cram_comparative_probe.rs",
            )
        },
        "timing_sample_policy": "integer per-process operation averages; depth entries individually timed",
        "allocation_tracking": "UNMEASURED",
        "worker_count": "UNMEASURED",
    }


def classify_result(payload: dict[str, Any] | None, returncode: int) -> tuple[str, Any]:
    """A process exit or loop count alone never certifies correct arithmetic."""
    if payload is None:
        return "UNRUN", "probe exited without a result artifact"
    if payload.get("schema") != "nine65-comparative-probe-v1":
        return "UNRUN", "unrecognized result schema"
    metadata = payload.get("metadata", {})
    if not isinstance(metadata, dict) or metadata.get("build_profile") != "debug" or metadata.get("allow_insecure_feature") is not True:
        return "UNRUN", "binary profile/features do not match the debug correctness contract"
    correctness = payload.get("correctness")
    if not isinstance(correctness, dict) or not correctness:
        return "UNRUN", "missing operation correctness evidence"
    unsupported = None
    for path, operations in correctness.items():
        if not isinstance(operations, dict) or not operations:
            return "UNRUN", f"missing correctness evidence for {path}"
        for operation, correct in operations.items():
            retired_mul = path == "legacy" and operations.get("mul_ct_status") == "refused-#135"
            if retired_mul and operation == "mul_ct_status":
                continue
            if retired_mul and operation == "mul_ct" and correct is False:
                unsupported = {"path": path, "operation": operation, "reason": "refused-#135"}
                continue
            if correct is False:
                return "WRONG_PLAINTEXT", {"path": path, "operation": operation}
            if correct is not True:
                return "UNRUN", f"invalid correctness evidence for {path}.{operation}"
    depth = payload.get("ct_mul_depth", {})
    if not isinstance(depth, dict) or not isinstance(depth.get("entries"), list):
        return "UNRUN", "malformed depth evidence"
    entries = depth.get("entries", [])
    for entry in entries:
        if not isinstance(entry, dict):
            return "UNRUN", "malformed depth entry"
        if entry.get("operation_error"):
            return "UNSUPPORTED", entry
        if not all(isinstance(entry.get(key), int) and not isinstance(entry.get(key), bool)
                   for key in ("expected", "decrypted")):
            return "UNRUN", "missing depth plaintext oracle values"
        if entry["decrypted"] != entry["expected"]:
            return "WRONG_PLAINTEXT", entry
        if entry.get("correct") is False:
            return "WRONG_PLAINTEXT", entry
        if entry.get("correct") is not True:
            return "UNRUN", "missing depth oracle result"
    requested = depth.get("requested")
    if (
        not isinstance(requested, int) or isinstance(requested, bool) or requested < 1
        or len(entries) != requested or depth.get("completed") != len(entries)
        or depth.get("all_completed_entries_correct") is not True
        or depth.get("first_error") is not None
    ):
        return "UNRUN", depth.get("first_error") or "incomplete depth evidence"
    if unsupported is not None:
        return "UNSUPPORTED", unsupported
    if returncode != 0 or payload.get("status") != "PASS":
        return "UNRUN", "process or reported status failed despite recorded checks"
    return "PASS", None
