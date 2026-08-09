#!/usr/bin/env python3
"""Build fhe-comparison-record-v1 files from the run2 raw probe artifact.

ADDITIVE, ONE-SHOT SCRIPT: kept here as provenance for how the records were
derived from raw/comparison_record_probe_run2.json. Not part of the crate
build. Does not touch any existing source file.
"""
import json
import pathlib
from fractions import Fraction

ROOT = pathlib.Path(__file__).parent
raw = json.loads((ROOT / "raw" / "comparison_record_probe_run2.json").read_text())

COMMIT = "28e7ce2fb5ccf7c8823170603821e08bd8093cce"
WORKING_TREE_SNAPSHOT_COMMIT = "227bd869b53fccd5da8a915627ae41407dd07d81"
REPOSITORY = "Skyelabz210/NINE65_v7"
HARDWARE_FINGERPRINT = "09fd291610c1ec6ef6d42ba79896772de5fa10e1a4f933384417676527ba3f2d"

BASE_COMPAT = {
    "scheme": "BFV-DualRNS",
    "plaintext_semantics": "scalar-mod-t",
    "target_security_bits": 128,
    "security_estimator": (
        "nine65-in-tree LatticeSecurityEstimator::dual_estimate() "
        "(CostModel::CoreSVP + MATZOV, integer-millibits, ternary secret) "
        "-- THIS IS A DETERMINISTIC INTERNAL SCREENING GATE, NOT an "
        "independent third-party lattice-estimator certificate (e.g. not "
        "the Albrecht et al. lattice-estimator Sage/Python tool). For this "
        "run: core_svp_effective_bits=259, matzov_effective_bits=233, "
        "binding_bits=233, meets_both=true (>=128 target)."
    ),
    "n": raw["n"],
    "log_q_bits": raw["log_q_bits"],
    "plaintext_modulus": raw["t"],
    "slots": 1,
    "refresh_kind": "none",
    "hardware_fingerprint": HARDWARE_FINGERPRINT,
    "threads": 1,
    "build_profile": "release-fat-lto-cgu1",
    "sample_policy": "warm-steady-state",
}

COMMAND = [
    "env", "RAYON_NUM_THREADS=1", "taskset", "-c", "0",
    "./target/release/examples/comparison_record_probe",
]

OP_SPECS = [
    ("keygen", "keygen"),
    ("encrypt", "encrypt"),
    ("decrypt", "decrypt"),
    ("add_ct", "add_ct"),
    ("mul_ct", "mul_ct"),
]

for op_name, probe_key in OP_SPECS:
    node = raw["operations"][probe_key]
    samples = node["samples_ns"]
    assert samples == sorted(samples)
    assert all(isinstance(s, int) for s in samples)
    med = Fraction(node["median_ns_numerator"], node["median_ns_denominator"])
    record = {
        "schema": "fhe-comparison-record-v1",
        "implementation": "NINE65",
        "version": COMMIT,
        "operation": op_name,
        "samples_ns": samples,
        "correctness": {
            "trials": node["correctness_trials"],
            "failures": node["correctness_failures"],
        },
        "compatibility": dict(BASE_COMPAT),
        "provenance": {
            "repository": REPOSITORY,
            "commit": COMMIT,
            "command": COMMAND,
            "raw_artifact": "benchmarks/records/raw/comparison_record_probe_run2.json",
        },
        "derived_statistics_not_part_of_contract_gate": {
            "note": "Everything in this block is convenience arithmetic derived from samples_ns above. It gates nothing; the contract's own comparator recomputes median/p95 itself from samples_ns.",
            "n_samples": node["n_samples"],
            "min_ns": node["min_ns"],
            "max_ns": node["max_ns"],
            "median_ns_numerator": med.numerator,
            "median_ns_denominator": med.denominator,
            "p95_ns_nearest_rank": node["p95_ns_nearest_rank"],
            "api_called": node["api"],
        },
        "integrity_notes": {
            "working_tree_dirty_at_measurement_time": True,
            "working_tree_snapshot_commit": WORKING_TREE_SNAPSHOT_COMMIT,
            "working_tree_snapshot_note": (
                "provenance.commit above is the real `git rev-parse HEAD` as "
                "instructed. The working tree was NOT clean at build/measure "
                "time -- other concurrent workflows had uncommitted edits to "
                "files this task was told not to touch (notably "
                "crates/nine65/src/ops/rns_fhe.rs and "
                "crates/nine65/src/params/secure_configs.rs). "
                "`git stash create` was used (non-destructively -- it does "
                "not alter the working tree or index) to snapshot exactly "
                "what was on disk into the dangling commit object named "
                "above, so the measured code is resolvable via "
                "`git show " + WORKING_TREE_SNAPSHOT_COMMIT + "` for as long "
                "as that object is not garbage-collected. The secure_128() "
                "parameter body itself (n=8192, primes "
                "[998244353, 985661441, 754974721], t=65537, 128-bit) was "
                "directly diffed against HEAD and confirmed UNCHANGED; the "
                "concurrent edits touching secure_configs.rs were in test "
                "code, not in secure_128()."
            ),
        },
    }
    out_path = ROOT / f"nine65_{op_name}_secure128.json"
    out_path.write_text(json.dumps(record, indent=2) + "\n")
    print("wrote", out_path)
