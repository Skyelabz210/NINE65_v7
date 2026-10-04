#!/usr/bin/env python3
"""Fail-closed admission ledger for the complete public-bootstrap candidates.

This audits archived public parameter evidence. It does not infer a noise proof
or a security estimate from a successful encrypted trial.
"""

import argparse
import hashlib
import json
import math
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CANONICAL = ROOT / "artifacts/bootstrap/canonical_lift_feasibility_2026-09-28.json"
DEPENDENCIES = {
    "R02_operation_schedule": ROOT / "artifacts/execution/bounded_digit_schedule.json",
    "R01_input_radius": ROOT / "docs/execution/2026-10-03/DIGIT_RADIUS_CONTRACT.md",
    "V00_security_disposition": ROOT / "docs/execution/2026-10-03/SECURITY_DISPOSITIONS.md",
}
REFERENCE_NAMES = (
    "public_bfv_reference_n1024_b17_q820_run1_2026-09-28",
    "public_bfv_reference_n1024_b32_q1000_run1_2026-09-28",
    "public_bfv_reference_n8192_b32_q1000_run1_2026-09-28",
)
FAILED_REFERENCE = "public_bfv_reference_n1024_b32_run1_2026-09-28"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prime64(value):
    """Deterministic Miller-Rabin for unsigned 64-bit integers."""
    if not isinstance(value, int) or not 2 <= value < 1 << 64:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for divisor in small:
        if value % divisor == 0:
            return value == divisor
    d = value - 1
    shifts = 0
    while d % 2 == 0:
        d //= 2
        shifts += 1
    for base in (2, 325, 9375, 28178, 450775, 9780504, 1795265022):
        a = base % value
        if a == 0:
            continue
        x = pow(a, d, value)
        if x in (1, value - 1):
            continue
        for _ in range(shifts - 1):
            x = x * x % value
            if x == value - 1:
                break
        else:
            return False
    return True


def geometry(n, plaintext, primes):
    if n < 2 or n & (n - 1) or len(set(primes)) != len(primes):
        raise ValueError("ring size or ordered prime list is invalid")
    for prime in primes:
        if not prime64(prime) or (prime - 1) % (2 * n):
            raise ValueError(f"{prime} is not an admitted 2N-th-root NTT prime")
    return {
        "q_bits_exact": math.prod(primes).bit_length(),
        "plaintext_slots_degree_one": (plaintext - 1) % (2 * n) == 0,
        "ntt_primes_checked": len(primes),
    }


def native_row(source):
    n, plaintext, primes = source["n"], source["base"], source["primes"]
    geom = geometry(n, plaintext, primes)
    if geom["q_bits_exact"] != source["q_bits"]:
        raise ValueError(f"{source['name']}: stale or incorrect Q bit length")
    if not geom["plaintext_slots_degree_one"]:
        raise ValueError(f"{source['name']}: slot geometry does not split")
    exact = source["exact_multiply"]
    screen = source["security_screen"]
    if "refusal" not in exact and exact["q_bits"] != geom["q_bits_exact"]:
        raise ValueError(f"{source['name']}: exact multiply uses another Q")
    if "refusal" not in screen and screen["q_bits"] != geom["q_bits_exact"]:
        raise ValueError(f"{source['name']}: security screen uses another Q")

    failures = []
    if "refusal" in exact:
        refusal = exact["refusal"]
        aux = re.search(r"required_bits: (\d+), pool_bits: (\d+)", refusal)
        fallback = re.search(r"FallbackAccumulatorOverCapacity.*required_bits: (\d+)", refusal)
        if aux:
            required, available = map(int, aux.groups())
            if required <= available:
                raise ValueError("contradictory auxiliary capacity refusal")
            failures.append(f"exact auxiliary capacity: {required} > {available} bits")
        elif fallback:
            required = int(fallback.group(1))
            if required <= 256:
                raise ValueError("contradictory fallback accumulator refusal")
            failures.append(f"fallback accumulator: {required} > 256 bits")
        else:
            failures.append(f"exact-arithmetic constructor refused: {refusal}")
    elif exact["required_aux_bits"] > exact["aux_bits"]:
        raise ValueError("exact multiply marked admitted with insufficient auxiliary bits")

    target = 192 if source["name"] == "secure_192" else 256 if source["name"] == "secure_256" else 128
    if "refusal" in screen:
        failures.append(f"in-tree structural security screen refused: {screen['refusal']}")
    elif screen["binding_bits"] < target:
        failures.append(f"in-tree binding screen: {screen['binding_bits']} < {target} target bits")
    refusal = source["first_noise_refusal"]
    if refusal is None:
        raise ValueError(f"{source['name']}: archived canonical refusal is absent")
    half_scale = math.prod(primes) // (plaintext * plaintext) // 2
    error_bound = int(refusal["error_bound"])
    if (refusal["error_bits"] != error_bound.bit_length()
            or refusal["half_delta_bits"] != half_scale.bit_length()
            or error_bound < half_scale):
        raise ValueError("canonical refusal disagrees with exact integer bounds")
    failures.append(
        f"canonical certificate at depth {refusal['depth']}: "
        f"{refusal['error_bits']} > {refusal['half_delta_bits']} half-scale bits"
    )
    return {
        "name": source["name"],
        "route": "native_current_canonical_circuit",
        "n": n,
        "plaintext_modulus": plaintext,
        "ordered_ciphertext_primes": primes,
        **geom,
        "theoretical_ciphertext_multiplications_for_rejected_circuit": source["ciphertext_multiplication_count"],
        "theoretical_automorphisms_for_rejected_circuit": source["automorphism_count"],
        "theoretical_main_key_bytes_if_plan_admitted": source["key_main_bytes_if_plan_admitted"],
        "first_failing_inequality": failures[0],
        "other_known_failures": failures[1:],
        "production_admitted": False,
    }


def reference_row(name):
    path = ROOT / "artifacts/bootstrap" / (name + ".json")
    record = json.loads(path.read_text())
    if record["schema"] != "nine65-bfv-bootstrap-reference-v1":
        raise ValueError(f"{name}: unrecognized reference artifact")
    n, plaintext = record["n"], record["plaintext_modulus"]
    primes = record["ciphertext_primes"]
    geom = geometry(n, plaintext, primes)
    if not geom["plaintext_slots_degree_one"]:
        raise ValueError(f"{name}: slot geometry does not split")
    if not record["rounds"] or any(
        round_["checked_coefficients"] != n or round_["after_multiply_budget_bits"] <= 0
        for round_ in record["rounds"]
    ):
        raise ValueError(f"{name}: incomplete or failed coefficient check")
    run_path = path.with_suffix(".run.json")
    run = json.loads(run_path.read_text())
    if not run["successful_result"] or run["exit_code"] != 0:
        raise ValueError(f"{name}: run metadata reports failure")
    if run["artifacts"]["result"]["sha256"] != digest(path):
        raise ValueError(f"{name}: result hash differs from execution metadata")
    return {
        "name": name,
        "route": "external_functional_reference_only",
        "n": n,
        "plaintext_modulus": plaintext,
        "ordered_ciphertext_primes": primes,
        **geom,
        "digit_radius_trial": record["digit_bound"],
        "digit_polynomial_degree": 4 * record["digit_bound"] + 1,
        "observed_refresh_rounds": len(record["rounds"]),
        "observed_all_coefficient_checks": sum(x["checked_coefficients"] for x in record["rounds"]),
        "observed_total_ms": record["total_ms"],
        "observed_peak_rss_kib": run.get("max_child_rss_kib_linux"),
        "galois_key_count": record["galois_keys"],
        "key_payload_bytes": None,
        "circuit_multiplication_count": None,
        "first_failing_inequality": None,
        "missing_admission_evidence": [
            "live input radius bound", "certified operation DAG and per-node error",
            "native arithmetic and return-key cycle", "external joint security disposition",
        ],
        "security_attestation": record["security_attestation"],
        "production_admitted": False,
    }


def failed_reference_row():
    path = ROOT / "artifacts/bootstrap" / (FAILED_REFERENCE + ".json")
    run_path = path.with_suffix(".run.json")
    stderr_path = path.with_suffix(".stderr.log")
    run = json.loads(run_path.read_text())
    if run["successful_result"] or run["exit_code"] == 0:
        raise ValueError("failed reference unexpectedly reports success")
    if run["artifacts"]["result"]["sha256"] != digest(path):
        raise ValueError("failed reference output hash differs")
    if run["artifacts"]["stderr"]["sha256"] != digest(stderr_path):
        raise ValueError("failed reference error log hash differs")
    stderr = stderr_path.read_text()
    if "refresh plaintext mismatch in round 1" not in stderr:
        raise ValueError("failed reference lacks the recorded plaintext mismatch")
    return {
        "name": FAILED_REFERENCE,
        "route": "external_failed_reference_trial",
        "nominal_requested_q_bits": 820,
        "exact_tuple_available": False,
        "first_observed_failure": "round 1 refresh plaintext mismatch after a passed first refresh and square",
        "first_failing_inequality": None,
        "production_admitted": False,
    }


def build():
    archive = json.loads(CANONICAL.read_text())
    if archive["schema"] != "nine65-canonical-lift-feasibility-v1":
        raise ValueError("unrecognized canonical feasibility schema")
    probe = ROOT / "artifacts/bootstrap/canonical_lift_probe_2026-09-28.json"
    if digest(probe) != archive["probe_sha256"]:
        raise ValueError("canonical feasibility input probe changed")
    for relative, expected in archive["probe_source_sha256"].items():
        if digest(ROOT / relative) != expected:
            raise ValueError(f"canonical probe source changed: {relative}")
    if digest(ROOT / "scripts/canonical_lift_feasibility.py") != archive["oracle_sha256"]:
        raise ValueError("canonical feasibility oracle changed")
    native = [native_row(row) for row in archive["records"]]
    reference = [reference_row(name) for name in REFERENCE_NAMES]
    failed_reference = failed_reference_row()
    missing = [key for key, path in DEPENDENCIES.items() if not path.is_file()]
    # Presence is only a prerequisite; acceptance requires reviewing the
    # schedule, bound and security contents against the exact tuple.
    return {
        "schema": "nine65-bootstrap-candidate-ledger-v1",
        "decision": "BLOCKED_DESIGN",
        "chosen_production_tuple": None,
        "dependency_files_missing": missing,
        "source_sha256": {
            str(CANONICAL.relative_to(ROOT)): digest(CANONICAL),
            **{str((ROOT / "artifacts/bootstrap" / (name + ".json")).relative_to(ROOT)):
               digest(ROOT / "artifacts/bootstrap" / (name + ".json"))
               for name in REFERENCE_NAMES},
            **{str((ROOT / "artifacts/bootstrap" / (name + ".run.json")).relative_to(ROOT)):
               digest(ROOT / "artifacts/bootstrap" / (name + ".run.json"))
               for name in REFERENCE_NAMES},
            str((ROOT / "artifacts/bootstrap" / (FAILED_REFERENCE + ".run.json")).relative_to(ROOT)):
                digest(ROOT / "artifacts/bootstrap" / (FAILED_REFERENCE + ".run.json")),
            str((ROOT / "artifacts/bootstrap" / (FAILED_REFERENCE + ".stderr.log")).relative_to(ROOT)):
                digest(ROOT / "artifacts/bootstrap" / (FAILED_REFERENCE + ".stderr.log")),
        },
        "native_canonical_candidates": native,
        "external_reference_trials": reference,
        "rejected_reference_trials": [failed_reference],
        "admission_note": "Every native row rejects the archived full-domain canonical circuit. "
                          "Reference trials are functional observations, not native candidates "
                          "or security attestations. No bounded-digit candidate can be admitted "
                          "before its live radius, complete DAG/noise, key-cycle and security evidence.",
    }


def self_test():
    assert [prime64(x) for x in (2, 17, 561, 1105, 18446744073709551615)] == [True, True, False, False, False]
    assert geometry(8, 17, [97, 113])["q_bits_exact"] == (97 * 113).bit_length()
    try:
        geometry(8, 17, [97, 97])
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate prime was admitted")
    try:
        geometry(8, 17, [15])
    except ValueError:
        pass
    else:
        raise AssertionError("composite NTT modulus was admitted")
    report = build()
    assert len(report["native_canonical_candidates"]) == 14
    assert len(report["external_reference_trials"]) == 3
    assert len(report["rejected_reference_trials"]) == 1
    assert report["decision"] == "BLOCKED_DESIGN"
    assert not any(row["production_admitted"] for row in
                   report["native_canonical_candidates"] + report["external_reference_trials"])
    assert all(row["first_failing_inequality"] for row in report["native_canonical_candidates"])
    bad = json.loads(CANONICAL.read_text())["records"][0].copy()
    bad["q_bits"] += 1
    try:
        native_row(bad)
    except ValueError:
        pass
    else:
        raise AssertionError("stale Q width was admitted")
    print("bootstrap candidate self-test: 9 checks passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
        if args.output:
            args.output.write_text(json.dumps(build(), indent=2) + "\n")
    except (OSError, ValueError, KeyError, TypeError, AssertionError) as error:
        parser.exit(1, f"bootstrap candidate search failed: {error}\n")


if __name__ == "__main__":
    main()
