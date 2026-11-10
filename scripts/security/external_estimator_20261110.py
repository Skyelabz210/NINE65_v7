#!/usr/bin/env python3
"""Bounded, pinned external LWE marginal diagnostics; never security admission.

Run the controller with Sage's Python. Each selected attack is a separate
deadline-limited process. The exact factor list is retained, but upstream LWE
receives its product; these are not factorization-aware or joint-key estimates.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import subprocess
import sys
import time

REVISION = "f31b86fe490ab11abb4a69efa13007583791e10a"
SOURCE_COMMIT = "7ada6503634a824e80bc4bcfd6231ad0178d7ed3"
MODELS = ("matzov_classical", "adps16_quantum_lattice")
ATTACKS = ("usvp", "dual")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def check_source(source, lock_path):
    root = Path(source)
    lock = json.loads(Path(lock_path).read_text())
    if lock["revision"] != REVISION or lock["source_commit"] != SOURCE_COMMIT:
        raise ValueError("unexpected upstream or NINE65 source revision in lock")
    actual = {str(p.relative_to(root)): digest(p) for p in (root / "estimator").rglob("*.py")}
    if actual != lock["python_source_sha256"]:
        raise ValueError("upstream Python source set or digest differs from lock")
    return lock


def load_packet(path, lock):
    if digest(path) != lock["input_packet_sha256"]:
        raise ValueError("input packet digest differs from lock")
    packet = json.loads(Path(path).read_text())
    if (packet["schema"] != "nine65-independent-review-inputs-v1"
            or packet["legacy_tuple_provenance"]["source_packet_sha256"] != lock["parameter_distributions_sha256"]):
        raise ValueError("input schema or legacy packet binding mismatch")
    return packet


def targets(packet):
    result = []
    for p in packet["named_profiles"]:
        result.append({"name": p["name"], "n": p["n"], "primes": p["ordered_primes_decimal"],
                       "plaintext_moduli": [str(p["t"])], "eta": p["eta"],
                       "secret_model": "ideal_uniform_ternary",
                       "sampler_caveat": "next_u64()%3; idealization TV bound applies"})
    for p in packet["native_domains"]:
        sparse = p["domain"] == "Source"
        result.append({"name": "native_" + p["domain"].lower(), "n": p["n"],
                       "primes": p["ordered_primes_decimal"],
                       "plaintext_moduli": p["plaintext_moduli_decimal"], "eta": p["cbd_eta"],
                       "secret_model": "balanced_sparse_48_48" if sparse else "ideal_uniform_ternary",
                       "sampler_caveat": "fixed balanced H96 hidden support" if sparse else
                       ("exact rejection-sampled uniform ternary" if p["domain"] == "Outer" else
                        "next_u64()%3; idealization TV bound applies")})
    for p in packet.get("legacy_clockwork_bootstrap_profiles", []):
        result.append({"name": "legacy_bootstrap_" + p["owner_profile"], "n": p["n"],
                       "primes": p["ordered_primes_decimal"], "plaintext_moduli": [p["t_decimal"]],
                       "eta": p["eta"], "secret_model": "ideal_uniform_ternary",
                       "sampler_caveat": "next_u64()%3; independent boot key favors -1; circular mode inherits Work key; idealization TV bound applies"})
    # Work and both 128 labels share one exact modeled instance. Preserve aliases.
    unique = {}
    for p in result:
        p["q_decimal"] = str(math.prod(map(int, p["primes"])))
        p["q_bit_length"] = int(p["q_decimal"]).bit_length()
        p["error_model"] = "CenteredBinomial(eta), variance eta/2"
        p["samples"] = "infinity; modeling relaxation, not a count of published independent samples"
        if p["sampler_caveat"].startswith("next_u64"):
            p["secret_vector_tv_upper_bound"] = str(Fraction(2 * p["n"], 3 * (1 << 64)))
        key = (p["n"], tuple(p["primes"]), p["eta"], p["secret_model"])
        if key in unique:
            unique[key]["aliases"].append(p["name"])
        else:
            p["aliases"] = [p["name"]]
            unique[key] = p
    return list(unique.values())


def worker(args):
    lock = check_source(args.source, args.lock)
    sys.path.insert(0, str(Path(args.source).resolve()))
    from sage.all import RR, log, oo
    import sage.version
    import scipy
    from estimator import LWE, ND, RC
    from estimator.reduction import ADPS16

    spec = next(p for p in targets(load_packet(args.inputs, lock)) if p["name"] == args.target)
    secret = ND.SparseTernary(48, 48, spec["n"]) if spec["secret_model"] == "balanced_sparse_48_48" else ND.Uniform(-1, 1)
    params = LWE.Parameters(n=spec["n"], q=int(spec["q_decimal"]), Xs=secret,
                            Xe=ND.CenteredBinomial(spec["eta"]), m=oo)
    model = RC.MATZOV if args.model == "matzov_classical" else ADPS16(mode="quantum")
    if args.attack == "usvp":
        cost = LWE.primal_usvp(params, red_cost_model=model, red_shape_model="gsa")
    else:
        cost = LWE.dual(params, red_cost_model=model)
    bits = float(log(RR(cost["rop"]), 2))
    if not math.isfinite(bits) or bits < 0:
        raise ValueError("nonfinite or negative attack result")
    print("ESTIMATOR_RESULT=" + json.dumps({"status": "finite", "bits": bits,
          "cost": str(cost), "cost_fields": {str(k): str(v) for k, v in cost.items()},
          "parameters": repr(params), "sage_version": sage.version.version,
          "python_version": sys.version, "scipy_version": scipy.__version__,
          "red_shape_model": "gsa" if args.attack == "usvp" else "dual algorithm's analytic shape"}, allow_nan=False))


def parse_result(transcript, exit_code):
    markers = [line[len("ESTIMATOR_RESULT="):] for line in transcript.splitlines()
               if line.startswith("ESTIMATOR_RESULT=")]
    if exit_code != 0 or len(markers) != 1:
        return {"status": "error", "error": "nonzero worker exit or missing/duplicate marker"}
    result = json.loads(markers[0])
    required = ("cost", "cost_fields", "parameters", "sage_version", "python_version", "scipy_version", "red_shape_model")
    if (not isinstance(result, dict) or result.get("status") != "finite"
            or isinstance(result.get("bits"), bool) or not isinstance(result.get("bits"), (int, float))
            or not math.isfinite(result["bits"]) or result["bits"] < 0
            or not all(result.get(key) for key in required)):
        raise ValueError("invalid or incomplete worker result")
    return result


def complete(results, tasks):
    actual = {(r["target"], r["attack"], r["model"]) for r in results}
    return (len(results) == len(tasks) and actual == set(tasks)
            and all(r["status"] == "finite" for r in results))


def execute(args, target, attack, model):
    command = [sys.executable, str(Path(__file__).resolve()), "--worker", "--target", target,
               "--attack", attack, "--model", model, "--source", args.source,
               "--lock", args.lock, "--inputs", args.inputs]
    started = time.monotonic()
    transcript = ""
    try:
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, timeout=args.timeout)
        transcript = completed.stdout
        result = parse_result(transcript, completed.returncode)
        result.update(transcript=transcript, exit_code=completed.returncode)
    except subprocess.TimeoutExpired as exc:
        result = {"status": "timeout", "transcript": (exc.stdout or b"").decode("utf-8", "replace")}
    except (ValueError, OSError) as exc:
        result = {"status": "error", "error_type": type(exc).__name__, "error": str(exc),
                  "transcript": transcript}
    result.update(target=target, attack=attack, model=model, command=command,
                  elapsed_seconds=time.monotonic() - started)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--lock", required=True)
    parser.add_argument("--inputs", required=True)
    parser.add_argument("--output")
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--target")
    parser.add_argument("--attack", choices=ATTACKS)
    parser.add_argument("--model", choices=MODELS)
    args = parser.parse_args()
    lock = check_source(args.source, args.lock)
    if args.worker:
        worker(args)
        return 0
    if args.jobs < 1 or args.timeout < 1:
        raise ValueError("positive resource bounds required")
    if not args.output:
        raise ValueError("controller requires --output")
    output = Path(args.output)
    if output.exists():
        raise ValueError("refusing to overwrite evidence")
    packet = load_packet(args.inputs, lock)
    instances = targets(packet)
    tasks = [(p["name"], attack, model) for p in instances for attack in ATTACKS for model in MODELS]
    report = {"schema": "nine65-external-marginal-estimator-v1", "source_commit": SOURCE_COMMIT,
              "upstream": lock, "driver_sha256": digest(__file__), "inputs_sha256": digest(args.inputs),
              "review_packet_sha256": lock["review_packet_sha256"],
              "parameter_distributions_sha256": lock["parameter_distributions_sha256"],
              "input_key_publication_fingerprint": packet["key_publication_fingerprint"],
              "targets": instances, "expected_tasks": tasks, "deadline_seconds_per_task": args.timeout,
              "jobs": args.jobs, "results": [], "focused_run_complete": False,
              "joint_key_security_proven": False, "factorization_aware_ring_coverage_complete": False,
              "quantum_attack_coverage_complete": False, "external_parameter_attestation_obtained": False,
              "production_admitted": False,
              "limitations": ["two selected attacks on idealized standalone generic-LWE marginals only",
                  "prime factors retained as evidence; upstream receives scalar product and does not assess ring factorization",
                  "m=infinity is a modeling relaxation; structured ring samples and publication correlations are not independent LWE samples",
                  "ADPS16 quantum lattice-reduction cost is not a complete quantum attack assessment",
                  "return-key embedded Work secret and seven-relation publication graph are not modeled",
                  "no independent reviewer or signed attestation; no security lower bound"]}
    def save():
        output.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    save()
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = [pool.submit(execute, args, *task) for task in tasks]
        for future in as_completed(futures):
            result = future.result()
            report["results"].append(result)
            save()
            print(json.dumps({k: result.get(k) for k in ("target", "attack", "model", "status", "bits", "elapsed_seconds")}), flush=True)
    report["focused_run_complete"] = complete(report["results"], tasks)
    save()
    return 0 if report["focused_run_complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
