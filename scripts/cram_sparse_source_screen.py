#!/usr/bin/env python3
"""Pinned external attack assessment for CRAM's internal source candidates.

Run with Sage, not the in-tree dense-only parameter screen. Every attack
gets an isolated process and a deadline. Missing/error/timeout results keep
the assessment incomplete. This script NEVER enables production admission.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
from math import prod
import os
from pathlib import Path
import subprocess
import sys
import time

UPSTREAM_REV = "f31b86fe490ab11abb4a69efa13007583791e10a"
ROTATED_REV = "aa2c40d4eee4551e6fba06c55d7432f6918e1597"
ROTATED_DEPENDENCY_REV = "6019056011d10d7e9c30a0d5da2d2f729fbc2eec"
WORK = (998244353, 985661441, 754974721, 469762049)
SOURCE = WORK[:2]
PROFILES = {
    "old32_high_q": {"n": 8192, "positive": 16, "negative": 16,
                     "primes": WORK, "purpose": "rejected prior conditional candidate"},
    "balanced96_low_q": {"n": 8192, "positive": 48, "negative": 48,
                         "primes": SOURCE, "purpose": "internal source candidate"},
    "binary96_low_q": {"n": 8192, "positive": 96, "negative": 0,
                       "primes": SOURCE, "purpose": "positive-controls-only source candidate"},
}
UPSTREAM_ATTACKS = ("usvp", "bdd", "bdd_hybrid", "bdd_mitm_hybrid", "dual",
                    "dual_hybrid", "bkw", "arora-gb")
ROTATED_ATTACKS = ("projected-cvp", "without-mitm", "mitm-square-root", "mitm-estimator")
MODELS = ("matzov_classical", "adps16_quantum_lattice")


def describe(name):
    p = dict(PROFILES[name])
    p.update(q=prod(p["primes"]), error={"distribution": "CenteredBinomial", "eta": 3},
             samples="infinity (conservative)",
             source_support_public=False, production_admitted=False)
    return p


def worker(args):
    # Import only after worker selection: --describe and the controller are
    # ordinary Python. Each engine uses its OWN pinned distribution types.
    from sage.all import RR, floor, log, oo
    import sage.version
    import faulthandler
    faulthandler.dump_traceback_later(60, repeat=True)
    spec = describe(args.profile)
    computational_acceleration = None
    if args.engine == "upstream":
        sys.path.insert(0, str(Path(args.upstream).resolve()))
        from estimator import LWE, ND, RC
        from estimator.reduction import ADPS16
        params = LWE.Parameters(n=spec["n"], q=spec["q"],
                                Xs=ND.SparseTernary(spec["positive"], spec["negative"], spec["n"]),
                                Xe=ND.CenteredBinomial(3), m=oo)
        model = RC.MATZOV if args.model == "matzov_classical" else ADPS16(mode="quantum")
        common = dict(red_cost_model=model, red_shape_model="gsa")
        if args.attack == "usvp":
            cost = LWE.primal_usvp(params, **common)
        elif args.attack == "bdd":
            cost = LWE.primal_bdd(params, **common)
        elif args.attack == "bdd_hybrid":
            cost = LWE.primal_hybrid(params, mitm=False, babai=False, **common)
        elif args.attack == "bdd_mitm_hybrid":
            cost = LWE.primal_hybrid(params, mitm=True, babai=True, **common)
        elif args.attack == "dual":
            cost = LWE.dual(params, red_cost_model=model)
        elif args.attack == "dual_hybrid":
            cost = LWE.dual_hybrid(params, red_cost_model=model)
        elif args.attack == "bkw":
            cost = LWE.coded_bkw(params)
        elif args.attack == "arora-gb":
            import estimator.gb as gb_module
            from cram_gb_series import install_verified_upstream_adapter
            computational_acceleration = install_verified_upstream_adapter(gb_module)
            cost = LWE.guess_composition(LWE.arora_gb)(params)
        else:
            raise ValueError("unknown upstream attack")
    else:
        sys.path.insert(0, str(Path(args.rotated).resolve() / "PrimalHybrid"))
        from lattice_estimator.estimator import LWE, ND, RC
        from lattice_estimator.estimator.reduction import ADPS16
        from lwe_rot_primal import rot_primal_hybrid
        params = LWE.Parameters(n=spec["n"], q=spec["q"],
                                Xs=ND.SparseTernary(spec["positive"], spec["negative"], spec["n"]),
                                Xe=ND.CenteredBinomial(3), m=oo)
        model = RC.MATZOV if args.model == "matzov_classical" else ADPS16(mode="quantum")
        options = {"projected-cvp": dict(babai=False, mitm=False),
                   "without-mitm": dict(babai=True, mitm=False),
                   "mitm-square-root": dict(babai=True, mitm=True, mitm_heuristic="square root"),
                   "mitm-estimator": dict(babai=True, mitm=True, mitm_heuristic="estimator")}
        cost = rot_primal_hybrid(params, poly_degree=spec["n"], red_cost_model=model, red_shape_model="gsa",
                                **options[args.attack])
    rop = cost["rop"]
    bits = None if rop == oo else float(log(RR(rop), 2))
    # Infinity is explicitly inconclusive, not evidence of unbounded security.
    print("CRAM_RESULT=" + json.dumps({"status": "finite" if bits is not None else "infinite",
          "bits": bits, "floor_bits": None if bits is None else int(floor(log(RR(rop), 2))),
          "cost": str(cost), "sage_version": sage.version.version,
          "parameters": repr(params), "red_shape_model": "gsa",
          "computational_acceleration": computational_acceleration}))


def execute(args, engine, attack, model):
    command = [sys.executable, str(Path(__file__).resolve()), "--worker",
               "--profile", args.profile, "--engine", engine, "--attack", attack,
               "--model", model, "--upstream", args.upstream, "--rotated", args.rotated]
    started = time.monotonic()
    try:
        completed = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, timeout=args.attack_timeout)
        lines = completed.stdout.splitlines()
        marker = next((line for line in reversed(lines) if line.startswith("CRAM_RESULT=")), None)
        result = json.loads(marker[len("CRAM_RESULT="):]) if marker and completed.returncode == 0 else {
            "status": "error", "exit_code": completed.returncode}
        result["transcript"] = completed.stdout
    except subprocess.TimeoutExpired as error:
        result = {"status": "timeout", "transcript": (error.stdout or b"").decode("utf-8", "replace")}
    result.update(engine=engine, attack=attack, model=model, elapsed_seconds=time.monotonic() - started)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=PROFILES, required=True)
    parser.add_argument("--describe", action="store_true")
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--engine", choices=("upstream", "rotated"))
    parser.add_argument("--attack")
    parser.add_argument("--model", choices=MODELS)
    parser.add_argument("--upstream", default="/upstream")
    parser.add_argument("--rotated", default="/rotated")
    parser.add_argument("--output", default="source-screen.json")
    parser.add_argument("--resume")
    parser.add_argument("--resume-sha256")
    parser.add_argument("--attack-timeout", type=int, default=75)
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    if args.describe:
        print(json.dumps(describe(args.profile), indent=2))
        return 0
    if args.worker:
        worker(args)
        return 0
    if args.jobs < 1 or args.attack_timeout < 1:
        raise ValueError("positive worker and timeout limits required")
    report = {"profile": args.profile, "parameters": describe(args.profile),
              "upstream_revision": UPSTREAM_REV, "rotated_revision": ROTATED_REV,
              "rotated_dependency_revision": ROTATED_DEPENDENCY_REV,
              "driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "gb_recurrence_sha256": hashlib.sha256(Path(__file__).with_name("cram_gb_series.py").read_bytes()).hexdigest(),
              "results": [], "assessment_complete": False,
              "quantum_hybrid_coverage_complete": False,
              "concurrent_hou_jiang_2026_366_covered": False,
              "joint_key_security_proven": False, "production_admitted": False}
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    if args.resume:
        raw = Path(args.resume).read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if not args.resume_sha256 or digest != args.resume_sha256:
            raise ValueError("checkpoint hash mismatch")
        previous = json.loads(raw)
        for key in ["profile", "upstream_revision", "rotated_revision", "rotated_dependency_revision"]:
            if previous[key] != report[key]:
                raise ValueError("checkpoint parameter/revision mismatch: " + key)
        if json.dumps(previous["parameters"], sort_keys=True) != json.dumps(report["parameters"], sort_keys=True):
            raise ValueError("checkpoint source distribution mismatch")
        report["resumed_from_sha256"] = digest
        report["results"] = [r for r in previous["results"] if r["status"] == "finite"]
        report["previous_incomplete_results"] = [r for r in previous["results"] if r["status"] != "finite"]
    def save():
        output.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    save()
    tasks = [(engine, attack, model) for model in MODELS
             for engine, attacks in [("upstream", UPSTREAM_ATTACKS), ("rotated", ROTATED_ATTACKS)]
             for attack in attacks]
    retained = {(r["engine"], r["attack"], r["model"]) for r in report["results"]}
    tasks = [task for task in tasks if task not in retained]
    print(json.dumps({"retained_finite_results": len(retained), "remaining_searches": len(tasks)}), flush=True)
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = [pool.submit(execute, args, *task) for task in tasks]
        for future in as_completed(futures):
            result = future.result()
            report["results"].append(result)
            save()
            print(json.dumps({k: result.get(k) for k in ["engine", "attack", "model", "status", "bits", "elapsed_seconds"]}), flush=True)
    report["assessment_complete"] = all(r["status"] == "finite" for r in report["results"])
    report["minimum_tested_bits_by_model"] = {
        model: min((r["bits"] for r in report["results"] if r["model"] == model and r["status"] == "finite"), default=None)
        for model in MODELS}
    save()
    # The old profile is an expected rejection; all results are still required.
    return 0 if report["assessment_complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
