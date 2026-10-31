#!/usr/bin/env python3
"""Run the pinned authors' enhanced primal-hybrid estimator, not a KDM proof.

Controller and --describe work without Sage. Workers require Sage. The
authors' coarse/fine optimization and probability model are used unchanged;
this does not validate the corrected Theorem 3.1 or claim complete coverage.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from cram_sparse_source_screen import describe, MODELS

LOCK = Path(__file__).with_name("security") / "hou_jiang_source_lock.json"
TASKS = tuple((model, variant) for model in MODELS for variant in ("baseline", "enhanced"))


def verify_source(root, lock):
    root = Path(root).resolve()
    if not lock.get("files"):
        raise ValueError("empty estimator source manifest")
    actual = {str(p.relative_to(root)) for p in (root / "lattice-estimator/estimator").rglob("*.py")}
    if actual != set(lock["files"]):
        raise ValueError("estimator source manifest differs from pinned file set")
    for name, expected in lock["files"].items():
        path = (root / name).resolve()
        if not path.is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError("estimator source hash mismatch: " + name)


def complete(results):
    identities = [(r.get("model"), r.get("variant")) for r in results]
    return (len(identities) == len(TASKS) and set(identities) == set(TASKS)
            and all(r.get("status") == "finite" and isinstance(r.get("bits"), (float, int))
                    and not isinstance(r["bits"], bool) and math.isfinite(r["bits"])
                    and r["bits"] >= 0 for r in results))


def worker(args, lock):
    verify_source(args.source, lock)
    sys.path.insert(0, str(Path(args.source).resolve() / "lattice-estimator"))
    from sage.all import RR, log, oo
    import sage.version
    import faulthandler
    faulthandler.dump_traceback_later(60, repeat=True)
    from estimator import LWE, ND, RC
    from estimator.reduction import ADPS16
    spec = describe("balanced96_low_q")
    params = LWE.Parameters(n=spec["n"], q=spec["q"],
                            Xs=ND.SparseTernary(spec["positive"], spec["negative"], spec["n"]),
                            Xe=ND.CenteredBinomial(spec["error"]["eta"]), m=oo)
    model = RC.MATZOV if args.model == "matzov_classical" else ADPS16(mode="quantum")
    # The authors' routine writes a diagnostic NumPy profile relative to cwd.
    # Isolate each worker's scratch output without changing the cost model or
    # allowing writes into either pinned source tree.
    with tempfile.TemporaryDirectory(prefix="cram-hou-jiang-") as scratch:
        previous = Path.cwd()
        try:
            os.chdir(scratch)
            cost = LWE.primal_hybrid(params, babai=True, mitm=False, deg_ring=spec["n"],
                                    structure_leverage=args.variant == "enhanced",
                                    red_shape_model="gsa", red_cost_model=model)
        finally:
            os.chdir(previous)
    bits = None if cost["rop"] == oo else float(log(RR(cost["rop"]), 2))
    print("CRAM_RESULT=" + json.dumps({
        "status": "finite" if bits is not None and math.isfinite(bits) else "inconclusive",
        "bits": bits if bits is not None and math.isfinite(bits) else None,
        "cost": str(cost), "parameters": repr(params), "sage_version": sage.version.version,
        "red_shape_model": "gsa", "babai": True, "mitm": False,
        "structure_leverage": args.variant == "enhanced",
    }, allow_nan=False))


def execute(args, model, variant):
    started = time.monotonic()
    command = [sys.executable, str(Path(__file__).resolve()), "--worker", "--source", args.source,
               "--model", model, "--variant", variant]
    try:
        process = subprocess.run(command, capture_output=True, text=True, timeout=args.timeout)
        marker = next((line[12:] for line in reversed(process.stdout.splitlines())
                       if line.startswith("CRAM_RESULT=")), None)
        result = json.loads(marker) if process.returncode == 0 and marker else {
            "status": "error", "exit_code": process.returncode}
        result["transcript"] = process.stdout + process.stderr
    except subprocess.TimeoutExpired as error:
        result = {"status": "timeout", "transcript":
                  (error.stdout or b"").decode("utf-8", "replace") +
                  (error.stderr or b"").decode("utf-8", "replace")}
    except (ValueError, OSError) as error:
        result = {"status": "error", "detail": str(error)}
    result.update(model=model, variant=variant, elapsed_seconds=time.monotonic() - started)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="/hou")
    parser.add_argument("--output", default="hou-jiang-screen.json")
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--describe", action="store_true")
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--model", choices=MODELS)
    parser.add_argument("--variant", choices=("baseline", "enhanced"))
    args = parser.parse_args()
    if args.timeout < 1 or args.jobs < 1:
        parser.error("positive timeout and job count required")
    lock = json.loads(LOCK.read_text())
    if args.describe:
        print(json.dumps({"parameters": describe("balanced96_low_q"), "source_lock": lock,
                          "tasks": TASKS, "production_admitted": False}, indent=2))
        return 0
    if args.worker:
        if args.model is None or args.variant is None:
            parser.error("worker requires model and variant")
        worker(args, lock)
        return 0
    verify_source(args.source, lock)
    report = {
        "scope": "pinned authors' implementation; optimized primal Babai, no MITM",
        "parameters": describe("balanced96_low_q"), "source_lock": lock,
        "driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "profile_driver_sha256": hashlib.sha256(Path(__file__).with_name(
            "cram_sparse_source_screen.py").read_bytes()).hexdigest(),
        "required_tasks": TASKS, "results": [], "pinned_implementation_run_complete": False,
        "corrected_theorem_3_1_validated": False,
        "quantum_hybrid_coverage_complete": False, "joint_key_security_proven": False,
        "production_admitted": False,
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise ValueError("refusing to overwrite existing evidence: " + str(output))
    def save():
        output.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    save()
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = [pool.submit(execute, args, *task) for task in TASKS]
        for future in as_completed(futures):
            result = future.result()
            report["results"].append(result)
            save()
            print(json.dumps({k: result.get(k) for k in
                              ("model", "variant", "status", "bits", "elapsed_seconds")}), flush=True)
    report["pinned_implementation_run_complete"] = complete(report["results"])
    save()
    return 0 if report["pinned_implementation_run_complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
