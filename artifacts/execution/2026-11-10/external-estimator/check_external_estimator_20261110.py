#!/usr/bin/env python3
"""Positive/negative evidence-boundary controls; no cryptanalytic estimates."""

import argparse
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
import tempfile
from unittest.mock import patch

import external_estimator_20261110 as driver


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--inputs", required=True)
    parser.add_argument("--lock", required=True)
    args = parser.parse_args()
    lock = driver.check_source(args.source, args.lock)
    packet = driver.load_packet(args.inputs, lock)
    controls = ["exact source manifest accepted", "exact input packet accepted"]
    with tempfile.TemporaryDirectory(prefix="nine65-external-controls-") as directory:
        root = Path(directory)
        bad_lock = dict(lock)
        bad_lock["python_source_sha256"] = dict(lock["python_source_sha256"])
        bad_lock["python_source_sha256"]["estimator/nd.py"] = "0" * 64
        path = root / "bad-lock.json"
        path.write_text(json.dumps(bad_lock))
        try:
            driver.check_source(args.source, path)
        except ValueError:
            controls.append("changed source digest rejected")
        else:
            raise AssertionError("changed source digest accepted")
        path = root / "changed-input.json"
        path.write_bytes(Path(args.inputs).read_bytes() + b" ")
        try:
            driver.load_packet(path, lock)
        except ValueError:
            controls.append("changed input bytes rejected")
        else:
            raise AssertionError("changed input bytes accepted")
    modeled = driver.targets(packet)
    assert len(modeled) == 8 and sum(len(p["aliases"]) for p in modeled) == 11
    assert modeled[0]["aliases"] == ["secure_128", "secure_128_deep", "native_work"]
    assert next(p for p in modeled if p["name"] == "native_source")["q_decimal"] == "983930967448092673"
    controls.append("eight exact tuples retain eleven aliases and exact sparse modulus")
    finite = {"status": "finite", "bits": 100.0, "cost": "fixture", "cost_fields": {"rop": "fixture"},
              "parameters": "fixture", "sage_version": "fixture", "python_version": "fixture",
              "scipy_version": "fixture", "red_shape_model": "fixture"}
    marker = "ESTIMATOR_RESULT=" + json.dumps(finite) + "\n"
    assert driver.parse_result(marker, 0)["status"] == "finite"
    controls.append("well-formed finite fixture accepted")
    worker_args = SimpleNamespace(source=args.source, inputs=args.inputs, lock=args.lock, timeout=1)
    fixtures = [("malformed JSON", "ESTIMATOR_RESULT={broken\n", 0),
                ("bogus success", 'ESTIMATOR_RESULT={"status":"finite","bits":100}\n', 0),
                ("nonfinite cost", "ESTIMATOR_RESULT=" + json.dumps(dict(finite, bits=float("nan"))), 0),
                ("negative cost", "ESTIMATOR_RESULT=" + json.dumps(dict(finite, bits=-1)), 0),
                ("duplicate marker", marker + marker, 0), ("missing marker", "", 0),
                ("nonzero worker exit", marker, 1)]
    for name, transcript, exit_code in fixtures:
        with patch.object(driver.subprocess, "run", return_value=SimpleNamespace(stdout=transcript, returncode=exit_code)):
            result = driver.execute(worker_args, "fixture", "usvp", "matzov_classical")
        assert result["status"] == "error" and result["transcript"] == transcript
        controls.append(name + " retained as per-task error")
    with patch.object(driver.subprocess, "run", side_effect=OSError("fixture launch failure")):
        assert driver.execute(worker_args, "fixture", "usvp", "matzov_classical")["status"] == "error"
    controls.append("worker launch error retained")
    with patch.object(driver.subprocess, "run", side_effect=subprocess.TimeoutExpired(["fixture"], 1, output=b"partial")):
        result = driver.execute(worker_args, "fixture", "usvp", "matzov_classical")
        assert result["status"] == "timeout" and result["transcript"] == "partial"
    controls.append("deadline retains timeout and partial transcript")
    tasks = [("fixture", "usvp", model) for model in driver.MODELS]
    results = [dict(target=t, attack=a, model=m, status="finite") for t, a, m in tasks]
    assert driver.complete(results, tasks)
    assert not driver.complete(results[:1], tasks)
    assert not driver.complete([results[0], results[0]], tasks)
    assert not driver.complete([results[0], dict(results[1], status="timeout")], tasks)
    controls.append("completion requires every distinct task finite; missing, duplicate, timeout rejected")
    print(json.dumps({"status": "pass", "control_count": len(controls), "controls": controls,
                      "scope": "evidence harness controls; no real attack result in fixtures"}, indent=2))


if __name__ == "__main__":
    main()
