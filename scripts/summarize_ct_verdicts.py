#!/usr/bin/env python3
"""Preserve dudect's three-valued evidence separately from the CI process result.

Displayed statistics are rounded; verdicts come from the Rust harness, whose
threshold and inconclusive policy this collector does not change.
"""
import argparse
from decimal import Decimal, InvalidOperation
import hashlib
import json
from pathlib import Path
import re


PREFIX = "security::ct_verification::constant_time_statistical"
EXPECTED_OBSERVATIONS = {
    "test_ct_dudect_montgomery_pow_exponent_hamming_weight": 1,
    "test_ct_dudect_montgomery_reduce_operand_magnitude": 1,
    "test_ct_dudect_montgomery_mul_operand_magnitude": 1,
    "test_ct_dudect_barrett_reduce_operand_magnitude": 1,
    "test_ct_dudect_mod_switch_rescale_sign_classes": 1,
    # This exact test measures both U512 reduction and the full rescale.
    "test_ct_dudect_mod_switch_rescale_fixed_vs_random": 2,
    "test_ct_dudect_exact_prime_drop_fixed_vs_random": 1,
    "test_ct_dudect_exact_prime_drop_small_vs_large_residues": 1,
    "test_ct_dudect_adjacency_k_elim_operand_magnitude": 1,
    "test_ct_dudect_adjacency_k_elim_operand_order": 1,
}
VERDICTS = {
    "CONSTANT-TIME at this sample size": "below_threshold",
    "INCONCLUSIVE": "inconclusive",
    "TIMING DEPENDENCE MEASURED": "timing_dependence",
}
RESULT = re.compile(r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;", re.M)
REPORT = re.compile(r"^--- dudect: (.*?) ---\s*$", re.M)
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def observations(text):
    reports = list(REPORT.finditer(text))
    result = []
    for i, match in enumerate(reports):
        block = text[match.end():reports[i + 1].start() if i + 1 < len(reports) else len(text)]
        verdicts = re.findall(r"^\s*VERDICT: (.+)$", block, re.M)
        controls = re.findall(r"^\s*t_control .*?= (\S+)\s*$", block, re.M)
        signals = re.findall(r"^\s*t_signal .*?= (\S+)\s*$", block, re.M)
        samples = re.findall(r"^\s*samples kept (\d+)/(\d+) after ", block, re.M)
        if not (len(verdicts) == len(controls) == len(signals) == len(samples) == 1):
            raise ValueError("each observable requires one verdict, control, signal and sample count")
        for statistic in (controls[0], signals[0]):
            try:
                number = Decimal(statistic)
            except InvalidOperation as error:
                raise ValueError("unrecognized statistic") from error
            if number.is_nan() or number < 0:
                raise ValueError("invalid statistic")
        kept, total = map(int, samples[0])
        if not 0 < kept <= total:
            raise ValueError("invalid sample counts")
        verdict = next((value for prefix, value in VERDICTS.items()
                        if verdicts[0].startswith(prefix)), None)
        if verdict is None:
            raise ValueError("unrecognized verdict")
        result.append({"label": match.group(1), "verdict": verdict,
                       "t_control_display": controls[0], "t_signal_display": signals[0],
                       "samples_kept": kept, "samples_total": total})
    return result


def summarize(directory, expected=None):
    expected = EXPECTED_OBSERVATIONS if expected is None else expected
    directory = Path(directory)
    errors, tests, statuses = [], [], {}
    ledger = directory / "status.tsv"
    ledger_bytes = ledger.read_bytes() if ledger.is_file() else b""
    if not ledger_bytes:
        errors.append("missing or empty process-status ledger")
    for line in ledger_bytes.decode("utf-8", errors="replace").splitlines():
        try:
            name, cargo, capture = line.split("\t")
            cargo, capture = int(cargo), int(capture)
            if name not in expected or name in statuses or not (0 <= cargo <= 255 and 0 <= capture <= 255):
                raise ValueError()
            statuses[name] = (cargo, capture)
        except ValueError:
            errors.append("unknown, duplicate or malformed process-status entry")
    for name, count in expected.items():
        record = {"test": f"{PREFIX}::{name}", "observations": []}
        tests.append(record)
        if name not in statuses:
            errors.append(f"{name}: missing invocation")
            continue
        cargo, capture = statuses[name]
        record.update(process_exit=cargo, capture_exit=capture)
        if capture:
            errors.append(f"{name}: log capture failed")
        try:
            raw = (directory / f"{name}.log").read_bytes()
            record["log_sha256"] = hashlib.sha256(raw).hexdigest()
            text = ANSI.sub("", raw.decode("utf-8", errors="replace"))
            if len(re.findall(rf"^test {re.escape(record['test'])} \.\.\.", text, re.M)) != 1:
                raise ValueError("expected exactly one invocation of the named test")
            results = RESULT.findall(text)
            if len(results) != 1:
                raise ValueError("missing or duplicate Rust test-result summary")
            outcome, passed, failed, ignored = results[0]
            passed, failed, ignored = int(passed), int(failed), int(ignored)
            if ignored or passed + failed != 1:
                raise ValueError("expected one executed test and no ignores")
            record["executed_tests"] = passed + failed
            record["observations"] = observations(text)
            if len(record["observations"]) != count:
                raise ValueError(f"expected {count} observables, found {len(record['observations'])}")
            dependence = any(o["verdict"] == "timing_dependence" for o in record["observations"])
            if cargo == 0:
                if (outcome, passed, failed) != ("ok", 1, 0) or dependence:
                    raise ValueError("process success contradicts test result or measured dependence")
            elif (outcome, passed, failed) != ("FAILED", 0, 1) or not dependence:
                raise ValueError("unexpected process failure, not a measured timing assertion")
        except (OSError, ValueError) as error:
            errors.append(f"{name}: {error}")
    counts = {verdict: 0 for verdict in VERDICTS.values()}
    for test in tests:
        for observed in test["observations"]:
            counts[observed["verdict"]] += 1
    status = ("invalid" if errors else "timing_dependence" if counts["timing_dependence"]
              else "inconclusive" if counts["inconclusive"] else "below_threshold")
    return {"schema": "nine65-ct-dudect-evidence-v1", "threshold": "5",
            "evidence_status": status, "observations": counts,
            "blocking_gate_pass": status in ("inconclusive", "below_threshold"),
            "all_observations_conclusive": not errors and not counts["inconclusive"],
            "constant_time_established": False,
            "statistics_scope": "rounded display values; classification preserves the Rust verdict",
            "status_ledger_sha256": hashlib.sha256(ledger_bytes).hexdigest(),
            "tests": tests, "errors": errors}


def markdown(summary):
    lines = ["### Dudect measurement evidence", "",
             f"Evidence status: **{summary['evidence_status']}**. Constant-time certification is not established.",
             "Inconclusive observations retain the existing nonblocking policy; they are not below-threshold evidence.", "",
             "| Test | Observable | Measurement verdict | Control t | Signal t |",
             "| --- | --- | --- | --- | --- |"]
    for test in summary["tests"]:
        name = test["test"].rsplit("::", 1)[-1]
        for observed in test["observations"]:
            label = observed["label"].replace("|", "\\|")
            lines.append(f"| {name} | {label} | {observed['verdict']} | {observed['t_control_display']} | {observed['t_signal_display']} |")
    if summary["errors"]:
        lines.extend(["", "Collection errors:", ""] + [f"- {error}" for error in summary["errors"]])
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--markdown", type=Path, required=True)
    parser.add_argument("--source-sha")
    parser.add_argument("--checkout-sha")
    args = parser.parse_args()
    summary = summarize(args.input_dir)
    summary.update(source_sha=args.source_sha, checkout_sha=args.checkout_sha)
    for path in (args.output, args.markdown):
        path.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2) + "\n")
    args.markdown.write_text(markdown(summary))
    print(json.dumps({key: summary[key] for key in ("evidence_status", "observations", "blocking_gate_pass")}))
    return 0 if summary["blocking_gate_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
