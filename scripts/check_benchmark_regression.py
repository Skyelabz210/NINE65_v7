#!/usr/bin/env python3
"""Detect FHE operation timing regressions against a committed baseline.

Answers the gap issue #19 identifies: `crates/nine65/tests/op_timings.rs`
already measures encrypt/add/public-mul/symmetric-mul/decrypt per secure
config, and `.github/workflows/ci.yml`'s "T4 - Benchmark Regression" job
already exists -- but that job runs `scripts/regression_scan.sh` (a *source*
gate: test-count floor, float/panic scan) plus a Criterion *smoke* run
(`cargo bench -- --test`, one sample per benchmark, no statistics). Neither
compares a timing number to anything. This script is the missing comparison.

Everything here is integer arithmetic on nanosecond counts. Per CLAUDE.md's
"Important Coding Rules" ("any benchmark reporting must use integer-only
timing/statistics, e.g. nanoseconds as u64, not floating-point seconds"),
no float ever appears in a sample, a median, or a delta -- deltas are
computed as basis points (1/100 of a percent) via integer multiply/floor-div,
matching `crates/nine65/tests/op_timings.rs`'s own integer-only median and ms
formatting on the Rust side.

## Workflow

1. Capture a run (writes `bench-results/op_timings.json` by default):

     cargo test -p nine65 --test op_timings --release --features allow_insecure \\
       -- --ignored --nocapture

2. Compare it against the committed baseline:

     python3 scripts/check_benchmark_regression.py

   Exits 0 and prints PASS/IMPROVED rows if nothing regressed past the
   threshold; exits 1 and prints REGRESSION rows otherwise.

3. Reduce noise by pooling repeated runs (recommended -- see "Threshold and
   noise" below). Point `--current` at N capture files from N separate
   invocations of step 1 (re-run step 1 between each, moving or copying
   `bench-results/op_timings.json` aside, or set `$NINE65_BENCH_JSON_OUT` to
   a distinct path per run):

     python3 scripts/check_benchmark_regression.py \\
       --current bench-results/run1.json bench-results/run2.json bench-results/run3.json

4. Update the baseline after an intentional, reviewed performance change:

     python3 scripts/check_benchmark_regression.py --update-baseline \\
       --current bench-results/run1.json bench-results/run2.json bench-results/run3.json

   This is the "documented process for updating one" -- there is no separate
   tool. Review the resulting diff to `docs/benchmarks/op_timings_baseline.json`
   like any other source change before committing it.

## Matching: config TUPLE, never config NAME

CLAUDE.md documents `secure_128` being silently redefined once already
(N=4096, 3 primes -> N=8192, 3 primes -> 4 primes, three separate tuples
under one unchanged name across the project's history) -- a name-keyed
comparison across that kind of change is meaningless, silently comparing two
different workloads. So every config is matched by its full tuple --
`(n, primes, t)`, read straight out of the JSON capture -- not by the
`config` name string. A capture whose tuple has no baseline entry is reported
as `NO BASELINE`, not skipped silently and not force-matched onto a
same-named-but-different entry.

## Threshold and noise

Default: **25%** (`--threshold-percent 25`), applied to the ratio of a
pooled median. This is not an arbitrary round number:

- `docs/roadmap/T5_BENCHMARKS_AND_REPRODUCIBILITY.md` and
  `docs/CRAM_PUBLIC_BASELINE_2026-08-26.md` already establish and use a >25%
  median-regression rule for this exact house benchmarking pattern (medians
  over repeated in-process rounds, `op_timings.rs`-style), deliberately
  looser than the ~20% run-to-run reproduce-window CLAUDE.md and README.md
  document for the same harness ("Run-to-run spread on secure_128 public mul
  across four separate invocations was 281-302ms" -- an ~7% half-spread
  around the ~292ms median, i.e. an observed peak-to-peak range of about 14%
  of the median on a "4 vCPU shared container" under real contention). This
  script's default matches that existing, already-reasoned house number
  instead of inventing a new one.
- 25% sits comfortably above the ~14% peak-to-peak spread CLAUDE.md measured
  on this exact container class, so ordinary scheduling noise on a shared
  runner should not false-positive, while still catching the kind of
  regression this issue exists to catch (the constant-time change to
  `BarrettContext::reduce_ct` that motivated writing `op_timings.rs` in the
  first place was a multi-x change to the innermost NTT loop, not a few
  percent).
- Pooling multiple repeated runs (`--current a.json b.json c.json`) takes the
  median over ALL rounds from ALL runs combined, further damping single-run
  noise before the threshold is even applied -- prefer 3 runs per the
  `op_timings.rs`/T5 house convention over relying on the threshold alone.

Tighten `--threshold-percent` for a quieter runner, loosen it for a noisier
one -- but do so with a measured noise floor for that runner, not a guess;
see the T5 doc's own caution against setting a threshold before measuring
noise.
"""

from __future__ import annotations

import argparse
import datetime
import json
import pathlib
import sys
from typing import Any

SCRIPT_SCHEMA = "nine65-op-timings-v1"
BASELINE_SCHEMA = "nine65-op-timings-baseline-v1"

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_BASELINE = ROOT / "docs/benchmarks/op_timings_baseline.json"
DEFAULT_CURRENT = ROOT / "bench-results/op_timings.json"

ConfigKey = tuple[int, tuple[int, ...], int]  # (n, primes, t)


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise SystemExit(
            f"error: {path} not found. Run the op_timings capture first (see this "
            f"script's module docstring for the command) or pass --current explicitly."
        )
    value = json.loads(text)
    if not isinstance(value, dict):
        raise SystemExit(f"error: {path} does not contain a JSON object")
    return value


def tuple_key(cfg: dict[str, Any]) -> ConfigKey:
    return (int(cfg["n"]), tuple(int(p) for p in cfg["primes"]), int(cfg["t"]))


def integer_median(values: list[int]) -> int:
    """Same rule as `median_ns` in `crates/nine65/tests/op_timings.rs`: sort
    and take the element at index len//2. For an even count this is the
    upper of the two middle elements, not their average -- a deliberate,
    documented choice so this never needs a fractional (float) result, and
    so pooling an even number of runs behaves identically to the Rust side's
    single-run (always-odd, 3 or 5 rounds) case."""
    if not values:
        raise ValueError("cannot take the median of zero samples")
    v = sorted(values)
    return v[len(v) // 2]


def pool_current(paths: list[pathlib.Path]) -> dict[ConfigKey, dict[str, Any]]:
    """Load one or more op_timings.rs JSON captures and pool raw samples per
    (config tuple, operation) across all of them, so the eventual median is
    taken over every round from every run -- see "Threshold and noise" in
    the module docstring.

    Two DIFFERENT config names can share one tuple -- this is not
    hypothetical: on this repo, right now, `secure_128` and
    `secure_128_deep` are numerically identical chains (see
    docs/benchmarks/op_timings_baseline.json's `secure_128` entry). When
    that happens, every name that ever mapped to the tuple is kept (as a
    sorted, ' / '-joined label) and their samples are pooled together --
    they are the same computation, so pooling is more signal, not less --
    rather than one name silently overwriting the other, which would hide
    that either name was ever measured."""
    pooled: dict[ConfigKey, dict[str, list[int]]] = {}
    names: dict[ConfigKey, set[str]] = {}
    for path in paths:
        doc = load_json(path)
        if doc.get("schema") != SCRIPT_SCHEMA:
            raise SystemExit(
                f"error: {path}: schema {doc.get('schema')!r}, expected {SCRIPT_SCHEMA!r} "
                f"(produced by crates/nine65/tests/op_timings.rs)"
            )
        for cfg in doc.get("configs", []):
            key = tuple_key(cfg)
            names.setdefault(key, set()).add(cfg["config"])
            bucket = pooled.setdefault(key, {})
            for op_name, op in cfg["operations"].items():
                bucket.setdefault(op_name, []).extend(int(s) for s in op["samples_ns"])

    result: dict[ConfigKey, dict[str, Any]] = {}
    for key, ops in pooled.items():
        result[key] = {
            "config": " / ".join(sorted(names[key])),
            "aliases": sorted(names[key]),
            "operations": {op: integer_median(samples) for op, samples in ops.items()},
            "sample_counts": {op: len(samples) for op, samples in ops.items()},
        }
    return result


def load_baseline(path: pathlib.Path) -> dict[ConfigKey, dict[str, Any]]:
    doc = load_json(path)
    if doc.get("schema") != BASELINE_SCHEMA:
        raise SystemExit(f"error: {path}: schema {doc.get('schema')!r}, expected {BASELINE_SCHEMA!r}")
    out: dict[ConfigKey, dict[str, Any]] = {}
    for cfg in doc.get("configs", []):
        key = tuple_key(cfg)
        out[key] = {
            "config": cfg["config"],
            "operations": {op: int(v["median_ns"]) for op, v in cfg["operations"].items()},
        }
    return out


def write_baseline(
    path: pathlib.Path,
    pooled: dict[ConfigKey, dict[str, Any]],
    source_paths: list[pathlib.Path],
) -> None:
    generated_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    configs = []
    for key, entry in sorted(pooled.items(), key=lambda kv: kv[1]["config"]):
        n, primes, t = key
        operations = {
            op: {
                "median_ns": median_ns,
                "sample_count": entry["sample_counts"][op],
            }
            for op, median_ns in entry["operations"].items()
        }
        configs.append(
            {
                "config": entry["config"],
                "n": n,
                "primes": list(primes),
                "t": t,
                "operations": operations,
                "source": (
                    f"captured via scripts/check_benchmark_regression.py --update-baseline "
                    f"on {generated_at}, pooled from {len(source_paths)} run(s): "
                    + ", ".join(str(p) for p in source_paths)
                ),
            }
        )
    payload = {
        "schema": BASELINE_SCHEMA,
        "generated_at_utc": generated_at,
        "configs": configs,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def bp_delta(current_ns: int, baseline_ns: int) -> int:
    """Integer basis-points delta (1 bp = 0.01%): positive means CURRENT is
    slower than BASELINE (regression direction), negative means faster
    (improvement). Integer multiply then floor-divide -- no float anywhere
    in this comparison, matching op_timings.rs's own integer-only median and
    display formatting."""
    return ((current_ns - baseline_ns) * 10000) // baseline_ns


def format_bp(bp: int) -> str:
    sign = "+" if bp >= 0 else "-"
    whole, frac = divmod(abs(bp), 100)
    return f"{sign}{whole}.{frac:02d}%"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare op_timings.rs JSON captures against a committed baseline; "
        "fail if any operation's pooled median regresses past --threshold-percent.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--baseline",
        type=pathlib.Path,
        default=DEFAULT_BASELINE,
        help=f"Baseline JSON path (default: {DEFAULT_BASELINE.relative_to(ROOT)})",
    )
    parser.add_argument(
        "--current",
        type=pathlib.Path,
        nargs="+",
        default=[DEFAULT_CURRENT],
        metavar="JSON",
        help=(
            "One or more op_timings.rs JSON captures (default: "
            f"{DEFAULT_CURRENT.relative_to(ROOT)}). Pass multiple files from repeated "
            "runs to pool samples before taking the median (recommended: 3)."
        ),
    )
    parser.add_argument(
        "--threshold-percent",
        type=int,
        default=25,
        help="Fail when a (config, operation) pooled median exceeds the baseline by more "
        "than this percent. Default: 25 -- see 'Threshold and noise' in this script's "
        "module docstring (python3 scripts/check_benchmark_regression.py --help).",
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Write the pooled --current capture(s) to --baseline instead of comparing. "
        "This is the documented baseline-update process; review the resulting diff "
        "before committing it.",
    )
    parser.add_argument(
        "--report-out",
        type=pathlib.Path,
        default=None,
        help="Optional path to also write a machine-readable JSON comparison report.",
    )
    args = parser.parse_args()

    if args.threshold_percent < 0:
        parser.error("--threshold-percent must be >= 0")
    threshold_bp = args.threshold_percent * 100

    current = pool_current(args.current)

    if args.update_baseline:
        write_baseline(args.baseline, current, args.current)
        print(f"Baseline written to {args.baseline} from {len(args.current)} capture file(s).")
        for key, entry in sorted(current.items(), key=lambda kv: kv[1]["config"]):
            print(f"  {entry['config']}: n={key[0]} primes={list(key[1])} t={key[2]}")
        return 0

    if not args.baseline.exists():
        print(
            f"error: no baseline at {args.baseline}. Use --update-baseline to create one "
            f"from a --current capture.",
            file=sys.stderr,
        )
        return 1

    baseline = load_baseline(args.baseline)

    rows: list[dict[str, Any]] = []
    any_regression = False
    any_compared = False

    for key, cur in sorted(current.items(), key=lambda kv: kv[1]["config"]):
        base = baseline.get(key)
        if base is None:
            print(
                f"[NO BASELINE]  {cur['config']} -- no baseline entry for this exact config "
                f"tuple (n={key[0]}, primes={list(key[1])}, t={key[2]}). Matching is by tuple, "
                f"never by name alone (see module docstring); this config may be new, or its "
                f"tuple may have changed since the baseline was captured. Skipping."
            )
            continue
        for op_name, cur_ns in sorted(cur["operations"].items()):
            base_ns = base["operations"].get(op_name)
            if base_ns is None:
                print(f"[NO BASELINE]  {cur['config']}.{op_name} -- not present in baseline. Skipping.")
                continue
            any_compared = True
            bp = bp_delta(cur_ns, base_ns)
            if bp > threshold_bp:
                status = "REGRESSION"
                any_regression = True
            elif bp < -threshold_bp:
                status = "IMPROVED"
            else:
                status = "PASS"
            print(
                f"[{status:10}] {cur['config']:20} {op_name:14} "
                f"baseline={base_ns:>13} ns  current={cur_ns:>13} ns  delta={format_bp(bp):>9}"
            )
            rows.append(
                {
                    "config": cur["config"],
                    "n": key[0],
                    "primes": list(key[1]),
                    "t": key[2],
                    "operation": op_name,
                    "baseline_ns": base_ns,
                    "current_ns": cur_ns,
                    "delta_bp": bp,
                    "status": status,
                    "sample_count": cur["sample_counts"][op_name],
                }
            )

    if args.report_out:
        report = {
            "schema": "nine65-benchmark-regression-report-v1",
            "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "baseline_path": str(args.baseline),
            "current_paths": [str(p) for p in args.current],
            "threshold_percent": args.threshold_percent,
            "rows": rows,
            "any_regression": any_regression,
        }
        args.report_out.parent.mkdir(parents=True, exist_ok=True)
        args.report_out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"\nReport written to {args.report_out}")

    if not any_compared:
        print(
            "\nRESULT: INCONCLUSIVE -- no (config, operation) pair matched between "
            "--current and --baseline. Not a pass.",
            file=sys.stderr,
        )
        return 1

    if any_regression:
        print(f"\nRESULT: REGRESSION DETECTED (threshold {args.threshold_percent}%)")
        return 1

    print(f"\nRESULT: PASS (no operation regressed more than {args.threshold_percent}% against baseline)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
