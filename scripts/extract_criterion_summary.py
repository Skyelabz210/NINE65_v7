#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def ns_to_ms(value):
    return value / 1_000_000.0


def load_estimate(path: Path):
    data = json.loads(path.read_text(encoding="utf-8"))
    median_ns = float(data["median"]["point_estimate"])
    mean_ns = float(data["mean"]["point_estimate"])
    stddev_ns = float(data.get("std_dev", {}).get("point_estimate", 0.0))
    return median_ns, mean_ns, stddev_ns


def main():
    parser = argparse.ArgumentParser(
        description="Extract machine-readable benchmark summary from Criterion estimates."
    )
    parser.add_argument(
        "--criterion-root",
        default="target/criterion",
        help="Path to Criterion output root.",
    )
    parser.add_argument("--out", required=True, help="Output JSON path.")
    args = parser.parse_args()

    root = Path(args.criterion_root)
    out_path = Path(args.out)
    entries = []

    if not root.exists():
        raise SystemExit(f"criterion root does not exist: {root}")

    for estimates_path in sorted(root.rglob("new/estimates.json")):
        rel = estimates_path.relative_to(root)
        benchmark_id = "/".join(rel.parts[:-2])  # drop new/estimates.json
        median_ns, mean_ns, stddev_ns = load_estimate(estimates_path)
        entries.append(
            {
                "benchmark_id": benchmark_id,
                "median_ns": median_ns,
                "mean_ns": mean_ns,
                "stddev_ns": stddev_ns,
                "median_ms": ns_to_ms(median_ns),
                "mean_ms": ns_to_ms(mean_ns),
                "source": str(estimates_path),
            }
        )

    payload = {
        "criterion_root": str(root),
        "benchmarks": entries,
        "count": len(entries),
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
