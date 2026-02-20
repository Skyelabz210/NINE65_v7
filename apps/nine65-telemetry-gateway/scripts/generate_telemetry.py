#!/usr/bin/env python3
import argparse
import base64
import datetime as dt
import json
import random
import sys
import uuid


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate synthetic ciphertext telemetry events for /v1/telemetry/events"
    )
    parser.add_argument("--count", type=int, default=10, help="Number of events")
    parser.add_argument("--tenant-id", default="tenant_a", help="Tenant id")
    parser.add_argument("--subject-prefix", default="subj", help="Subject prefix")
    parser.add_argument("--device-prefix", default="dev", help="Device prefix")
    parser.add_argument("--signal-types", default="hrv,hr,gait", help="Comma-separated signal types")
    parser.add_argument("--key-id", default="fhekey_2026_02", help="FHE key id")
    parser.add_argument("--model-version", default="risk-v3.2.1", help="Model version")
    parser.add_argument("--start", default=None, help="ISO8601 UTC start time")
    parser.add_argument("--interval-ms", type=int, default=200, help="Spacing between events")
    parser.add_argument("--seed", type=int, default=None, help="Optional random seed")
    parser.add_argument("--output", default="-", help="Output path or '-' for stdout")
    return parser.parse_args()


def isoformat(ts: dt.datetime) -> str:
    return ts.replace(tzinfo=dt.timezone.utc).isoformat().replace("+00:00", "Z")


def random_payload(rng: random.Random, size: int = 48) -> str:
    blob = bytes(rng.getrandbits(8) for _ in range(size))
    return base64.b64encode(blob).decode("ascii")


def make_events(args: argparse.Namespace):
    rng = random.Random(args.seed)
    signal_types = [s.strip() for s in args.signal_types.split(",") if s.strip()]
    start = (
        dt.datetime.fromisoformat(args.start.replace("Z", "+00:00"))
        if args.start
        else dt.datetime.now(dt.timezone.utc)
    )

    for idx in range(args.count):
        subject_id = f"{args.subject_prefix}_{(idx % 5) + 1:03d}"
        device_id = f"{args.device_prefix}_{(idx % 3) + 1:03d}"
        captured_at = start + dt.timedelta(milliseconds=args.interval_ms * idx)
        yield {
            "event_id": str(uuid.uuid4()),
            "tenant_id": args.tenant_id,
            "subject_id": subject_id,
            "device_id": device_id,
            "captured_at": isoformat(captured_at),
            "signal_type": rng.choice(signal_types) if signal_types else "hrv",
            "sequence_no": idx,
            "ciphertext_payload_b64": random_payload(rng),
            "key_id": args.key_id,
            "model_version": args.model_version,
            "metadata": {
                "source": "synthetic",
                "sampling_hz": 250,
                "firmware": "1.8.0"
            }
        }


def write_events(events, output: str) -> None:
    if output == "-":
        handle = sys.stdout
    else:
        handle = open(output, "w", encoding="utf-8")

    try:
        for event in events:
            handle.write(json.dumps(event))
            handle.write("\n")
    finally:
        if handle is not sys.stdout:
            handle.close()


def main() -> int:
    args = parse_args()
    events = list(make_events(args))
    write_events(events, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
