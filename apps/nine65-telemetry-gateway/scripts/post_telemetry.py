#!/usr/bin/env python3
import argparse
import json
import time
import urllib.request
from typing import Dict, Iterable, List


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="POST telemetry events to gateway endpoint")
    parser.add_argument("--url", required=True, help="Target /v1/telemetry/events URL")
    parser.add_argument("--input", required=True, help="JSONL or JSON file")
    parser.add_argument("--bearer", required=True, help="Bearer token value")
    parser.add_argument("--key-id", required=True, help="X-Key-Id header value")
    parser.add_argument("--delay-ms", type=int, default=0, help="Delay between requests")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout seconds")
    parser.add_argument("--limit", type=int, default=None, help="Optional limit")
    return parser.parse_args()


def load_events(path: str) -> List[Dict]:
    with open(path, "r", encoding="utf-8") as handle:
        content = handle.read().strip()

    if not content:
        return []

    if content.startswith("["):
        return json.loads(content)

    events = []
    for line in content.splitlines():
        line = line.strip()
        if line:
            events.append(json.loads(line))
    return events


def iter_events(events: List[Dict], limit: int | None) -> Iterable[Dict]:
    if limit is None:
        return events
    return events[:limit]


def post_event(url: str, payload: Dict, bearer: str, key_id: str, timeout: int) -> tuple[int, str]:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {bearer}",
            "Idempotency-Key": payload.get("event_id", "missing-event-id"),
            "X-Key-Id": key_id,
        },
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.status, response.read().decode("utf-8", errors="replace")


def main() -> int:
    args = parse_args()
    events = load_events(args.input)
    selected = list(iter_events(events, args.limit))

    if not selected:
        print("No events found.")
        return 1

    success = 0
    for index, event in enumerate(selected, start=1):
        try:
            status, body = post_event(args.url, event, args.bearer, args.key_id, args.timeout)
            if 200 <= status < 300:
                success += 1
            print(f"[{index}] status={status} body={body}")
        except Exception as exc:
            print(f"[{index}] error={exc}")

        if args.delay_ms > 0:
            time.sleep(args.delay_ms / 1000.0)

    print(f"sent={len(selected)} success={success}")
    return 0 if success == len(selected) else 1


if __name__ == "__main__":
    raise SystemExit(main())
