#!/usr/bin/env python3
"""Mini WSA data generator.

Produces SecurityEventDto-shaped JSON (matching the API contract from
Phase 2) and either POSTs it to the ingest endpoint or writes NDJSON
(one JSON array per line) to stdout or a file.

Standard library only. Target Python 3.10+.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import random
import sys
import time
import urllib.error
import urllib.request
import uuid


CONFIG_IDS: list[int] = [14227, 14228, 14229]

HOSTNAMES: list[str] = ["www.example.com", "api.example.com", "admin.example.com"]

PATHS: list[str] = [
    "/api/v1/login",
    "/admin",
    "/",
    "/api/v1/users",
    "/search",
    "/checkout",
]

METHODS: list[str] = ["GET", "POST", "PUT"]

STATUS_CODES: list[int] = [200, 400, 401, 403, 429, 500]

USER_AGENTS: list[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "curl/8.4.0",
    "GoogleBot/2.1 (+http://www.google.com/bot.html)",
    "python-requests/2.31",
]

GEO_LOCATIONS: list[dict[str, str]] = [
    {"country": "US", "city": "San Francisco"},
    {"country": "CN", "city": "Beijing"},
    {"country": "RU", "city": "Moscow"},
    {"country": "BR", "city": "Sao Paulo"},
    {"country": "DE", "city": "Berlin"},
    {"country": "IN", "city": "Bangalore"},
    {"country": "GB", "city": "London"},
    {"country": "JP", "city": "Tokyo"},
]


def _ip_pool() -> list[str]:
    ips: list[str] = []
    for i in range(1, 21):
        ips.append(f"203.0.113.{i}")
    for i in range(1, 16):
        ips.append(f"198.51.100.{i}")
    for i in range(1, 16):
        ips.append(f"192.0.2.{i}")
    return ips


CLIENT_IPS: list[str] = _ip_pool()


RULE_TEMPLATES: dict[str, dict[str, str]] = {
    "INJECTION":          {"id": "950001", "name": "SQL_INJECTION",    "severity": "CRITICAL", "message": "SQL Injection Attack Detected"},
    "XSS":                {"id": "941100", "name": "XSS_ATTACK",       "severity": "HIGH",     "message": "Cross-Site Scripting Attempt"},
    "PROTOCOL_VIOLATION": {"id": "920100", "name": "PROTOCOL_ANOMALY", "severity": "MEDIUM",   "message": "Malformed HTTP Request"},
    "DATA_LEAKAGE":       {"id": "970001", "name": "DATA_LEAK",        "severity": "HIGH",     "message": "Sensitive Data Exposure"},
    "BOT":                {"id": "913001", "name": "BOT_ACTIVITY",    "severity": "LOW",      "message": "Automated Bot Request"},
    "DOS":                {"id": "930001", "name": "DOS_ATTEMPT",     "severity": "CRITICAL", "message": "Denial of Service Pattern"},
    "RATE_LIMIT":         {"id": "960001", "name": "RATE_LIMITED",    "severity": "MEDIUM",   "message": "Rate Limit Exceeded"},
}

ACTIONS: list[str] = ["DENY", "ALERT", "MONITOR"]
ACTION_WEIGHTS: list[int] = [55, 30, 15]

WAVE_WINDOW = dt.timedelta(minutes=2)
EVENT_WINDOW = dt.timedelta(hours=1)


def _iso_utc(moment: dt.datetime) -> str:
    return moment.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def random_event(rng: random.Random, now: dt.datetime) -> dict:
    """Returns one SecurityEventDto-shaped dict with a random timestamp inside a
    window ending at `now`."""
    category = rng.choice(list(RULE_TEMPLATES.keys()))
    rt = RULE_TEMPLATES[category]
    ts = now - dt.timedelta(seconds=rng.randint(0, int(EVENT_WINDOW.total_seconds())))
    return {
        "eventId": "evt-" + uuid.UUID(int=rng.getrandbits(128)).hex[:12],
        "timestamp": _iso_utc(ts),
        "configId": rng.choice(CONFIG_IDS),
        "policyId": f"pol_web{rng.randint(1, 3)}",
        "clientIp": rng.choice(CLIENT_IPS),
        "hostname": rng.choice(HOSTNAMES),
        "path": rng.choice(PATHS),
        "method": rng.choice(METHODS),
        "statusCode": rng.choice(STATUS_CODES),
        "userAgent": rng.choice(USER_AGENTS),
        "rule": {
            "id": rt["id"],
            "name": rt["name"],
            "message": rt["message"],
            "severity": rt["severity"],
            "category": category,
        },
        "action": rng.choices(ACTIONS, weights=ACTION_WEIGHTS, k=1)[0],
        "geoLocation": dict(rng.choice(GEO_LOCATIONS)),
        "requestSize": rng.randint(100, 10_000),
        "responseSize": rng.randint(100, 50_000),
    }


def attack_wave(rng: random.Random, size: int, ends_at: dt.datetime) -> list[dict]:
    """Returns `size` events sharing the same clientIp and path, with timestamps
    packed inside a 2-minute window ending at `ends_at`. For size > 6, every
    event beyond the sixth triggers the repeat-offender bonus (>5 in 10 min)."""
    anchor = random_event(rng, ends_at)
    shared_ip = anchor["clientIp"]
    shared_path = anchor["path"]
    denom = max(size - 1, 1)
    events: list[dict] = []
    for i in range(size):
        offset_s = (i / denom) * WAVE_WINDOW.total_seconds()
        ts = ends_at - WAVE_WINDOW + dt.timedelta(seconds=offset_s)
        event = random_event(rng, ts)
        event["clientIp"] = shared_ip
        event["path"] = shared_path
        event["timestamp"] = _iso_utc(ts)
        events.append(event)
    return events


def generate_batch(
    rng: random.Random,
    count: int,
    waves: int,
    wave_size: int,
    window_end: dt.datetime,
) -> list[dict]:
    """count - waves*wave_size random events + waves attack waves, shuffled."""
    normal = count - waves * wave_size
    events: list[dict] = [random_event(rng, window_end) for _ in range(normal)]
    for i in range(waves):
        events.extend(attack_wave(rng, wave_size, window_end - dt.timedelta(seconds=i * 30)))
    rng.shuffle(events)
    return events


def post_batches(
    events: list[dict],
    target: str,
    batch_size: int,
    fail_fast: bool = False,
) -> tuple[int, int, float]:
    """POST events to the ingest endpoint in chunks of batch_size.
    Returns (sent, rejected, elapsed_s)."""
    sent = 0
    rejected = 0
    start = time.monotonic()
    for i in range(0, len(events), batch_size):
        batch = events[i : i + batch_size]
        payload = json.dumps(batch).encode("utf-8")
        req = urllib.request.Request(
            url=target,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                if resp.status in (200, 201):
                    sent += len(batch)
                else:
                    body = resp.read()
                    msg = f"ingest returned {resp.status}: {body!r}"
                    if fail_fast:
                        raise RuntimeError(msg)
                    rejected += len(batch)
                    print(msg, file=sys.stderr)
        except urllib.error.HTTPError as err:
            body = err.read()
            msg = f"ingest HTTP {err.code}: {body!r}"
            if fail_fast:
                raise RuntimeError(msg) from err
            rejected += len(batch)
            print(msg, file=sys.stderr)
    elapsed = time.monotonic() - start
    return sent, rejected, elapsed


def write_ndjson(events: list[dict], out_handle, batch_size: int) -> None:
    """One JSON array per line, each array sized `batch_size`."""
    for i in range(0, len(events), batch_size):
        out_handle.write(json.dumps(events[i : i + batch_size]))
        out_handle.write("\n")


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Mini WSA data generator")
    parser.add_argument("--count", type=int, default=10_000, help="total events emitted")
    parser.add_argument("--waves", type=int, default=10, help="number of attack waves")
    parser.add_argument("--wave-size", type=int, default=50, help="events per wave")
    parser.add_argument("--batch", type=int, default=100, help="events per POST / NDJSON line")
    parser.add_argument("--seed", type=int, default=42, help="PRNG seed")
    parser.add_argument("--target", help="ingest URL. Mutually exclusive with --output.")
    parser.add_argument("--output", help="File path or '-' for stdout. Mutually exclusive with --target.")
    parser.add_argument("--fail-fast", action="store_true", help="abort on first non-2xx response")
    args = parser.parse_args(argv)

    if (args.target is None) == (args.output is None):
        parser.error("exactly one of --target or --output is required")
    if args.waves * args.wave_size > args.count:
        parser.error(
            f"waves * wave-size ({args.waves * args.wave_size}) must not exceed count ({args.count})"
        )
    if args.count <= 0:
        parser.error("--count must be positive")
    if args.batch <= 0:
        parser.error("--batch must be positive")
    return args


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    rng = random.Random(args.seed)
    now = dt.datetime.now(dt.timezone.utc)
    events = generate_batch(rng, args.count, args.waves, args.wave_size, now)

    if args.target:
        sent, rejected, elapsed = post_batches(
            events, args.target, args.batch, fail_fast=args.fail_fast
        )
        batches = (len(events) + args.batch - 1) // args.batch
        print(
            f"sent={sent} rejected={rejected} batches={batches} "
            f"elapsed={elapsed:.1f}s target={args.target}"
        )
    else:
        if args.output == "-":
            write_ndjson(events, sys.stdout, args.batch)
        else:
            with open(args.output, "w", encoding="utf-8") as handle:
                write_ndjson(events, handle, args.batch)
            print(f"wrote={len(events)} output={args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
