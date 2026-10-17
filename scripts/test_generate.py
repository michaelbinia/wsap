"""Unit and integration tests for scripts/generate.py."""
from __future__ import annotations

import datetime as dt
import json
import random
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import generate as g  # noqa: E402


REQUIRED_FIELDS = (
    "eventId",
    "timestamp",
    "configId",
    "clientIp",
    "hostname",
    "path",
    "method",
    "statusCode",
    "rule",
    "action",
)

ENRICHMENT_FIELDS = ("receivedAt", "attackType", "threatScore")


class WaveTests(unittest.TestCase):
    def test_wave_shares_ip_and_path(self) -> None:
        rng = random.Random(1)
        ends_at = dt.datetime(2026, 5, 20, 14, 0, tzinfo=dt.timezone.utc)
        events = g.attack_wave(rng, 20, ends_at)

        self.assertEqual(len(events), 20)
        self.assertEqual(len({e["clientIp"] for e in events}), 1)
        self.assertEqual(len({e["path"] for e in events}), 1)

    def test_wave_timestamps_in_window(self) -> None:
        rng = random.Random(2)
        ends_at = dt.datetime(2026, 5, 20, 14, 0, tzinfo=dt.timezone.utc)
        events = g.attack_wave(rng, 20, ends_at)

        window_start = ends_at - g.WAVE_WINDOW
        for event in events:
            ts = dt.datetime.strptime(event["timestamp"], "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=dt.timezone.utc
            )
            self.assertGreaterEqual(ts, window_start)
            self.assertLessEqual(ts, ends_at)


class EventSchemaTests(unittest.TestCase):
    def test_event_has_required_fields_and_valid_enums(self) -> None:
        rng = random.Random(3)
        now = dt.datetime.now(dt.timezone.utc)
        event = g.random_event(rng, now)

        for key in REQUIRED_FIELDS:
            self.assertIn(key, event)
            self.assertIsNotNone(event[key])
        self.assertIn(event["rule"]["severity"], ("CRITICAL", "HIGH", "MEDIUM", "LOW"))
        self.assertIn(event["rule"]["category"], g.RULE_TEMPLATES.keys())
        self.assertIn(event["action"], ("DENY", "ALERT", "MONITOR"))

    def test_event_does_not_emit_server_side_enrichment_fields(self) -> None:
        rng = random.Random(4)
        now = dt.datetime.now(dt.timezone.utc)
        event = g.random_event(rng, now)

        for key in ENRICHMENT_FIELDS:
            self.assertNotIn(key, event)

    def test_client_ips_are_from_rfc5737_ranges(self) -> None:
        rng = random.Random(5)
        now = dt.datetime.now(dt.timezone.utc)
        for _ in range(50):
            event = g.random_event(rng, now)
            self.assertIn(event["clientIp"], g.CLIENT_IPS)

    def test_same_seed_produces_identical_event_ids(self) -> None:
        now = dt.datetime(2026, 5, 20, 14, 0, tzinfo=dt.timezone.utc)
        rng_a = random.Random(99)
        rng_b = random.Random(99)
        ids_a = [g.random_event(rng_a, now)["eventId"] for _ in range(10)]
        ids_b = [g.random_event(rng_b, now)["eventId"] for _ in range(10)]
        self.assertEqual(ids_a, ids_b)


class _StubIngestHandler(BaseHTTPRequestHandler):
    """Collects every POST body into a class-level list and returns 201."""

    received: list[list[dict]] = []

    def do_POST(self) -> None:  # noqa: N802  (BaseHTTPRequestHandler contract)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        type(self).received.append(json.loads(body))
        self.send_response(201)
        self.end_headers()

    def log_message(self, *_args, **_kwargs) -> None:
        pass


class IntegrationTests(unittest.TestCase):
    """Spin up a stdlib HTTPServer and point the generator at it."""

    def test_post_batches_sends_every_event_in_chunks_of_batch_size(self) -> None:
        _StubIngestHandler.received = []
        server = HTTPServer(("127.0.0.1", 0), _StubIngestHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            rng = random.Random(1)
            now = dt.datetime(2026, 5, 20, 14, 0, tzinfo=dt.timezone.utc)
            events = [g.random_event(rng, now) for _ in range(25)]

            sent, rejected, elapsed = g.post_batches(
                events,
                f"http://127.0.0.1:{port}/v1/events/ingest",
                batch_size=10,
                fail_fast=True,
            )

            self.assertEqual(sent, 25)
            self.assertEqual(rejected, 0)
            self.assertGreaterEqual(elapsed, 0)
            self.assertEqual([len(b) for b in _StubIngestHandler.received], [10, 10, 5])

            first_event = _StubIngestHandler.received[0][0]
            for key in REQUIRED_FIELDS:
                self.assertIn(key, first_event)
            self.assertIn(first_event["rule"]["category"], g.RULE_TEMPLATES.keys())
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
