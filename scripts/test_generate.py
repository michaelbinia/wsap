"""Unit tests for scripts/generate.py."""
from __future__ import annotations

import datetime as dt
import random
import sys
import unittest
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


if __name__ == "__main__":
    unittest.main()
