"""Tests for S1-T4: Event rate limiter and retention cleanup."""

import sys
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scanner.collector.rate_limiter import EventRateLimiter, cleanup_old_telemetry
from scanner.collector.process_collector import make_telemetry_event
from scanner.storage import SQLiteStorage


def _make_event(pid: int = 1) -> object:
    return make_telemetry_event("h", "process_start", pid, {"pid": pid})


class EventRateLimiterTests(unittest.TestCase):
    def test_accepts_within_cap(self) -> None:
        rl = EventRateLimiter(max_events_per_minute=10)
        for _ in range(10):
            self.assertTrue(rl.accept(_make_event()))

    def test_drops_over_cap(self) -> None:
        rl = EventRateLimiter(max_events_per_minute=5)
        results = [rl.accept(_make_event()) for _ in range(10)]
        self.assertEqual(results.count(True), 5)
        self.assertEqual(results.count(False), 5)
        self.assertEqual(rl.total_dropped, 5)

    def test_filter_batch(self) -> None:
        rl = EventRateLimiter(max_events_per_minute=3)
        batch = [_make_event(i) for i in range(6)]
        accepted = rl.filter(batch)
        self.assertEqual(len(accepted), 3)
        self.assertEqual(rl.total_dropped, 3)


class CleanupOldTelemetryTests(unittest.TestCase):
    def test_deletes_old_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = SQLiteStorage(Path(tmpdir) / "test.db")
            store.initialize()

            conn = store.connection
            now = datetime.now(timezone.utc)
            old_ts = (now - timedelta(days=10)).isoformat()
            recent_ts = now.isoformat()

            conn.execute(
                "INSERT INTO telemetry_event (event_id, host_id, ts, event_type, pid, payload_json) VALUES (?, ?, ?, ?, ?, ?)",
                ("old-1", "h", old_ts, "process_start", 1, "{}"),
            )
            conn.execute(
                "INSERT INTO telemetry_event (event_id, host_id, ts, event_type, pid, payload_json) VALUES (?, ?, ?, ?, ?, ?)",
                ("new-1", "h", recent_ts, "process_start", 2, "{}"),
            )
            conn.commit()

            deleted = cleanup_old_telemetry(conn, retention_days=7)
            self.assertEqual(deleted, 1)

            remaining = conn.execute("SELECT event_id FROM telemetry_event").fetchall()
            self.assertEqual(len(remaining), 1)
            self.assertEqual(remaining[0]["event_id"], "new-1")
            store.close()

    def test_no_op_when_nothing_old(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = SQLiteStorage(Path(tmpdir) / "test.db")
            store.initialize()

            conn = store.connection
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "INSERT INTO telemetry_event (event_id, host_id, ts, event_type, pid, payload_json) VALUES (?, ?, ?, ?, ?, ?)",
                ("fresh-1", "h", now, "process_start", 1, "{}"),
            )
            conn.commit()

            deleted = cleanup_old_telemetry(conn, retention_days=7)
            self.assertEqual(deleted, 0)
            store.close()


if __name__ == "__main__":
    unittest.main()
