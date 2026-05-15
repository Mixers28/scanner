"""Tests for S1-T1: Process collector and event persistence."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scanner.collector.process_collector import (
    normalize_process_fields,
    make_telemetry_event,
    ProcessCollector,
)
from scanner.common.types import TelemetryEvent
from scanner.storage import SQLiteStorage


class NormalizeProcessFieldsTests(unittest.TestCase):
    def test_basic_normalization(self) -> None:
        result = normalize_process_fields(
            pid=1234,
            ppid=4,
            exe_path=r"C:\Program Files\App\thing.exe",
            name="thing.exe",
            create_time=1700000000.0,
        )
        self.assertEqual(result["pid"], 1234)
        self.assertEqual(result["ppid"], 4)
        self.assertEqual(result["name"], "thing.exe")
        # image_path_norm should be lowercased
        self.assertEqual(result["image_path_norm"], result["image_path_norm"].lower())
        # identity_key should be a 64-char hex sha256
        self.assertEqual(len(result["identity_key"]), 64)

    def test_none_exe_path(self) -> None:
        result = normalize_process_fields(
            pid=1, ppid=None, exe_path=None, name=None, create_time=None,
        )
        self.assertEqual(result["image_path_norm"], "")
        self.assertEqual(result["ppid"], 0)
        self.assertEqual(result["name"], "")
        self.assertIsNotNone(result["identity_key"])

    def test_identity_key_stability(self) -> None:
        """Same inputs should produce identical identity keys."""
        a = normalize_process_fields(1, 0, r"C:\foo\bar.exe", "bar.exe", 0.0)
        b = normalize_process_fields(1, 0, r"c:/foo/bar.exe", "bar.exe", 0.0)
        self.assertEqual(a["identity_key"], b["identity_key"])


class MakeTelemetryEventTests(unittest.TestCase):
    def test_envelope_shape(self) -> None:
        ev = make_telemetry_event(
            host_id="host-1",
            event_type="process_start",
            pid=42,
            payload={"pid": 42, "name": "test.exe"},
        )
        self.assertIsInstance(ev, TelemetryEvent)
        self.assertEqual(ev.event_type, "process_start")
        self.assertEqual(ev.pid, 42)
        self.assertEqual(ev.host_id, "host-1")
        self.assertIn("pid", ev.payload)
        # event_id should be a 32-char hex uuid
        self.assertEqual(len(ev.event_id), 32)
        # ts should be ISO format
        self.assertIn("T", ev.ts)

    def test_event_types(self) -> None:
        for etype in ("process_start", "process_stop"):
            ev = make_telemetry_event("h", etype, 1, {})
            self.assertEqual(ev.event_type, etype)


class ProcessCollectorSnapshotTests(unittest.TestCase):
    def _make_fake_proc(self, pid: int, ppid: int, exe: str, name: str) -> MagicMock:
        proc = MagicMock()
        proc.as_dict.return_value = {
            "pid": pid, "ppid": ppid, "exe": exe,
            "name": name, "create_time": 1700000000.0, "status": "running",
        }
        return proc

    @patch("scanner.collector.process_collector.psutil.process_iter")
    def test_first_snapshot_all_starts(self, mock_iter: MagicMock) -> None:
        mock_iter.return_value = [
            self._make_fake_proc(10, 1, r"C:\app.exe", "app.exe"),
            self._make_fake_proc(20, 1, r"C:\svc.exe", "svc.exe"),
        ]
        collector = ProcessCollector(host_id="test-host")
        started, stopped = collector.snapshot()

        self.assertEqual(len(started), 2)
        self.assertEqual(len(stopped), 0)
        self.assertTrue(all(e.event_type == "process_start" for e in started))

    @patch("scanner.collector.process_collector.psutil.process_iter")
    def test_second_snapshot_detects_stop(self, mock_iter: MagicMock) -> None:
        proc_a = self._make_fake_proc(10, 1, r"C:\app.exe", "app.exe")
        proc_b = self._make_fake_proc(20, 1, r"C:\svc.exe", "svc.exe")

        mock_iter.return_value = [proc_a, proc_b]
        collector = ProcessCollector(host_id="test-host")
        collector.snapshot()  # seed known PIDs

        # Second snapshot: proc_b gone, proc_c new
        proc_c = self._make_fake_proc(30, 1, r"C:\new.exe", "new.exe")
        mock_iter.return_value = [proc_a, proc_c]
        started, stopped = collector.snapshot()

        self.assertEqual(len(started), 1)
        self.assertEqual(started[0].payload["pid"], 30)
        self.assertEqual(len(stopped), 1)
        self.assertEqual(stopped[0].payload["pid"], 20)
        self.assertEqual(stopped[0].event_type, "process_stop")

    @patch("scanner.collector.process_collector.psutil.process_iter")
    def test_no_change_no_events(self, mock_iter: MagicMock) -> None:
        proc = self._make_fake_proc(10, 1, r"C:\app.exe", "app.exe")
        mock_iter.return_value = [proc]
        collector = ProcessCollector(host_id="h")
        collector.snapshot()

        mock_iter.return_value = [proc]
        started, stopped = collector.snapshot()
        self.assertEqual(len(started), 0)
        self.assertEqual(len(stopped), 0)


class EventPersistenceTests(unittest.TestCase):
    def test_persist_and_query(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = SQLiteStorage(Path(tmpdir) / "test.db")
            store.initialize()

            ev = make_telemetry_event(
                host_id="h1",
                event_type="process_start",
                pid=99,
                payload={"pid": 99, "name": "test.exe"},
            )
            count = store.persist_events([ev])
            self.assertEqual(count, 1)

            rows = store.query_events(event_type="process_start")
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["event_id"], ev.event_id)
            self.assertEqual(rows[0]["pid"], 99)

            payload = json.loads(rows[0]["payload_json"])
            self.assertEqual(payload["name"], "test.exe")
            store.close()

    def test_persist_ignores_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = SQLiteStorage(Path(tmpdir) / "test.db")
            store.initialize()

            ev = make_telemetry_event("h1", "process_start", 1, {})
            store.persist_events([ev])
            store.persist_events([ev])  # duplicate

            rows = store.query_events()
            self.assertEqual(len(rows), 1)
            store.close()


if __name__ == "__main__":
    unittest.main()
