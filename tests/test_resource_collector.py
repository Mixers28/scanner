"""Tests for S1-T2: Resource collector."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock, PropertyMock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scanner.collector.resource_collector import (
    _safe_resource_sample,
    collect_resource_samples,
)


class SafeResourceSampleTests(unittest.TestCase):
    def _make_proc(
        self, pid: int = 100, exe: str = r"C:\app.exe",
        cpu: float = 5.0, rss: int = 1024, vms: int = 2048,
        read_bytes: int = 500, write_bytes: int = 300,
    ) -> MagicMock:
        proc = MagicMock()
        proc.pid = pid
        proc.exe.return_value = exe
        proc.cpu_percent.return_value = cpu
        mem = MagicMock()
        mem.rss = rss
        mem.vms = vms
        proc.memory_info.return_value = mem
        io = MagicMock()
        io.read_bytes = read_bytes
        io.write_bytes = write_bytes
        proc.io_counters.return_value = io
        proc.oneshot.return_value.__enter__ = MagicMock(return_value=None)
        proc.oneshot.return_value.__exit__ = MagicMock(return_value=False)
        return proc

    def test_sample_shape(self) -> None:
        proc = self._make_proc()
        result = _safe_resource_sample(proc)
        self.assertIsNotNone(result)
        self.assertEqual(result["pid"], 100)
        self.assertEqual(result["cpu_percent"], 5.0)
        self.assertEqual(result["memory_rss_bytes"], 1024)
        self.assertEqual(result["disk_read_bytes"], 500)

    def test_returns_none_on_no_such_process(self) -> None:
        import psutil
        proc = MagicMock()
        proc.oneshot.return_value.__enter__ = MagicMock(
            side_effect=psutil.NoSuchProcess(999)
        )
        result = _safe_resource_sample(proc)
        self.assertIsNone(result)


class CollectResourceSamplesTests(unittest.TestCase):
    @patch("scanner.collector.resource_collector.psutil.process_iter")
    def test_emits_resource_sample_events(self, mock_iter: MagicMock) -> None:
        proc = MagicMock()
        proc.pid = 42
        proc.exe.return_value = r"C:\svc.exe"
        proc.cpu_percent.return_value = 2.0
        mem = MagicMock()
        mem.rss = 4096
        mem.vms = 8192
        proc.memory_info.return_value = mem
        io = MagicMock()
        io.read_bytes = 100
        io.write_bytes = 200
        proc.io_counters.return_value = io
        proc.oneshot.return_value.__enter__ = MagicMock(return_value=None)
        proc.oneshot.return_value.__exit__ = MagicMock(return_value=False)

        mock_iter.return_value = [proc]
        events = collect_resource_samples(host_id="h1")

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, "resource_sample")
        self.assertEqual(events[0].payload["cpu_percent"], 2.0)
        self.assertEqual(events[0].payload["image_path"], r"C:\svc.exe")
        self.assertEqual(events[0].payload["signer_publisher"], "unknown")
        self.assertIn("identity_key", events[0].payload)

    @patch("scanner.collector.resource_collector.psutil.process_iter")
    def test_empty_on_all_vanished(self, mock_iter: MagicMock) -> None:
        import psutil
        proc = MagicMock()
        proc.oneshot.return_value.__enter__ = MagicMock(
            side_effect=psutil.NoSuchProcess(1)
        )
        mock_iter.return_value = [proc]
        events = collect_resource_samples(host_id="h1")
        self.assertEqual(len(events), 0)


if __name__ == "__main__":
    unittest.main()
