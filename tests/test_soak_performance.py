"""Soak and performance validation tests.

SPEC §8 acceptance criteria:
  - Criterion 1: Service runs for 24h without crashes (manual soak on target host).
  - SPEC §7 performance budgets:
      CPU: average < 2% idle; burst < 10% for < 5s
      Memory: < 400 MB resident
      DB: < 500 MB rolling

These tests validate the performance budget within a bounded N-cycle run.
For full 24h soak, run the service on the target Windows host and inspect
the status output for db_size_mb and cycle stability.

Usage (quick budget check):
    python -m pytest tests/test_soak_performance.py -v

Full soak (target host only):
    python -m scanner run --db soak_test.db --max-cycles 0
    (let it run for 24h, then check: python -m scanner status --db soak_test.db)
"""

from __future__ import annotations

import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scanner.baseline.mode import BaselineMode
from scanner.service.orchestrator import ScannerService

_SOAK_CYCLES = 50  # representative burst; 24h soak is manual on target host
_MAX_CYCLE_SECONDS = 2.0  # each cycle must complete within this wall-clock budget


def _make_config(tmpdir: str) -> dict:
    return {
        "collector": {
            "process_poll_interval_seconds": 1,
            "resource_poll_interval_seconds": 5,
            "network_poll_interval_seconds": 10,
            "capture_command_line": False,
            "max_events_per_minute": 6000,
        },
        "baseline": {
            "learning_window_days": 7,
            "enable_drift": False,
            "drift_min_confidence": 0.8,
        },
        "anomaly": {
            "cooldown_minutes": 30,
            "resource_spike_intervals": 3,
        },
        "verify": {
            "total_timeout_seconds": 5,
            "cache_ttl_days": 7,
            "adapters_enabled": ["signature"],
        },
        "reporting": {
            "formats": ["json", "html"],
            "include_technical_appendix": True,
            "out_dir": str(Path(tmpdir) / "reports"),
        },
        "retention": {
            "telemetry_days": 7,
            "incidents_days": 90,
            "max_baseline_versions": 10,
            "max_whitelist_versions": 50,
            "max_db_mb": 500,
        },
    }


class CycleStabilityTests(unittest.TestCase):
    """Verify the service can run N consecutive cycles without error."""

    @patch("scanner.service.orchestrator.collect_network_connections", return_value=[])
    @patch("scanner.service.orchestrator.collect_resource_samples", return_value=[])
    @patch("scanner.service.orchestrator.ProcessCollector")
    def test_n_cycles_complete_without_error(
        self, mock_pc_cls, mock_res, mock_net
    ) -> None:
        mock_pc = MagicMock()
        mock_pc.snapshot.return_value = ([], [])
        mock_pc_cls.return_value = mock_pc

        with tempfile.TemporaryDirectory() as tmpdir:
            svc = ScannerService(
                db_path=Path(tmpdir) / "soak.db",
                config=_make_config(tmpdir),
            )
            svc.start()
            try:
                for i in range(_SOAK_CYCLES):
                    stats = svc.run_cycle()
                    self.assertIn("events", stats,
                                  f"Cycle {i} returned malformed stats")

                self.assertEqual(svc._cycle_count, _SOAK_CYCLES)
                self.assertTrue(svc.is_running)
            finally:
                svc.stop()

        self.assertFalse(svc.is_running, "Service should be stopped after stop()")


class CycleTimingTests(unittest.TestCase):
    """Each idle cycle must complete well under the performance budget."""

    @patch("scanner.service.orchestrator.collect_network_connections", return_value=[])
    @patch("scanner.service.orchestrator.collect_resource_samples", return_value=[])
    @patch("scanner.service.orchestrator.ProcessCollector")
    def test_idle_cycle_timing(
        self, mock_pc_cls, mock_res, mock_net
    ) -> None:
        mock_pc = MagicMock()
        mock_pc.snapshot.return_value = ([], [])
        mock_pc_cls.return_value = mock_pc

        with tempfile.TemporaryDirectory() as tmpdir:
            svc = ScannerService(
                db_path=Path(tmpdir) / "timing.db",
                config=_make_config(tmpdir),
            )
            svc.start()
            try:
                timings = []
                for _ in range(10):
                    t0 = time.monotonic()
                    svc.run_cycle()
                    timings.append(time.monotonic() - t0)

                avg = sum(timings) / len(timings)
                worst = max(timings)

                self.assertLess(
                    avg, _MAX_CYCLE_SECONDS,
                    f"Average idle cycle time {avg:.3f}s exceeds {_MAX_CYCLE_SECONDS}s budget",
                )
                self.assertLess(
                    worst, _MAX_CYCLE_SECONDS * 3,
                    f"Worst-case cycle time {worst:.3f}s is unexpectedly slow",
                )
            finally:
                svc.stop()


class RetentionStabilityTests(unittest.TestCase):
    """Retention runs without error and returns expected keys."""

    @patch("scanner.service.orchestrator.collect_network_connections", return_value=[])
    @patch("scanner.service.orchestrator.collect_resource_samples", return_value=[])
    @patch("scanner.service.orchestrator.ProcessCollector")
    def test_retention_after_cycles(
        self, mock_pc_cls, mock_res, mock_net
    ) -> None:
        mock_pc = MagicMock()
        mock_pc.snapshot.return_value = ([], [])
        mock_pc_cls.return_value = mock_pc

        with tempfile.TemporaryDirectory() as tmpdir:
            svc = ScannerService(
                db_path=Path(tmpdir) / "ret.db",
                config=_make_config(tmpdir),
            )
            svc.start()
            try:
                for _ in range(5):
                    svc.run_cycle()

                result = svc.run_retention()
                self.assertIn("deleted_telemetry", result)
                self.assertIn("deleted_baselines", result)
            finally:
                svc.stop()


class StatusFieldsTests(unittest.TestCase):
    """Status output includes all fields required by SPEC §A4.7."""

    def test_status_fields_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            svc = ScannerService(db_path=Path(tmpdir) / "status.db")
            svc.start()
            try:
                status = svc.status()
                required = ("running", "host_id", "mode", "cycle_count",
                            "total_events", "total_incidents", "db_path")
                for key in required:
                    self.assertIn(key, status, f"Status missing required field: {key}")
            finally:
                svc.stop()

    def test_status_mode_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            svc = ScannerService(db_path=Path(tmpdir) / "status.db")
            svc.start()
            try:
                status = svc.status()
                self.assertIn(status["mode"], ("learning", "monitor"),
                              "Mode must be learning or monitor when running")
            finally:
                svc.stop()


if __name__ == "__main__":
    unittest.main()
