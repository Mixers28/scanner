"""Tests for S6-T1: Service orchestrator and status CLI."""

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scanner.service.orchestrator import ScannerService, run_foreground
from scanner.baseline.mode import BaselineMode
from scanner.baseline.stats import IdentityProfile
from scanner.common.types import TelemetryEvent
from scanner.verify.adapters import VerificationResult
from scanner.common.types import Verdict


class ServiceLifecycleTests(unittest.TestCase):
    """Start / stop / status basics."""

    def test_start_and_stop(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            svc = ScannerService(db_path=Path(tmpdir) / "test.db")
            self.assertFalse(svc.is_running)
            svc.start()
            self.assertTrue(svc.is_running)
            svc.stop()
            self.assertFalse(svc.is_running)

    def test_double_stop_safe(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            svc = ScannerService(db_path=Path(tmpdir) / "test.db")
            svc.start()
            svc.stop()
            svc.stop()  # should not raise

    def test_run_cycle_before_start_raises(self) -> None:
        svc = ScannerService()
        with self.assertRaises(RuntimeError):
            svc.run_cycle()

    def test_status_before_start(self) -> None:
        svc = ScannerService()
        status = svc.status()
        self.assertFalse(status["running"])
        self.assertEqual(status["mode"], "unknown")

    def test_status_after_start(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            svc = ScannerService(db_path=Path(tmpdir) / "test.db")
            svc.start()
            try:
                status = svc.status()
                self.assertTrue(status["running"])
                self.assertIn(status["mode"], ("learning", "monitor"))
                self.assertEqual(status["cycle_count"], 0)
                self.assertEqual(status["total_events"], 0)
                self.assertIn("host_id", status)
                self.assertIn("started_ts", status)
                self.assertIn("db_path", status)
            finally:
                svc.stop()


class StatusCLITests(unittest.TestCase):
    def test_status_reads_last_known_persisted_state(self) -> None:
        from scanner.__main__ import main

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            svc = ScannerService(db_path=db_path, host_id="host-1")
            svc.start()
            svc.run_cycle()
            svc.stop()

            out = io.StringIO()
            with redirect_stdout(out):
                ret = main(["status", "--db", str(db_path)])

            self.assertEqual(ret, 0)
            payload = json.loads(out.getvalue())
            self.assertFalse(payload["running"])
            self.assertEqual(payload["host_id"], "host-1")
            self.assertEqual(payload["cycle_count"], 1)
            self.assertEqual(payload["mode"], "learning")


class RunCycleTests(unittest.TestCase):
    """Integration tests for the poll cycle."""

    @patch("scanner.service.orchestrator.collect_network_connections", return_value=[])
    @patch("scanner.service.orchestrator.collect_resource_samples", return_value=[])
    @patch("scanner.service.orchestrator.ProcessCollector")
    def test_cycle_returns_stats(self, mock_pc_cls, mock_res, mock_net) -> None:
        mock_pc = MagicMock()
        mock_pc.snapshot.return_value = ([], [])
        mock_pc_cls.return_value = mock_pc

        with tempfile.TemporaryDirectory() as tmpdir:
            svc = ScannerService(db_path=Path(tmpdir) / "test.db")
            svc.start()
            try:
                stats = svc.run_cycle()
                self.assertIn("events", stats)
                self.assertIn("incidents_created", stats)
                self.assertEqual(stats["events"], 0)
                self.assertEqual(svc._cycle_count, 1)
            finally:
                svc.stop()

    @patch("scanner.service.orchestrator.collect_network_connections", return_value=[])
    @patch("scanner.service.orchestrator.collect_resource_samples", return_value=[])
    @patch("scanner.service.orchestrator.ProcessCollector")
    def test_multiple_cycles_increment_counter(self, mock_pc_cls, mock_res, mock_net) -> None:
        mock_pc = MagicMock()
        mock_pc.snapshot.return_value = ([], [])
        mock_pc_cls.return_value = mock_pc

        with tempfile.TemporaryDirectory() as tmpdir:
            svc = ScannerService(db_path=Path(tmpdir) / "test.db")
            svc.start()
            try:
                svc.run_cycle()
                svc.run_cycle()
                svc.run_cycle()
                self.assertEqual(svc._cycle_count, 3)
                status = svc.status()
                self.assertEqual(status["cycle_count"], 3)
            finally:
                svc.stop()

    @patch("scanner.service.orchestrator.collect_network_connections", return_value=[])
    @patch("scanner.service.orchestrator.collect_resource_samples", return_value=[])
    @patch("scanner.service.orchestrator.ProcessCollector")
    def test_resource_and_network_collectors_follow_poll_intervals(self, mock_pc_cls, mock_res, mock_net) -> None:
        mock_pc = MagicMock()
        mock_pc.snapshot.return_value = ([], [])
        mock_pc_cls.return_value = mock_pc

        with tempfile.TemporaryDirectory() as tmpdir:
            config = {
                "collector": {
                    "process_poll_interval_seconds": 1,
                    "resource_poll_interval_seconds": 60,
                    "network_poll_interval_seconds": 120,
                    "capture_command_line": False,
                    "max_events_per_minute": 6000,
                },
                "baseline": {
                    "learning_window_days": 7,
                    "enable_drift": True,
                    "drift_min_confidence": 0.8,
                },
                "anomaly": {
                    "cooldown_minutes": 30,
                    "resource_spike_intervals": 3,
                },
                "verify": {
                    "total_timeout_seconds": 30,
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
            svc = ScannerService(db_path=Path(tmpdir) / "test.db", config=config)
            svc.start()
            try:
                svc.run_cycle()
                svc.run_cycle()
                self.assertEqual(mock_res.call_count, 1)
                self.assertEqual(mock_net.call_count, 1)
            finally:
                svc.stop()

    @patch("scanner.service.orchestrator.collect_network_connections", return_value=[])
    @patch("scanner.service.orchestrator.collect_resource_samples", return_value=[])
    @patch("scanner.service.orchestrator.evaluate_signals", return_value=[])
    @patch("scanner.service.orchestrator.ProcessCollector")
    def test_process_start_passes_recent_launch_count_to_signal_evaluation(
        self,
        mock_pc_cls,
        mock_eval,
        mock_res,
        mock_net,
    ) -> None:
        event_ts = datetime.now(timezone.utc).isoformat()

        def make_event(pid: int) -> TelemetryEvent:
            return TelemetryEvent(
                event_id=f"ev-{pid}",
                host_id="host-1",
                ts=event_ts,
                event_type="process_start",
                pid=pid,
                payload={
                    "identity_key": "k1",
                    "image_path_norm": r"c:\program files\app.exe",
                    "signer_publisher": "Microsoft",
                },
            )

        mock_pc = MagicMock()
        mock_pc.snapshot.return_value = ([make_event(101), make_event(102), make_event(103), make_event(104)], [])
        mock_pc_cls.return_value = mock_pc

        with tempfile.TemporaryDirectory() as tmpdir:
            svc = ScannerService(db_path=Path(tmpdir) / "test.db", host_id="host-1")
            svc.start()
            try:
                profile = IdentityProfile(identity_key="k1", launch_count=10)
                svc._snapshot_store.save_snapshot(1, {"k1": profile})
                svc._mode_manager.force_mode(BaselineMode.MONITOR)

                svc.run_cycle()

                recent_counts = [
                    call.kwargs.get("recent_launch_count")
                    for call in mock_eval.call_args_list
                    if call.args[0] == "k1"
                ]
                self.assertTrue(recent_counts)
                self.assertIn(4, recent_counts)
            finally:
                svc.stop()

    @patch("scanner.service.orchestrator.run_verification_with_budget")
    @patch("scanner.service.orchestrator.collect_network_connections", return_value=[])
    @patch("scanner.service.orchestrator.collect_resource_samples", return_value=[])
    @patch("scanner.service.orchestrator.ProcessCollector")
    def test_verification_results_persisted_for_incident(
        self,
        mock_pc_cls,
        mock_res,
        mock_net,
        mock_verify,
    ) -> None:
        event_ts = datetime.now(timezone.utc).isoformat()
        mock_pc = MagicMock()
        mock_pc.snapshot.return_value = ([
            TelemetryEvent(
                event_id="ev-1",
                host_id="host-1",
                ts=event_ts,
                event_type="process_start",
                pid=101,
                payload={
                    "identity_key": "new-k1",
                    "image_path": r"C:\Users\alice\Downloads\tool.exe",
                    "image_path_norm": r"c:\users\alice\downloads\tool.exe",
                    "signer_publisher": "unsigned",
                },
            )
        ], [])
        mock_pc_cls.return_value = mock_pc
        mock_verify.return_value = [
            VerificationResult(
                adapter_name="signature",
                verdict=Verdict.UNKNOWN,
                evidence={"reason": "stub"},
                duration_ms=12,
            )
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            svc = ScannerService(db_path=Path(tmpdir) / "test.db", host_id="host-1")
            svc.start()
            try:
                svc._mode_manager.force_mode(BaselineMode.MONITOR)
                stats = svc.run_cycle()
                self.assertEqual(stats["incidents_created"], 1)
                incidents = svc._incident_manager.get_open_incidents()
                self.assertEqual(len(incidents), 1)
                rows = svc._storage.connection.execute(
                    "SELECT adapter_name, verdict, duration_ms FROM verification_result WHERE incident_id = ?",
                    (incidents[0].incident_id,),
                ).fetchall()
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["adapter_name"], "signature")
                self.assertEqual(rows[0]["verdict"], "unknown")
                self.assertEqual(rows[0]["duration_ms"], 12)
            finally:
                svc.stop()


class RetentionTests(unittest.TestCase):
    """Retention cleanup integration."""

    def test_retention_before_start(self) -> None:
        svc = ScannerService()
        result = svc.run_retention()
        self.assertEqual(result, {})

    def test_retention_after_start(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            svc = ScannerService(db_path=Path(tmpdir) / "test.db")
            svc.start()
            try:
                result = svc.run_retention()
                self.assertIn("deleted_telemetry", result)
                self.assertIn("deleted_baselines", result)
            finally:
                svc.stop()


class BaselineCommitTests(unittest.TestCase):
    """Baseline snapshot commit."""

    def test_commit_empty_returns_none(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            svc = ScannerService(db_path=Path(tmpdir) / "test.db")
            svc.start()
            try:
                result = svc.commit_baseline()
                self.assertIsNone(result)
            finally:
                svc.stop()

    def test_commit_before_start_returns_none(self) -> None:
        svc = ScannerService()
        self.assertIsNone(svc.commit_baseline())


class RunForegroundTests(unittest.TestCase):
    """Foreground run loop with max_cycles."""

    @patch("scanner.service.orchestrator.collect_network_connections", return_value=[])
    @patch("scanner.service.orchestrator.collect_resource_samples", return_value=[])
    @patch("scanner.service.orchestrator.ProcessCollector")
    def test_foreground_limited_cycles(self, mock_pc_cls, mock_res, mock_net) -> None:
        mock_pc = MagicMock()
        mock_pc.snapshot.return_value = ([], [])
        mock_pc_cls.return_value = mock_pc

        with tempfile.TemporaryDirectory() as tmpdir:
            db = str(Path(tmpdir) / "test.db")
            svc = run_foreground(db_path=db, max_cycles=3)
            self.assertFalse(svc.is_running)
            self.assertEqual(svc._cycle_count, 3)


class ReportGenerationTests(unittest.TestCase):
    """Report file generation."""

    @patch("scanner.service.orchestrator.collect_network_connections", return_value=[])
    @patch("scanner.service.orchestrator.collect_resource_samples", return_value=[])
    @patch("scanner.service.orchestrator.ProcessCollector")
    def test_generate_report_creates_files(self, mock_pc_cls, mock_res, mock_net) -> None:
        mock_pc = MagicMock()
        mock_pc.snapshot.return_value = ([], [])
        mock_pc_cls.return_value = mock_pc

        with tempfile.TemporaryDirectory() as tmpdir:
            svc = ScannerService(db_path=Path(tmpdir) / "test.db")
            svc.start()
            try:
                # Directly test _generate_report
                incident_data = {
                    "incident_id": "test-inc-001",
                    "severity": "warning",
                    "score": 4,
                    "signals": [
                        {"code": "new_identity", "points": 2, "description": "New process"},
                    ],
                }
                svc._config["reporting"]["out_dir"] = str(Path(tmpdir) / "reports")
                svc._generate_report(incident_data, [])

                report_dir = Path(tmpdir) / "reports"
                self.assertTrue((report_dir / "test-inc-001.json").exists())
                self.assertTrue((report_dir / "test-inc-001.html").exists())

                # Verify JSON is valid
                content = (report_dir / "test-inc-001.json").read_text(encoding="utf-8")
                parsed = json.loads(content)
                self.assertEqual(parsed["incident_id"], "test-inc-001")
            finally:
                svc.stop()


if __name__ == "__main__":
    unittest.main()
