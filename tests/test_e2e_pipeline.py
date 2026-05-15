"""End-to-end pipeline integration tests.

Covers SPEC §8 MVP acceptance criteria scenarios A, B, and C.

  A) unsigned executable in user-writable dir + outbound connection → critical
  B) unusual parent chain not in baseline → warning
  C) sustained resource spike above baseline p90 → incident generated
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scanner.baseline.mode import BaselineMode
from scanner.baseline.stats import IdentityProfile, ResourceStats
from scanner.common.types import TelemetryEvent
from scanner.service.orchestrator import ScannerService


def _make_event(
    host_id: str,
    event_type: str,
    payload: dict,
    pid: int = 1000,
) -> TelemetryEvent:
    return TelemetryEvent(
        event_id=f"ev-{pid}-{event_type}",
        host_id=host_id,
        ts=datetime.now(timezone.utc).isoformat(),
        event_type=event_type,
        pid=pid,
        payload=payload,
    )


class ScenarioATests(unittest.TestCase):
    """SPEC §8 criterion 3: unsigned + user-writable + outbound → critical."""

    @patch("scanner.service.orchestrator.collect_network_connections")
    @patch("scanner.service.orchestrator.collect_resource_samples", return_value=[])
    @patch("scanner.service.orchestrator.ProcessCollector")
    def test_unsigned_writable_outbound_produces_critical_incident(
        self, mock_pc_cls, mock_res, mock_net
    ) -> None:
        host_id = "host-scenario-a"
        mock_pc = MagicMock()
        mock_pc.snapshot.return_value = ([], [])
        mock_pc_cls.return_value = mock_pc

        mock_net.return_value = [
            _make_event(
                host_id,
                "net_conn",
                {
                    "identity_key": "evil_key_abc",
                    "image_path_norm": r"c:\users\test\downloads\evil.exe",
                    "signer_publisher": "unsigned",
                    "remote_ip": "1.2.3.4",
                    "remote_port": 4444,
                },
                pid=9999,
            )
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            report_dir = Path(tmpdir) / "reports"
            svc = ScannerService(
                db_path=Path(tmpdir) / "test.db",
                host_id=host_id,
                config=_make_config(tmpdir, report_dir),
            )
            svc.start()
            try:
                svc._mode_manager.force_mode(BaselineMode.MONITOR)
                stats = svc.run_cycle()

                self.assertEqual(stats["incidents_created"], 1,
                                 "Expected exactly one incident from Scenario A")

                incidents = svc._incident_manager.get_open_incidents()
                self.assertEqual(len(incidents), 1)
                self.assertEqual(incidents[0].severity.value, "critical",
                                 "Unsigned+writable+outbound must produce critical severity")

                report_files = list(report_dir.glob("*.json"))
                self.assertEqual(len(report_files), 1, "Expected one JSON report file")
                report = json.loads(report_files[0].read_text(encoding="utf-8"))
                self.assertIn("summary", report)
                self.assertIn("what_happened", report["summary"])
                self.assertIn("safe_next_actions", report["summary"])
            finally:
                svc.stop()


class ScenarioBTests(unittest.TestCase):
    """SPEC §8 criterion 4: unusual parent chain → warning or critical."""

    @patch("scanner.service.orchestrator.collect_network_connections")
    @patch("scanner.service.orchestrator.collect_resource_samples", return_value=[])
    @patch("scanner.service.orchestrator.ProcessCollector")
    def test_unusual_parent_chain_produces_warning_or_critical(
        self, mock_pc_cls, mock_res, mock_net
    ) -> None:
        host_id = "host-scenario-b"
        identity_key = "known_process_key"
        known_parent = "known_parent_key"
        unknown_parent = "unknown_parent_key"

        mock_pc = MagicMock()
        mock_pc.snapshot.return_value = ([], [])
        mock_pc_cls.return_value = mock_pc

        # Event has both unusual parent AND new network dest → score 4 = WARNING
        mock_net.return_value = [
            _make_event(
                host_id,
                "net_conn",
                {
                    "identity_key": identity_key,
                    "image_path_norm": r"c:\program files\legit\app.exe",
                    "signer_publisher": "TrustCo",
                    "parent_identity_key": unknown_parent,
                    "remote_ip": "5.6.7.8",
                    "remote_port": 80,
                },
                pid=2000,
            )
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            svc = ScannerService(
                db_path=Path(tmpdir) / "test.db",
                host_id=host_id,
                config=_make_config(tmpdir),
            )
            svc.start()
            try:
                # Baseline: process is known but with a different parent
                profile = IdentityProfile(identity_key=identity_key, launch_count=50)
                profile.parent_keys = {known_parent}
                svc._snapshot_store.save_snapshot(1, {identity_key: profile})
                svc._mode_manager.force_mode(BaselineMode.MONITOR)

                stats = svc.run_cycle()
                self.assertEqual(stats["incidents_created"], 1,
                                 "Expected one incident for unusual parent chain")

                incidents = svc._incident_manager.get_open_incidents()
                self.assertEqual(len(incidents), 1)
                self.assertIn(incidents[0].severity.value, ("warning", "critical"),
                              "Unusual parent must produce warning or critical severity")
            finally:
                svc.stop()


class ScenarioCTests(unittest.TestCase):
    """SPEC §8 criterion 5: sustained resource spike → incident generated."""

    @patch("scanner.service.orchestrator.collect_network_connections", return_value=[])
    @patch("scanner.service.orchestrator.collect_resource_samples")
    @patch("scanner.service.orchestrator.ProcessCollector")
    def test_resource_spike_produces_incident(
        self, mock_pc_cls, mock_res, mock_net
    ) -> None:
        host_id = "host-scenario-c"
        identity_key = "resource_hog_key"

        mock_pc = MagicMock()
        mock_pc.snapshot.return_value = ([], [])
        mock_pc_cls.return_value = mock_pc

        mock_res.return_value = [
            _make_event(
                host_id,
                "resource_sample",
                {
                    "identity_key": identity_key,
                    "image_path_norm": r"c:\program files\miner\miner.exe",
                    "signer_publisher": "MinerCo",
                    "cpu_percent": 95.0,
                    "memory_rss_bytes": 0,
                },
                pid=3000,
            )
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            svc = ScannerService(
                db_path=Path(tmpdir) / "test.db",
                host_id=host_id,
                config=_make_config(tmpdir),
            )
            svc.start()
            try:
                # Baseline: process seen with low CPU (p90 ≈ 10%)
                profile = IdentityProfile(identity_key=identity_key, launch_count=100)
                for _ in range(20):
                    profile.resource.add(cpu=5.0, mem=50_000_000)
                profile.resource.add(cpu=10.0, mem=60_000_000)
                svc._snapshot_store.save_snapshot(1, {identity_key: profile})
                svc._mode_manager.force_mode(BaselineMode.MONITOR)

                stats = svc.run_cycle()
                self.assertEqual(stats["incidents_created"], 1,
                                 "Expected one incident for resource spike")

                incidents = svc._incident_manager.get_open_incidents()
                self.assertEqual(len(incidents), 1)
                signal_codes = [s["code"] for s in incidents[0].signals]
                self.assertIn("resource_spike", signal_codes,
                              "resource_spike signal must be present")
            finally:
                svc.stop()


class ExportReportCLITests(unittest.TestCase):
    """SPEC §8 criterion 7: user-facing report generated and exportable."""

    @patch("scanner.service.orchestrator.collect_network_connections")
    @patch("scanner.service.orchestrator.collect_resource_samples", return_value=[])
    @patch("scanner.service.orchestrator.ProcessCollector")
    def test_export_report_roundtrip(self, mock_pc_cls, mock_res, mock_net) -> None:
        from scanner.__main__ import main

        host_id = "host-export"
        mock_pc = MagicMock()
        mock_pc.snapshot.return_value = ([], [])
        mock_pc_cls.return_value = mock_pc

        mock_net.return_value = [
            _make_event(
                host_id,
                "net_conn",
                {
                    "identity_key": "export_test_key",
                    "image_path_norm": r"c:\users\attacker\payload.exe",
                    "signer_publisher": "unsigned",
                    "remote_ip": "10.0.0.1",
                    "remote_port": 8080,
                },
                pid=7777,
            )
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "test.db")
            report_dir = str(Path(tmpdir) / "reports")
            export_dir = str(Path(tmpdir) / "exported")

            svc = ScannerService(
                db_path=db_path,
                host_id=host_id,
                config=_make_config(tmpdir, Path(report_dir)),
            )
            svc.start()
            try:
                svc._mode_manager.force_mode(BaselineMode.MONITOR)
                svc.run_cycle()
                incidents = svc._incident_manager.get_open_incidents()
                self.assertEqual(len(incidents), 1)
                incident_id = incidents[0].incident_id
            finally:
                svc.stop()

            # Now use the CLI to export the report
            ret = main([
                "export-report",
                "--incident", incident_id,
                "--db", db_path,
                "--out-dir", export_dir,
                "--formats", "json,html,text",
            ])
            self.assertEqual(ret, 0)

            exported = Path(export_dir)
            self.assertTrue((exported / f"{incident_id}.json").exists())
            self.assertTrue((exported / f"{incident_id}.html").exists())
            self.assertTrue((exported / f"{incident_id}.txt").exists())

            data = json.loads((exported / f"{incident_id}.json").read_text(encoding="utf-8"))
            summary = data["summary"]
            for field in ("what_happened", "why_it_matters", "what_changed",
                          "checks_ran", "safe_next_actions"):
                self.assertTrue(summary.get(field, "").strip(),
                                f"Missing required plain-language field: {field}")
            self.assertEqual(len(data["verification_results"]), 1)
            self.assertEqual(data["verification_results"][0]["adapter_name"], "signature")

    def test_export_report_missing_db(self) -> None:
        from scanner.__main__ import main
        ret = main(["export-report", "--incident", "nonexistent", "--db", "/nonexistent/path.db"])
        self.assertEqual(ret, 1)

    def test_export_report_missing_incident(self) -> None:
        from scanner.__main__ import main
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "test.db")
            svc = ScannerService(db_path=db_path)
            svc.start()
            svc.stop()
            ret = main(["export-report", "--incident", "no-such-id", "--db", db_path])
            self.assertEqual(ret, 1)


def _make_config(tmpdir: str, report_dir: Path | None = None) -> dict:
    report_dir = report_dir or Path(tmpdir) / "reports"
    return {
        "collector": {
            "process_poll_interval_seconds": 2,
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
            "out_dir": str(report_dir),
        },
        "retention": {
            "telemetry_days": 7,
            "incidents_days": 90,
            "max_baseline_versions": 10,
            "max_whitelist_versions": 50,
            "max_db_mb": 500,
        },
    }


if __name__ == "__main__":
    unittest.main()
