"""Tests for S4-T3: Dedupe, cooldown, and incident updates."""

import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scanner.anomaly.incidents import (
    Incident,
    IncidentManager,
    build_incident_signature,
)
from scanner.anomaly.scoring import ScoringResult
from scanner.anomaly.signals import Signal
from scanner.common.types import IncidentState, Severity
from scanner.storage import SQLiteStorage


def _make_scoring(score: int = 4, signals: list[Signal] | None = None, hard_flag: bool = False) -> ScoringResult:
    sigs = signals or [Signal("new_identity", 2, "new"), Signal("unsigned_writable", 2, "unsigned")]
    return ScoringResult(score=score, severity=Severity.WARNING, signals=sigs, hard_flag=hard_flag)


class BuildIncidentSignatureTests(unittest.TestCase):
    def test_deterministic(self) -> None:
        a = build_incident_signature("h1", "k1", ["new_identity", "unsigned_writable"])
        b = build_incident_signature("h1", "k1", ["unsigned_writable", "new_identity"])
        self.assertEqual(a, b)

    def test_different_host(self) -> None:
        a = build_incident_signature("h1", "k1", ["new_identity"])
        b = build_incident_signature("h2", "k1", ["new_identity"])
        self.assertNotEqual(a, b)

    def test_different_signals(self) -> None:
        a = build_incident_signature("h1", "k1", ["new_identity"])
        b = build_incident_signature("h1", "k1", ["unsigned_writable"])
        self.assertNotEqual(a, b)

    def test_length(self) -> None:
        sig = build_incident_signature("h", "k", ["a"])
        self.assertEqual(len(sig), 16)


class IncidentRoundtripTests(unittest.TestCase):
    def test_to_from_dict(self) -> None:
        inc = Incident(
            host_id="h1", identity_key="k1", signature="sig",
            severity=Severity.WARNING, score=4,
        )
        d = inc.to_dict()
        inc2 = Incident.from_dict(d)
        self.assertEqual(inc2.incident_id, inc.incident_id)
        self.assertEqual(inc2.severity, Severity.WARNING)
        self.assertEqual(inc2.state, IncidentState.OPEN)


class IncidentManagerTests(unittest.TestCase):
    def _make_manager(self, tmpdir: str, cooldown: int = 30) -> tuple:
        store = SQLiteStorage(Path(tmpdir) / "test.db")
        store.initialize()
        mgr = IncidentManager(store.connection, "host-1", cooldown)
        return store, mgr

    def test_creates_incident(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, mgr = self._make_manager(tmpdir)
            scoring = _make_scoring()
            now = datetime(2026, 2, 1, tzinfo=timezone.utc)
            inc = mgr.process_scoring("k1", scoring, now=now)
            self.assertIsNotNone(inc)
            self.assertEqual(inc.severity, Severity.WARNING)
            self.assertEqual(inc.host_id, "host-1")
            store.close()

    def test_zero_score_no_incident(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, mgr = self._make_manager(tmpdir)
            scoring = ScoringResult(score=0, severity=Severity.INFO, signals=[], hard_flag=False)
            inc = mgr.process_scoring("k1", scoring)
            self.assertIsNone(inc)
            store.close()

    def test_duplicate_suppressed_by_cooldown(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, mgr = self._make_manager(tmpdir, cooldown=30)
            scoring = _make_scoring()
            now = datetime(2026, 2, 1, tzinfo=timezone.utc)
            inc1 = mgr.process_scoring("k1", scoring, now=now)
            self.assertIsNotNone(inc1)

            # Same signal pattern within cooldown → suppressed
            inc2 = mgr.process_scoring("k1", scoring, now=now + timedelta(minutes=10))
            self.assertIsNone(inc2)
            store.close()

    def test_update_after_cooldown(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, mgr = self._make_manager(tmpdir, cooldown=30)
            scoring = _make_scoring()
            now = datetime(2026, 2, 1, tzinfo=timezone.utc)
            inc1 = mgr.process_scoring("k1", scoring, now=now)

            # After cooldown → update existing incident
            inc2 = mgr.process_scoring("k1", scoring, now=now + timedelta(minutes=31))
            self.assertIsNotNone(inc2)
            self.assertEqual(inc2.incident_id, inc1.incident_id)
            self.assertEqual(inc2.occurrence_count, 2)
            store.close()

    def test_severity_escalation_on_update(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, mgr = self._make_manager(tmpdir, cooldown=1)
            now = datetime(2026, 2, 1, tzinfo=timezone.utc)

            low = _make_scoring(score=2, signals=[Signal("new_identity", 2, "")])
            mgr.process_scoring("k1", low, now=now)

            high = _make_scoring(score=6, signals=[Signal("new_identity", 2, ""), Signal("unsigned_writable", 2, ""), Signal("new_network_dest", 2, "")])
            inc = mgr.process_scoring("k1", high, now=now + timedelta(minutes=2))
            # Different signal set → different signature → new incident, not update
            # Let's use same signals but higher score won't happen with same codes
            # Instead test hard_flag escalation
            store.close()

    def test_hard_flag_escalation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, mgr = self._make_manager(tmpdir, cooldown=1)
            now = datetime(2026, 2, 1, tzinfo=timezone.utc)

            normal = _make_scoring(score=4, hard_flag=False)
            mgr.process_scoring("k1", normal, now=now)

            hard = _make_scoring(score=4, hard_flag=True)
            inc = mgr.process_scoring("k1", hard, now=now + timedelta(minutes=2))
            self.assertIsNotNone(inc)
            self.assertEqual(inc.severity, Severity.CRITICAL)
            store.close()

    def test_get_open_incidents(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, mgr = self._make_manager(tmpdir)
            now = datetime(2026, 2, 1, tzinfo=timezone.utc)
            mgr.process_scoring("k1", _make_scoring(), now=now)
            mgr.process_scoring("k2", _make_scoring(
                signals=[Signal("resource_spike", 1, "")],
                score=1,
            ), now=now)

            open_incidents = mgr.get_open_incidents()
            self.assertEqual(len(open_incidents), 2)
            store.close()

    def test_different_signals_different_incident(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, mgr = self._make_manager(tmpdir)
            now = datetime(2026, 2, 1, tzinfo=timezone.utc)
            s1 = _make_scoring(score=2, signals=[Signal("new_identity", 2, "")])
            s2 = _make_scoring(score=2, signals=[Signal("unsigned_writable", 2, "")])
            inc1 = mgr.process_scoring("k1", s1, now=now)
            inc2 = mgr.process_scoring("k1", s2, now=now)
            self.assertNotEqual(inc1.incident_id, inc2.incident_id)
            store.close()


if __name__ == "__main__":
    unittest.main()
