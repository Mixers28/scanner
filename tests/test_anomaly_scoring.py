"""Tests for S4-T2: Score mapping and severity."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scanner.anomaly.signals import Signal
from scanner.anomaly.scoring import compute_score, map_severity, score_signals, ScoringResult
from scanner.common.types import Severity


class ComputeScoreTests(unittest.TestCase):
    def test_empty(self) -> None:
        self.assertEqual(compute_score([]), 0)

    def test_single(self) -> None:
        self.assertEqual(compute_score([Signal("x", 2, "")]), 2)

    def test_multiple(self) -> None:
        signals = [Signal("a", 2, ""), Signal("b", 1, ""), Signal("c", 2, "")]
        self.assertEqual(compute_score(signals), 5)


class MapSeverityTests(unittest.TestCase):
    def test_info_range(self) -> None:
        self.assertEqual(map_severity(1), Severity.INFO)
        self.assertEqual(map_severity(2), Severity.INFO)

    def test_warning_range(self) -> None:
        self.assertEqual(map_severity(3), Severity.WARNING)
        self.assertEqual(map_severity(5), Severity.WARNING)

    def test_critical_by_score(self) -> None:
        self.assertEqual(map_severity(6), Severity.CRITICAL)
        self.assertEqual(map_severity(10), Severity.CRITICAL)

    def test_critical_by_hard_flag(self) -> None:
        self.assertEqual(map_severity(1, hard_flag=True), Severity.CRITICAL)
        self.assertEqual(map_severity(0, hard_flag=True), Severity.CRITICAL)


class ScoreSignalsTests(unittest.TestCase):
    def test_hard_flag_escalation(self) -> None:
        signals = [Signal("unsigned_writable", 2, "")]
        payload = {
            "signer_publisher": "unsigned",
            "image_path_norm": r"c:\users\alice\downloads\evil.exe",
            "remote_ip": "1.2.3.4",
        }
        result = score_signals(signals, payload)
        self.assertTrue(result.hard_flag)
        self.assertEqual(result.severity, Severity.CRITICAL)

    def test_no_hard_flag_signed(self) -> None:
        signals = [Signal("new_identity", 2, "")]
        payload = {
            "signer_publisher": "Trusted Corp",
            "image_path_norm": r"c:\program files\app.exe",
        }
        result = score_signals(signals, payload)
        self.assertFalse(result.hard_flag)
        self.assertEqual(result.severity, Severity.INFO)
        self.assertEqual(result.score, 2)

    def test_no_hard_flag_unknown_signer(self) -> None:
        signals = [Signal("new_identity", 2, "")]
        payload = {
            "signer_publisher": "unknown",
            "image_path_norm": r"c:\users\alice\downloads\app.exe",
            "remote_ip": "1.2.3.4",
        }
        result = score_signals(signals, payload)
        self.assertFalse(result.hard_flag)
        self.assertEqual(result.severity, Severity.INFO)

    def test_warning_threshold(self) -> None:
        signals = [Signal("a", 2, ""), Signal("b", 1, "")]
        payload = {}
        result = score_signals(signals, payload)
        self.assertEqual(result.severity, Severity.WARNING)

    def test_critical_by_score_alone(self) -> None:
        signals = [Signal("a", 2, ""), Signal("b", 2, ""), Signal("c", 2, "")]
        payload = {}
        result = score_signals(signals, payload)
        self.assertEqual(result.score, 6)
        self.assertEqual(result.severity, Severity.CRITICAL)

    def test_result_contains_signals(self) -> None:
        signals = [Signal("x", 1, "test")]
        result = score_signals(signals, {})
        self.assertEqual(len(result.signals), 1)
        self.assertEqual(result.signals[0].code, "x")


if __name__ == "__main__":
    unittest.main()
