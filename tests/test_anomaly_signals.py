"""Tests for S4-T1: Anomaly signal calculation."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scanner.baseline.stats import IdentityProfile
from scanner.anomaly.signals import (
    check_new_identity,
    check_unsigned_writable,
    check_unusual_parent,
    check_new_network_dest,
    check_resource_spike,
    check_burst_launch,
    check_hard_escalation,
    evaluate_signals,
)


def _baseline_profile(key: str = "k1") -> IdentityProfile:
    p = IdentityProfile(identity_key=key)
    for i in range(10):
        p.record_launch(f"2026-01-{i+1:02d}T00:00:00", parent_key="parent1")
        p.record_resource(3.0, 1024 * 1024)  # 3% CPU, 1MB
    p.record_network("10.0.0.1", 443)
    return p


class CheckNewIdentityTests(unittest.TestCase):
    def test_new_identity_detected(self) -> None:
        sig = check_new_identity("unknown", {})
        self.assertIsNotNone(sig)
        self.assertEqual(sig.code, "new_identity")
        self.assertEqual(sig.points, 2)

    def test_known_identity_no_signal(self) -> None:
        sig = check_new_identity("k1", {"k1": _baseline_profile()})
        self.assertIsNone(sig)


class CheckUnsignedWritableTests(unittest.TestCase):
    def test_unsigned_writable_detected(self) -> None:
        sig = check_unsigned_writable("unsigned", r"c:\users\alice\downloads\evil.exe")
        self.assertIsNotNone(sig)
        self.assertEqual(sig.code, "unsigned_writable")

    def test_signed_writable_no_signal(self) -> None:
        sig = check_unsigned_writable("Microsoft Corp", r"c:\users\alice\downloads\app.exe")
        self.assertIsNone(sig)

    def test_unknown_writable_no_signal(self) -> None:
        sig = check_unsigned_writable("unknown", r"c:\users\alice\downloads\app.exe")
        self.assertIsNone(sig)

    def test_unsigned_system_no_signal(self) -> None:
        sig = check_unsigned_writable("unsigned", r"c:\program files\app.exe")
        self.assertIsNone(sig)


class CheckUnusualParentTests(unittest.TestCase):
    def test_unusual_parent_detected(self) -> None:
        profiles = {"k1": _baseline_profile()}
        sig = check_unusual_parent("k1", "rogue_parent", profiles)
        self.assertIsNotNone(sig)
        self.assertEqual(sig.code, "unusual_parent")

    def test_known_parent_no_signal(self) -> None:
        profiles = {"k1": _baseline_profile()}
        sig = check_unusual_parent("k1", "parent1", profiles)
        self.assertIsNone(sig)

    def test_unknown_identity_returns_none(self) -> None:
        sig = check_unusual_parent("unknown", "any", {})
        self.assertIsNone(sig)


class CheckNewNetworkDestTests(unittest.TestCase):
    def test_new_dest_detected(self) -> None:
        profiles = {"k1": _baseline_profile()}
        sig = check_new_network_dest("k1", "8.8.8.8", 53, profiles)
        self.assertIsNotNone(sig)
        self.assertEqual(sig.code, "new_network_dest")

    def test_known_dest_no_signal(self) -> None:
        profiles = {"k1": _baseline_profile()}
        sig = check_new_network_dest("k1", "10.0.0.1", 443, profiles)
        self.assertIsNone(sig)

    def test_unknown_identity_detected(self) -> None:
        sig = check_new_network_dest("unknown", "1.2.3.4", 80, {})
        self.assertIsNotNone(sig)


class CheckResourceSpikeTests(unittest.TestCase):
    def test_cpu_spike_detected(self) -> None:
        profiles = {"k1": _baseline_profile()}
        sig = check_resource_spike("k1", 80.0, 0, profiles)
        self.assertIsNotNone(sig)
        self.assertEqual(sig.code, "resource_spike")

    def test_normal_cpu_no_signal(self) -> None:
        profiles = {"k1": _baseline_profile()}
        sig = check_resource_spike("k1", 3.0, 1024 * 1024, profiles)
        self.assertIsNone(sig)

    def test_unknown_identity_returns_none(self) -> None:
        sig = check_resource_spike("unknown", 99.0, 0, {})
        self.assertIsNone(sig)


class CheckBurstLaunchTests(unittest.TestCase):
    def test_burst_detected(self) -> None:
        profiles = {"k1": _baseline_profile()}  # 10 launches over ~7 days
        sig = check_burst_launch("k1", 50, 10, profiles)
        self.assertIsNotNone(sig)
        self.assertEqual(sig.code, "burst_launch")

    def test_normal_rate_no_signal(self) -> None:
        profiles = {"k1": _baseline_profile()}
        sig = check_burst_launch("k1", 1, 10, profiles)
        self.assertIsNone(sig)


class CheckHardEscalationTests(unittest.TestCase):
    def test_hard_flag_all_conditions(self) -> None:
        self.assertTrue(check_hard_escalation(
            "unsigned", r"c:\users\alice\downloads\evil.exe", True,
        ))

    def test_no_flag_signed(self) -> None:
        self.assertFalse(check_hard_escalation(
            "Microsoft", r"c:\users\alice\downloads\app.exe", True,
        ))

    def test_no_flag_unknown(self) -> None:
        self.assertFalse(check_hard_escalation(
            "unknown", r"c:\users\alice\downloads\app.exe", True,
        ))

    def test_no_flag_no_network(self) -> None:
        self.assertFalse(check_hard_escalation(
            "unsigned", r"c:\users\alice\downloads\app.exe", False,
        ))

    def test_no_flag_system_path(self) -> None:
        self.assertFalse(check_hard_escalation(
            "unsigned", r"c:\program files\app.exe", True,
        ))


class EvaluateSignalsTests(unittest.TestCase):
    def test_new_identity_returns_signal(self) -> None:
        signals = evaluate_signals("unknown", {}, {})
        codes = [s.code for s in signals]
        self.assertIn("new_identity", codes)

    def test_combined_signals(self) -> None:
        profiles = {"k1": _baseline_profile()}
        payload = {
            "image_path_norm": r"c:\users\alice\downloads\app.exe",
            "signer_publisher": "unsigned",
            "remote_ip": "8.8.8.8",
            "remote_port": 53,
            "parent_identity_key": "rogue",
        }
        signals = evaluate_signals("k1", payload, profiles)
        codes = {s.code for s in signals}
        self.assertIn("unsigned_writable", codes)
        self.assertIn("unusual_parent", codes)
        self.assertIn("new_network_dest", codes)

    def test_no_signals_for_clean_known(self) -> None:
        profiles = {"k1": _baseline_profile()}
        payload = {
            "image_path_norm": r"c:\program files\app.exe",
            "signer_publisher": "Microsoft",
            "parent_identity_key": "parent1",
        }
        signals = evaluate_signals("k1", payload, profiles)
        self.assertEqual(len(signals), 0)


if __name__ == "__main__":
    unittest.main()
