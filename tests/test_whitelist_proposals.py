"""Tests for S3-T3: Candidate proposal and approval metadata."""

import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scanner.baseline.stats import IdentityProfile
from scanner.whitelist.proposals import (
    propose_candidates,
    approve_rule,
    WhitelistStore,
)
from scanner.whitelist.rules import RuleScope, WhitelistRule
from scanner.storage import SQLiteStorage


def _high_confidence_profile(key: str = "k1") -> IdentityProfile:
    """Build a profile that meets the default confidence threshold."""
    p = IdentityProfile(identity_key=key)
    for i in range(35):
        p.record_launch(f"2026-01-{(i % 28)+1:02d}T00:00:00", parent_key="parent1")
        p.record_resource(5.0, 2048)
    p.record_network("10.0.0.1", 443)
    return p


def _low_confidence_profile(key: str = "k2") -> IdentityProfile:
    p = IdentityProfile(identity_key=key)
    p.record_launch("2026-01-01T00:00:00")
    return p


class ProposeCandidatesTests(unittest.TestCase):
    def test_proposes_high_confidence(self) -> None:
        profiles = {"k1": _high_confidence_profile()}
        candidates = propose_candidates(profiles, min_confidence=0.8)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].identity_key, "k1")
        self.assertEqual(candidates[0].source, "baseline_proposal")
        self.assertEqual(candidates[0].approved_ts, "")

    def test_skips_low_confidence(self) -> None:
        profiles = {"k2": _low_confidence_profile()}
        candidates = propose_candidates(profiles, min_confidence=0.8)
        self.assertEqual(len(candidates), 0)

    def test_mixed_profiles(self) -> None:
        profiles = {
            "k1": _high_confidence_profile("k1"),
            "k2": _low_confidence_profile("k2"),
        }
        candidates = propose_candidates(profiles, min_confidence=0.8)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].identity_key, "k1")


class ApproveRuleTests(unittest.TestCase):
    def test_sets_approved_ts(self) -> None:
        rule = WhitelistRule(identity_key="k1", source="baseline_proposal")
        now = datetime(2026, 2, 1, tzinfo=timezone.utc)
        approved = approve_rule(rule, now=now)
        self.assertEqual(approved.approved_ts, now.isoformat())
        self.assertEqual(approved.identity_key, "k1")

    def test_preserves_fields(self) -> None:
        rule = WhitelistRule(
            identity_key="k1", source="baseline_proposal",
            rationale="auto", file_hash="abc",
        )
        approved = approve_rule(rule)
        self.assertEqual(approved.source, "baseline_proposal")
        self.assertEqual(approved.rationale, "auto")
        self.assertEqual(approved.file_hash, "abc")


class WhitelistStoreTests(unittest.TestCase):
    def _make(self, tmpdir: str) -> tuple:
        store = SQLiteStorage(Path(tmpdir) / "test.db")
        store.initialize()
        ws = WhitelistStore(store.connection, "host-1")
        return store, ws

    def test_save_and_load_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, ws = self._make(tmpdir)
            rule = WhitelistRule(identity_key="k1", rationale="test")
            approved = approve_rule(rule)
            count = ws.save_rules(1, [approved])
            self.assertEqual(count, 1)

            loaded = ws.load_rules(1)
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0].identity_key, "k1")
            self.assertNotEqual(loaded[0].approved_ts, "")
            store.close()

    def test_load_active_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, ws = self._make(tmpdir)
            unapproved = WhitelistRule(identity_key="k1")
            approved = approve_rule(WhitelistRule(identity_key="k2"))
            ws.save_rules(1, [unapproved, approved])

            active = ws.load_active_rules()
            self.assertEqual(len(active), 1)
            self.assertEqual(active[0].identity_key, "k2")
            store.close()

    def test_skips_invalid_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, ws = self._make(tmpdir)
            bad_rule = WhitelistRule(identity_key="")  # fails safety rail
            good_rule = WhitelistRule(identity_key="k1")
            count = ws.save_rules(1, [bad_rule, good_rule])
            self.assertEqual(count, 1)
            store.close()

    def test_latest_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, ws = self._make(tmpdir)
            self.assertIsNone(ws.latest_version())
            ws.save_rules(1, [WhitelistRule(identity_key="k1")])
            ws.save_rules(3, [WhitelistRule(identity_key="k2")])
            self.assertEqual(ws.latest_version(), 3)
            store.close()

    def test_prune_old_versions(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, ws = self._make(tmpdir)
            for v in range(1, 55):
                ws.save_rules(v, [WhitelistRule(identity_key=f"k{v}")])
            self.assertEqual(len(ws.list_versions()), 54)
            deleted = ws.prune_old_versions(keep=50)
            self.assertGreater(deleted, 0)
            self.assertEqual(len(ws.list_versions()), 50)
            store.close()

    def test_survives_restart(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"

            store1 = SQLiteStorage(db_path)
            store1.initialize()
            ws1 = WhitelistStore(store1.connection, "host-1")
            ws1.save_rules(1, [approve_rule(WhitelistRule(identity_key="k1"))])
            store1.close()

            store2 = SQLiteStorage(db_path)
            store2.initialize()
            ws2 = WhitelistStore(store2.connection, "host-1")
            active = ws2.load_active_rules()
            self.assertEqual(len(active), 1)
            self.assertEqual(active[0].identity_key, "k1")
            store2.close()


if __name__ == "__main__":
    unittest.main()
