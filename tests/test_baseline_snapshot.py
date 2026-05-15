"""Tests for S2-T3: Versioned baseline snapshot persistence."""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scanner.baseline.snapshot import BaselineSnapshotStore
from scanner.baseline.stats import IdentityProfile, BaselineAggregator, compute_confidence
from scanner.anomaly.signals import check_resource_spike
from scanner.storage import SQLiteStorage


def _build_profiles() -> dict[str, IdentityProfile]:
    agg = BaselineAggregator()
    agg.ingest("process_start", {"identity_key": "k1"}, "2026-01-01T00:00:00")
    agg.ingest("resource_sample", {
        "identity_key": "k1", "cpu_percent": 5.0, "memory_rss_bytes": 2048,
    }, "2026-01-01T01:00:00")
    agg.ingest("net_conn", {
        "identity_key": "k1", "remote_ip": "10.0.0.1", "remote_port": 443,
    }, "2026-01-01T02:00:00")
    agg.ingest("process_start", {"identity_key": "k2"}, "2026-01-01T03:00:00")
    return agg.profiles


class BaselineSnapshotStoreTests(unittest.TestCase):
    def _make_store_and_snap(self, tmpdir: str) -> tuple:
        store = SQLiteStorage(Path(tmpdir) / "test.db")
        store.initialize()
        snap = BaselineSnapshotStore(store.connection, "host-1")
        return store, snap

    def test_save_and_load_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, snap = self._make_store_and_snap(tmpdir)
            profiles = _build_profiles()

            count = snap.save_snapshot(1, profiles)
            self.assertEqual(count, 2)

            loaded = snap.load_snapshot(1)
            self.assertEqual(set(loaded.keys()), {"k1", "k2"})
            self.assertEqual(loaded["k1"].launch_count, 1)
            self.assertIn("10.0.0.1:443", loaded["k1"].network_destinations)
            store.close()

    def test_latest_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, snap = self._make_store_and_snap(tmpdir)
            self.assertIsNone(snap.latest_version())

            snap.save_snapshot(1, _build_profiles())
            snap.save_snapshot(3, _build_profiles())
            self.assertEqual(snap.latest_version(), 3)
            store.close()

    def test_list_versions(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, snap = self._make_store_and_snap(tmpdir)
            snap.save_snapshot(1, _build_profiles())
            snap.save_snapshot(2, _build_profiles())
            snap.save_snapshot(5, _build_profiles())
            self.assertEqual(snap.list_versions(), [1, 2, 5])
            store.close()

    def test_prune_old_versions(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, snap = self._make_store_and_snap(tmpdir)
            for v in range(1, 13):
                snap.save_snapshot(v, _build_profiles())

            self.assertEqual(len(snap.list_versions()), 12)
            deleted = snap.prune_old_versions(keep=10)
            self.assertGreater(deleted, 0)
            remaining = snap.list_versions()
            self.assertEqual(len(remaining), 10)
            self.assertEqual(remaining[0], 3)  # versions 1,2 pruned
            store.close()

    def test_prune_noop_when_under_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, snap = self._make_store_and_snap(tmpdir)
            snap.save_snapshot(1, _build_profiles())
            deleted = snap.prune_old_versions(keep=10)
            self.assertEqual(deleted, 0)
            store.close()

    def test_survives_restart(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            profiles = _build_profiles()

            store1 = SQLiteStorage(db_path)
            store1.initialize()
            snap1 = BaselineSnapshotStore(store1.connection, "host-1")
            snap1.save_snapshot(1, profiles)
            store1.close()

            store2 = SQLiteStorage(db_path)
            store2.initialize()
            snap2 = BaselineSnapshotStore(store2.connection, "host-1")
            loaded = snap2.load_snapshot(1)
            self.assertEqual(set(loaded.keys()), {"k1", "k2"})
            self.assertEqual(loaded["k1"].launch_count, 1)
            store2.close()

    def test_version_stable_unless_new_commit(self) -> None:
        """Loading same version twice gives identical data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store, snap = self._make_store_and_snap(tmpdir)
            snap.save_snapshot(1, _build_profiles())

            load_a = snap.load_snapshot(1)
            load_b = snap.load_snapshot(1)
            for key in load_a:
                self.assertEqual(load_a[key].to_dict(), load_b[key].to_dict())
            store.close()

    def test_confidence_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, snap = self._make_store_and_snap(tmpdir)
            profiles = _build_profiles()
            snap.save_snapshot(1, profiles)

            row = store.connection.execute(
                "SELECT confidence FROM baseline_profile WHERE identity_key = 'k1' AND baseline_version = 1"
            ).fetchone()
            self.assertIsNotNone(row)
            self.assertGreater(row["confidence"], 0.0)
            store.close()

    def test_loaded_snapshot_preserves_resource_thresholds(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, snap = self._make_store_and_snap(tmpdir)
            profiles = _build_profiles()
            snap.save_snapshot(1, profiles)

            loaded = snap.load_snapshot(1)
            self.assertEqual(loaded["k1"].resource.cpu_percentiles()["p90"], 5.0)
            self.assertEqual(loaded["k1"].resource.mem_percentiles()["p90"], 2048.0)
            self.assertIsNone(
                check_resource_spike("k1", 5.0, 2048, loaded)
            )
            store.close()


if __name__ == "__main__":
    unittest.main()
