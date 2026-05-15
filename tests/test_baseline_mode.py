"""Tests for S2-T1: Baseline learning/monitor mode state machine."""

import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scanner.baseline.mode import BaselineMode, BaselineModeManager
from scanner.storage import SQLiteStorage


class BaselineModeManagerTests(unittest.TestCase):
    def _make_manager(self, tmpdir: str, window_days: int = 7) -> tuple:
        store = SQLiteStorage(Path(tmpdir) / "test.db")
        store.initialize()
        mgr = BaselineModeManager(store.connection, "host-1", window_days)
        return store, mgr

    def test_cold_start_is_learning(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, mgr = self._make_manager(tmpdir)
            mode = mgr.current_mode()
            self.assertEqual(mode, BaselineMode.LEARNING)
            store.close()

    def test_stays_learning_within_window(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, mgr = self._make_manager(tmpdir, window_days=7)
            start = datetime(2026, 1, 1, tzinfo=timezone.utc)
            mgr.current_mode(now=start)  # seed

            within = start + timedelta(days=6, hours=23)
            mode = mgr.current_mode(now=within)
            self.assertEqual(mode, BaselineMode.LEARNING)
            store.close()

    def test_transitions_to_monitor_after_window(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, mgr = self._make_manager(tmpdir, window_days=7)
            start = datetime(2026, 1, 1, tzinfo=timezone.utc)
            mgr.current_mode(now=start)

            after = start + timedelta(days=7)
            mode = mgr.current_mode(now=after)
            self.assertEqual(mode, BaselineMode.MONITOR)
            store.close()

    def test_stays_monitor_after_transition(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, mgr = self._make_manager(tmpdir, window_days=1)
            start = datetime(2026, 1, 1, tzinfo=timezone.utc)
            mgr.current_mode(now=start)
            mgr.current_mode(now=start + timedelta(days=2))  # triggers transition

            much_later = start + timedelta(days=100)
            mode = mgr.current_mode(now=much_later)
            self.assertEqual(mode, BaselineMode.MONITOR)
            store.close()

    def test_survives_restart(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            start = datetime(2026, 1, 1, tzinfo=timezone.utc)

            # Session 1: seed learning
            store1 = SQLiteStorage(db_path)
            store1.initialize()
            mgr1 = BaselineModeManager(store1.connection, "host-1", 7)
            mgr1.current_mode(now=start)
            store1.close()

            # Session 2: reopen after window
            store2 = SQLiteStorage(db_path)
            store2.initialize()
            mgr2 = BaselineModeManager(store2.connection, "host-1", 7)
            mode = mgr2.current_mode(now=start + timedelta(days=8))
            self.assertEqual(mode, BaselineMode.MONITOR)
            store2.close()

    def test_reset_returns_to_learning(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, mgr = self._make_manager(tmpdir, window_days=1)
            start = datetime(2026, 1, 1, tzinfo=timezone.utc)
            mgr.current_mode(now=start)
            mgr.current_mode(now=start + timedelta(days=2))
            self.assertEqual(mgr.current_mode(now=start + timedelta(days=2)), BaselineMode.MONITOR)

            mgr.reset(now=start + timedelta(days=3))
            mode = mgr.current_mode(now=start + timedelta(days=3))
            self.assertEqual(mode, BaselineMode.LEARNING)
            store.close()

    def test_force_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, mgr = self._make_manager(tmpdir)
            now = datetime(2026, 1, 1, tzinfo=timezone.utc)
            mgr.current_mode(now=now)  # seed as learning

            mgr.force_mode(BaselineMode.MONITOR, now=now)
            self.assertEqual(mgr.current_mode(now=now), BaselineMode.MONITOR)
            store.close()

    def test_configurable_window(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, mgr = self._make_manager(tmpdir, window_days=1)
            start = datetime(2026, 1, 1, tzinfo=timezone.utc)
            mgr.current_mode(now=start)

            mode = mgr.current_mode(now=start + timedelta(days=1))
            self.assertEqual(mode, BaselineMode.MONITOR)
            store.close()


if __name__ == "__main__":
    unittest.main()
