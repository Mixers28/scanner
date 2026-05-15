import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scanner.storage import SQLiteStorage


class StorageBootstrapTests(unittest.TestCase):
    def test_initialize_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "scanner.db"

            store = SQLiteStorage(db_path)
            store.initialize()
            self.assertEqual([1, 2, 3, 4], store.get_applied_versions())
            store.close()

            store2 = SQLiteStorage(db_path)
            store2.initialize()
            self.assertEqual([1, 2, 3, 4], store2.get_applied_versions())
            store2.close()

    def test_core_tables_exist(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "scanner.db"
            store = SQLiteStorage(db_path)
            store.initialize()
            store.close()

            conn = sqlite3.connect(db_path)
            try:
                tables = {
                    row[0]
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()
                }
            finally:
                conn.close()

            expected = {
                "schema_migrations",
                "telemetry_event",
                "baseline_profile",
                "whitelist_entry",
                "incident",
                "verification_result",
                "scanner_status",
            }
            self.assertTrue(expected.issubset(tables))


if __name__ == "__main__":
    unittest.main()
