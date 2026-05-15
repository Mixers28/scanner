"""SQLite bootstrap and migration support for Scanner."""

from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any, Iterable, TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.common.types import TelemetryEvent
    from scanner.verify.adapters import VerificationResult

_MIGRATIONS: list[tuple[int, str]] = [
    (
        1,
        """
        CREATE TABLE IF NOT EXISTS telemetry_event (
            event_id TEXT PRIMARY KEY,
            host_id TEXT NOT NULL,
            ts TEXT NOT NULL,
            event_type TEXT NOT NULL,
            payload_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS baseline_profile (
            baseline_version INTEGER NOT NULL,
            host_id TEXT NOT NULL,
            identity_key TEXT NOT NULL,
            confidence REAL NOT NULL DEFAULT 0,
            profile_json TEXT NOT NULL,
            PRIMARY KEY (baseline_version, host_id, identity_key)
        );

        CREATE TABLE IF NOT EXISTS whitelist_entry (
            entry_id TEXT PRIMARY KEY,
            whitelist_version INTEGER NOT NULL,
            host_id TEXT NOT NULL,
            scope TEXT NOT NULL,
            entry_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS incident (
            incident_id TEXT PRIMARY KEY,
            host_id TEXT NOT NULL,
            created_ts TEXT NOT NULL,
            updated_ts TEXT NOT NULL,
            severity TEXT NOT NULL,
            score INTEGER NOT NULL,
            incident_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS verification_result (
            result_id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            adapter_name TEXT NOT NULL,
            ts TEXT NOT NULL,
            verdict TEXT NOT NULL,
            evidence_json TEXT NOT NULL
        );
        """,
    ),
    (
        2,
        """
        -- Add pid column for existing databases created with migration 1.
        -- SQLite ALTER TABLE ADD COLUMN is idempotent-safe with IF NOT EXISTS
        -- not supported, so we use a pragma check approach.
        -- For simplicity: if the column already exists the statement is a no-op
        -- because migration 1 already includes it in fresh DBs.
        ALTER TABLE telemetry_event ADD COLUMN pid INTEGER NOT NULL DEFAULT 0;
        """,
    ),
    (
        3,
        """
        CREATE TABLE IF NOT EXISTS scanner_status (
            status_id INTEGER PRIMARY KEY CHECK (status_id = 1),
            host_id TEXT NOT NULL DEFAULT '',
            running INTEGER NOT NULL DEFAULT 0,
            started_ts TEXT NOT NULL DEFAULT '',
            updated_ts TEXT NOT NULL DEFAULT '',
            mode TEXT NOT NULL DEFAULT 'unknown',
            cycle_count INTEGER NOT NULL DEFAULT 0,
            total_events INTEGER NOT NULL DEFAULT 0,
            total_incidents INTEGER NOT NULL DEFAULT 0,
            rate_limiter_dropped INTEGER NOT NULL DEFAULT 0
        );
        """,
    ),
    (
        4,
        """
        ALTER TABLE verification_result ADD COLUMN duration_ms INTEGER NOT NULL DEFAULT 0;
        """,
    ),
]


class SQLiteStorage:
    """Thin SQLite bootstrap wrapper with deterministic migrations."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self._conn: sqlite3.Connection | None = None

    @property
    def connection(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("SQLiteStorage is not initialized")
        return self._conn

    def initialize(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._ensure_migrations_table()
        self._apply_pending_migrations(_MIGRATIONS)
        self._conn.commit()

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def get_applied_versions(self) -> list[int]:
        rows = self.connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version ASC"
        ).fetchall()
        return [int(row["version"]) for row in rows]

    def _ensure_migrations_table(self) -> None:
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_ts TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )

    def _apply_pending_migrations(self, migrations: Iterable[tuple[int, str]]) -> None:
        applied = set(self.get_applied_versions())
        for version, sql in migrations:
            if version in applied:
                continue
            self.connection.executescript(sql)
            self.connection.execute(
                "INSERT INTO schema_migrations (version) VALUES (?)",
                (version,),
            )

    # ── Telemetry persistence ──────────────────────────────────────

    def persist_events(self, events: Iterable[TelemetryEvent]) -> int:
        """Insert telemetry events. Returns count of rows inserted."""
        from scanner.common.types import TelemetryEvent

        rows = 0
        for ev in events:
            self.connection.execute(
                """INSERT OR IGNORE INTO telemetry_event
                   (event_id, host_id, ts, event_type, pid, payload_json)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    ev.event_id,
                    ev.host_id,
                    ev.ts,
                    ev.event_type,
                    ev.pid,
                    json.dumps(ev.payload),
                ),
            )
            rows += 1
        self.connection.commit()
        return rows

    def query_events(
        self,
        event_type: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Query telemetry events, optionally filtered by event_type."""
        if event_type:
            rows = self.connection.execute(
                "SELECT * FROM telemetry_event WHERE event_type = ? ORDER BY ts DESC LIMIT ?",
                (event_type, limit),
            ).fetchall()
        else:
            rows = self.connection.execute(
                "SELECT * FROM telemetry_event ORDER BY ts DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def persist_verification_results(
        self,
        incident_id: str,
        results: Iterable[VerificationResult],
    ) -> int:
        """Persist verification results for an incident."""
        rows = 0
        for result in results:
            self.connection.execute(
                """INSERT INTO verification_result
                   (result_id, incident_id, adapter_name, ts, verdict, evidence_json, duration_ms)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    uuid.uuid4().hex,
                    incident_id,
                    result.adapter_name,
                    result.timestamp,
                    result.verdict.value,
                    json.dumps(result.evidence),
                    result.duration_ms,
                ),
            )
            rows += 1
        self.connection.commit()
        return rows

    def persist_status(self, status: dict[str, Any]) -> None:
        """Persist the latest scanner runtime status snapshot."""
        self.connection.execute(
            """INSERT OR REPLACE INTO scanner_status
               (status_id, host_id, running, started_ts, updated_ts, mode,
                cycle_count, total_events, total_incidents, rate_limiter_dropped)
               VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                status.get("host_id", ""),
                1 if status.get("running") else 0,
                status.get("started_ts", ""),
                status.get("updated_ts", ""),
                status.get("mode", "unknown"),
                status.get("cycle_count", 0),
                status.get("total_events", 0),
                status.get("total_incidents", 0),
                status.get("rate_limiter_dropped", 0),
            ),
        )
        self.connection.commit()

    def load_status(self) -> dict[str, Any] | None:
        """Load the latest persisted scanner runtime status snapshot."""
        row = self.connection.execute(
            "SELECT * FROM scanner_status WHERE status_id = 1"
        ).fetchone()
        if row is None:
            return None
        data = dict(row)
        data["running"] = bool(data["running"])
        data.pop("status_id", None)
        return data
