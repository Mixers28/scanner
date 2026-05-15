"""Hub storage — one SQLite per agent host under a data directory."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS incident (
    incident_id  TEXT PRIMARY KEY,
    host_id      TEXT NOT NULL,
    severity     TEXT NOT NULL,
    score        INTEGER NOT NULL,
    created_ts   TEXT NOT NULL,
    updated_ts   TEXT NOT NULL,
    incident_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS host_meta (
    host_id      TEXT PRIMARY KEY,
    last_seen_ts TEXT NOT NULL,
    mode         TEXT NOT NULL DEFAULT 'unknown'
);
"""


class HubStore:
    """Manages one SQLite database per agent host."""

    def __init__(self, data_dir: str | Path) -> None:
        self._data_dir = Path(data_dir)
        self._data_dir.mkdir(parents=True, exist_ok=True)

    # ── write ──────────────────────────────────────────────────────

    def put_incident(self, host_id: str, incident_data: dict[str, Any]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._conn(host_id) as conn:
            conn.execute(
                """INSERT OR REPLACE INTO incident
                   (incident_id, host_id, severity, score,
                    created_ts, updated_ts, incident_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    incident_data["incident_id"],
                    host_id,
                    incident_data.get("severity", "info"),
                    incident_data.get("score", 0),
                    incident_data.get("created_ts", now),
                    incident_data.get("updated_ts", now),
                    json.dumps(incident_data),
                ),
            )
            conn.execute(
                "INSERT OR REPLACE INTO host_meta (host_id, last_seen_ts, mode)"
                " VALUES (?, ?, ?)",
                (host_id, now, incident_data.get("mode", "monitor")),
            )

    # ── read ───────────────────────────────────────────────────────

    def list_hosts(self) -> list[dict[str, Any]]:
        hosts = []
        for db_file in sorted(self._data_dir.glob("*.db")):
            host_id = db_file.stem
            with self._conn(host_id) as conn:
                meta = conn.execute(
                    "SELECT last_seen_ts, mode FROM host_meta WHERE host_id = ?",
                    (host_id,),
                ).fetchone()
                count = conn.execute(
                    "SELECT COUNT(*) FROM incident"
                ).fetchone()[0]
            hosts.append({
                "host_id": host_id,
                "last_seen_ts": meta["last_seen_ts"] if meta else "",
                "mode": meta["mode"] if meta else "unknown",
                "incident_count": count,
            })
        return hosts

    def list_incidents(
        self,
        host_id: str,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        db_file = self._data_dir / f"{host_id}.db"
        if not db_file.exists():
            return []
        with self._conn(host_id) as conn:
            rows = conn.execute(
                "SELECT incident_json FROM incident"
                " ORDER BY updated_ts DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [json.loads(r["incident_json"]) for r in rows]

    # ── internal ───────────────────────────────────────────────────

    def _conn(self, host_id: str) -> sqlite3.Connection:
        db_path = self._data_dir / f"{host_id}.db"
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        conn.executescript(_SCHEMA)
        conn.commit()
        return conn
