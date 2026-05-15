"""Hub push client — queues incidents to a SQLite outbox and flushes to the hub.

Design:
  - Service thread writes to outbox via the service's existing SQLite connection.
  - Push thread opens its own connection, reads outbox, POSTs to hub, deletes on success.
  - On hub unreachable: increments attempt count and backs off; retries every 30s.
  - No external dependencies — uses stdlib urllib.request.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_FLUSH_INTERVAL = 30        # seconds between flush attempts
_BATCH_SIZE = 20            # max items per flush pass
_MAX_ATTEMPTS = 48          # drop after ~24h of failures (48 × 30s)


class HubPushClient:
    """Pushes incidents to the central hub with a durable outbox."""

    def __init__(self, hub_url: str, api_key: str, db_path: Path) -> None:
        self._hub_url = hub_url.rstrip("/")
        self._api_key = api_key
        self._db_path = db_path
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    # ── lifecycle ──────────────────────────────────────────────────

    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._flush_loop, daemon=True, name="scanner-push",
        )
        self._thread.start()
        logger.info("Hub push client started (hub=%s)", self._hub_url)

    def stop(self) -> None:
        self._stop_event.set()

    # ── enqueue (called from service thread) ──────────────────────

    def queue_incident(self, conn: Any, incident_data: dict) -> None:
        """Insert an incident into the outbox using the caller's connection."""
        _ensure_outbox(conn)
        conn.execute(
            "INSERT INTO outbox (event_type, payload_json, created_ts)"
            " VALUES (?, ?, ?)",
            ("incident", json.dumps(incident_data),
             datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()

    # ── flush loop (push thread) ───────────────────────────────────

    def _flush_loop(self) -> None:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        _ensure_outbox(conn)

        while not self._stop_event.is_set():
            try:
                self._flush(conn)
            except Exception:
                logger.exception("Push flush error")
            self._stop_event.wait(_FLUSH_INTERVAL)

        conn.close()

    def _flush(self, conn: sqlite3.Connection) -> None:
        rows = conn.execute(
            "SELECT id, event_type, payload_json FROM outbox"
            " WHERE attempts < ? ORDER BY id ASC LIMIT ?",
            (_MAX_ATTEMPTS, _BATCH_SIZE),
        ).fetchall()

        for row in rows:
            success = self._post(row["event_type"], json.loads(row["payload_json"]))
            if success:
                conn.execute("DELETE FROM outbox WHERE id = ?", (row["id"],))
            else:
                conn.execute(
                    "UPDATE outbox SET attempts = attempts + 1, last_attempt_ts = ?"
                    " WHERE id = ?",
                    (datetime.now(timezone.utc).isoformat(), row["id"]),
                )
                conn.commit()
                break  # back off; try again next interval
        conn.commit()

    def _post(self, event_type: str, payload: dict) -> bool:
        url = f"{self._hub_url}/api/v1/{event_type}s"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("X-API-Key", self._api_key)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return 200 <= resp.status < 300
        except urllib.error.HTTPError as exc:
            logger.warning("Hub push HTTP %s for %s", exc.code, url)
        except Exception as exc:
            logger.debug("Hub push failed (%s): %s", url, exc)
        return False


# ── outbox schema (migration applied lazily) ──────────────────────

_OUTBOX_DDL = """
CREATE TABLE IF NOT EXISTS outbox (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type       TEXT NOT NULL,
    payload_json     TEXT NOT NULL,
    created_ts       TEXT NOT NULL,
    attempts         INTEGER NOT NULL DEFAULT 0,
    last_attempt_ts  TEXT
);
"""


def _ensure_outbox(conn: Any) -> None:
    conn.execute(_OUTBOX_DDL)
    conn.commit()
