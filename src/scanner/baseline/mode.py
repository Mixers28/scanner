"""Baseline mode state machine.

Manages the learning -> monitor lifecycle.  The mode is persisted in
SQLite so it survives service restarts.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)

_MODE_TABLE_DDL = """
CREATE TABLE IF NOT EXISTS baseline_mode (
    host_id TEXT PRIMARY KEY,
    mode TEXT NOT NULL DEFAULT 'learning',
    learning_start_ts TEXT NOT NULL,
    transition_ts TEXT
)
"""


class BaselineMode(str, Enum):
    LEARNING = "learning"
    MONITOR = "monitor"


class BaselineModeManager:
    """Deterministic state machine for baseline learning -> monitor transition.

    Transition rule:
        If current mode is LEARNING and (now - learning_start) >= learning_window_days
        then transition to MONITOR.

    The mode row is created on first call to ``current_mode`` if it does not
    already exist (cold start).
    """

    def __init__(
        self,
        conn: Any,
        host_id: str,
        learning_window_days: int = 7,
    ) -> None:
        self._conn = conn
        self._host_id = host_id
        self._window = timedelta(days=learning_window_days)
        self._ensure_table()

    # ── public API ─────────────────────────────────────────────────

    def current_mode(self, now: datetime | None = None) -> BaselineMode:
        """Return the current mode, triggering a transition if due."""
        now = now or datetime.now(timezone.utc)
        row = self._load_row()

        if row is None:
            self._insert_row(now)
            return BaselineMode.LEARNING

        mode = BaselineMode(row["mode"])

        if mode == BaselineMode.LEARNING:
            start = datetime.fromisoformat(row["learning_start_ts"])
            if now - start >= self._window:
                self._transition_to_monitor(now)
                return BaselineMode.MONITOR

        return mode

    def force_mode(self, mode: BaselineMode, now: datetime | None = None) -> None:
        """Force a specific mode (useful for testing / admin override)."""
        now = now or datetime.now(timezone.utc)
        row = self._load_row()
        if row is None:
            self._insert_row(now, mode=mode)
        else:
            ts = now.isoformat()
            self._conn.execute(
                "UPDATE baseline_mode SET mode = ?, transition_ts = ? WHERE host_id = ?",
                (mode.value, ts, self._host_id),
            )
            self._conn.commit()

    def reset(self, now: datetime | None = None) -> None:
        """Reset back to learning (e.g. after major config change)."""
        now = now or datetime.now(timezone.utc)
        self._conn.execute("DELETE FROM baseline_mode WHERE host_id = ?", (self._host_id,))
        self._conn.commit()
        self._insert_row(now)

    # ── internals ──────────────────────────────────────────────────

    def _ensure_table(self) -> None:
        self._conn.execute(_MODE_TABLE_DDL)
        self._conn.commit()

    def _load_row(self) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT mode, learning_start_ts, transition_ts FROM baseline_mode WHERE host_id = ?",
            (self._host_id,),
        ).fetchone()
        if row is None:
            return None
        return dict(row)

    def _insert_row(
        self,
        now: datetime,
        mode: BaselineMode = BaselineMode.LEARNING,
    ) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO baseline_mode (host_id, mode, learning_start_ts) VALUES (?, ?, ?)",
            (self._host_id, mode.value, now.isoformat()),
        )
        self._conn.commit()

    def _transition_to_monitor(self, now: datetime) -> None:
        ts = now.isoformat()
        self._conn.execute(
            "UPDATE baseline_mode SET mode = ?, transition_ts = ? WHERE host_id = ?",
            (BaselineMode.MONITOR.value, ts, self._host_id),
        )
        self._conn.commit()
        logger.info("Baseline transitioned to MONITOR for host %s at %s", self._host_id, ts)
