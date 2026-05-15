"""Event rate limiter and retention cleanup for telemetry.

Enforces max_events_per_minute cap (drops excess events) and provides
a retention cleanup hook that deletes telemetry older than the configured
retention window.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Sequence

from scanner.common.types import TelemetryEvent

logger = logging.getLogger(__name__)


class EventRateLimiter:
    """Sliding-window rate limiter for telemetry events."""

    def __init__(self, max_events_per_minute: int) -> None:
        self.max_per_minute = max_events_per_minute
        self._timestamps: list[float] = []
        self._dropped: int = 0

    def _prune(self, now: float) -> None:
        cutoff = now - 60.0
        self._timestamps = [t for t in self._timestamps if t > cutoff]

    def accept(self, event: TelemetryEvent) -> bool:
        """Return True if the event is within the rate cap, False to drop."""
        now = time.monotonic()
        self._prune(now)
        if len(self._timestamps) >= self.max_per_minute:
            self._dropped += 1
            if self._dropped % 100 == 1:
                logger.warning(
                    "Rate limiter dropping events (total dropped=%d, cap=%d/min)",
                    self._dropped, self.max_per_minute,
                )
            return False
        self._timestamps.append(now)
        return True

    def filter(self, events: Sequence[TelemetryEvent]) -> list[TelemetryEvent]:
        """Filter a batch of events through the rate limiter."""
        return [ev for ev in events if self.accept(ev)]

    @property
    def total_dropped(self) -> int:
        return self._dropped


def cleanup_old_telemetry(
    conn: Any,
    retention_days: int,
) -> int:
    """Delete telemetry_event rows older than retention_days.

    Returns number of rows deleted.
    """
    cursor = conn.execute(
        """DELETE FROM telemetry_event
           WHERE ts < datetime('now', ? || ' days')""",
        (f"-{retention_days}",),
    )
    conn.commit()
    return cursor.rowcount
