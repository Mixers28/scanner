"""Versioned baseline snapshot persistence.

Persists and loads aggregated IdentityProfile sets as versioned snapshots
in the baseline_profile table.  Supports version pruning to keep only the
N most recent versions per host.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from scanner.baseline.stats import IdentityProfile, compute_confidence

logger = logging.getLogger(__name__)


class BaselineSnapshotStore:
    """Read/write versioned baseline snapshots to SQLite."""

    def __init__(self, conn: Any, host_id: str) -> None:
        self._conn = conn
        self._host_id = host_id

    # ── write ──────────────────────────────────────────────────────

    def save_snapshot(
        self,
        version: int,
        profiles: dict[str, IdentityProfile],
        min_confidence_samples: int = 30,
    ) -> int:
        """Persist all profiles under the given version.  Returns row count."""
        rows = 0
        for key, profile in profiles.items():
            confidence = compute_confidence(profile, min_confidence_samples)
            profile_json = json.dumps(profile.to_dict())
            self._conn.execute(
                """INSERT OR REPLACE INTO baseline_profile
                   (baseline_version, host_id, identity_key, confidence, profile_json)
                   VALUES (?, ?, ?, ?, ?)""",
                (version, self._host_id, key, confidence, profile_json),
            )
            rows += 1
        self._conn.commit()
        return rows

    # ── read ───────────────────────────────────────────────────────

    def load_snapshot(self, version: int) -> dict[str, IdentityProfile]:
        """Load all profiles for a given version.  Returns {identity_key: profile}."""
        rows = self._conn.execute(
            "SELECT identity_key, profile_json FROM baseline_profile WHERE baseline_version = ? AND host_id = ?",
            (version, self._host_id),
        ).fetchall()
        profiles: dict[str, IdentityProfile] = {}
        for row in rows:
            data = json.loads(row["profile_json"])
            profiles[row["identity_key"]] = IdentityProfile.from_dict(data)
        return profiles

    def latest_version(self) -> int | None:
        """Return the highest version number for this host, or None."""
        row = self._conn.execute(
            "SELECT MAX(baseline_version) AS v FROM baseline_profile WHERE host_id = ?",
            (self._host_id,),
        ).fetchone()
        if row is None or row["v"] is None:
            return None
        return int(row["v"])

    def list_versions(self) -> list[int]:
        """Return all snapshot versions for this host, ascending."""
        rows = self._conn.execute(
            "SELECT DISTINCT baseline_version FROM baseline_profile WHERE host_id = ? ORDER BY baseline_version ASC",
            (self._host_id,),
        ).fetchall()
        return [int(r["baseline_version"]) for r in rows]

    # ── pruning ────────────────────────────────────────────────────

    def prune_old_versions(self, keep: int = 10) -> int:
        """Delete all but the most recent `keep` versions.  Returns deleted row count."""
        versions = self.list_versions()
        if len(versions) <= keep:
            return 0
        to_delete = versions[: len(versions) - keep]
        total = 0
        for v in to_delete:
            cur = self._conn.execute(
                "DELETE FROM baseline_profile WHERE baseline_version = ? AND host_id = ?",
                (v, self._host_id),
            )
            total += cur.rowcount
        self._conn.commit()
        return total
