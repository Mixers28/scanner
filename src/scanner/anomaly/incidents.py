"""Incident lifecycle – creation, deduplication, cooldown, and updates.

An incident signature is derived from (host_id, identity_key, signal_codes)
so repeated occurrences of the same anomaly pattern map to the same incident.
Cooldown suppresses re-alerting within a configurable window (default 30 min).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from scanner.anomaly.scoring import ScoringResult
from scanner.common.types import IncidentState, Severity


@dataclass
class Incident:
    incident_id: str = ""
    host_id: str = ""
    identity_key: str = ""
    signature: str = ""
    severity: Severity = Severity.INFO
    score: int = 0
    state: IncidentState = IncidentState.OPEN
    signals: list[dict[str, Any]] = field(default_factory=list)
    created_ts: str = ""
    updated_ts: str = ""
    occurrence_count: int = 1

    def __post_init__(self) -> None:
        if not self.incident_id:
            self.incident_id = uuid.uuid4().hex
        now = datetime.now(timezone.utc).isoformat()
        if not self.created_ts:
            self.created_ts = now
        if not self.updated_ts:
            self.updated_ts = now

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "host_id": self.host_id,
            "identity_key": self.identity_key,
            "signature": self.signature,
            "severity": self.severity.value,
            "score": self.score,
            "state": self.state.value,
            "signals": self.signals,
            "created_ts": self.created_ts,
            "updated_ts": self.updated_ts,
            "occurrence_count": self.occurrence_count,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Incident:
        return cls(
            incident_id=data.get("incident_id", ""),
            host_id=data.get("host_id", ""),
            identity_key=data.get("identity_key", ""),
            signature=data.get("signature", ""),
            severity=Severity(data.get("severity", "info")),
            score=data.get("score", 0),
            state=IncidentState(data.get("state", "open")),
            signals=data.get("signals", []),
            created_ts=data.get("created_ts", ""),
            updated_ts=data.get("updated_ts", ""),
            occurrence_count=data.get("occurrence_count", 1),
        )


def build_incident_signature(
    host_id: str,
    identity_key: str,
    signal_codes: list[str],
) -> str:
    """Deterministic signature for deduplication."""
    sorted_codes = sorted(set(signal_codes))
    payload = f"{host_id}|{identity_key}|{','.join(sorted_codes)}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


class IncidentManager:
    """Manages incident creation, deduplication, and cooldown.

    Operates against the SQLite incident table.
    """

    def __init__(
        self,
        conn: Any,
        host_id: str,
        cooldown_minutes: int = 30,
    ) -> None:
        self._conn = conn
        self._host_id = host_id
        self._cooldown = timedelta(minutes=cooldown_minutes)

    def process_scoring(
        self,
        identity_key: str,
        scoring: ScoringResult,
        now: datetime | None = None,
    ) -> Incident | None:
        """Create or update an incident from a scoring result.

        Returns the Incident if it was created or updated, or None if
        suppressed by cooldown.
        """
        now = now or datetime.now(timezone.utc)
        if scoring.score == 0 and not scoring.hard_flag:
            return None

        signal_codes = [s.code for s in scoring.signals]
        signature = build_incident_signature(self._host_id, identity_key, signal_codes)

        existing = self._find_by_signature(signature)

        if existing is not None:
            last_update = datetime.fromisoformat(existing.updated_ts)
            if now - last_update < self._cooldown:
                return None  # suppressed
            return self._update_incident(existing, scoring, now)

        return self._create_incident(identity_key, signature, scoring, now)

    def _find_by_signature(self, signature: str) -> Incident | None:
        row = self._conn.execute(
            "SELECT incident_json FROM incident WHERE host_id = ? AND incident_id IN "
            "(SELECT incident_id FROM incident WHERE host_id = ?)"
            " AND incident_json LIKE ?",
            (self._host_id, self._host_id, f'%"signature": "{signature}"%'),
        ).fetchone()

        # Simpler approach: scan by host and check signature in JSON
        rows = self._conn.execute(
            "SELECT incident_json FROM incident WHERE host_id = ? ORDER BY updated_ts DESC",
            (self._host_id,),
        ).fetchall()
        for r in rows:
            data = json.loads(r["incident_json"])
            if data.get("signature") == signature:
                return Incident.from_dict(data)
        return None

    def _create_incident(
        self,
        identity_key: str,
        signature: str,
        scoring: ScoringResult,
        now: datetime,
    ) -> Incident:
        ts = now.isoformat()
        incident = Incident(
            host_id=self._host_id,
            identity_key=identity_key,
            signature=signature,
            severity=scoring.severity,
            score=scoring.score,
            signals=[{"code": s.code, "points": s.points, "description": s.description} for s in scoring.signals],
            created_ts=ts,
            updated_ts=ts,
        )
        self._conn.execute(
            """INSERT INTO incident
               (incident_id, host_id, created_ts, updated_ts, severity, score, incident_json)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (incident.incident_id, self._host_id, ts, ts,
             incident.severity.value, incident.score, json.dumps(incident.to_dict())),
        )
        self._conn.commit()
        return incident

    def _update_incident(
        self,
        existing: Incident,
        scoring: ScoringResult,
        now: datetime,
    ) -> Incident:
        ts = now.isoformat()
        existing.updated_ts = ts
        existing.occurrence_count += 1
        # Escalate severity if new score is higher
        if scoring.score > existing.score:
            existing.score = scoring.score
            existing.severity = scoring.severity
        if scoring.hard_flag:
            existing.severity = Severity.CRITICAL

        self._conn.execute(
            """UPDATE incident SET updated_ts = ?, severity = ?, score = ?, incident_json = ?
               WHERE incident_id = ? AND host_id = ?""",
            (ts, existing.severity.value, existing.score,
             json.dumps(existing.to_dict()), existing.incident_id, self._host_id),
        )
        self._conn.commit()
        return existing

    def get_open_incidents(self) -> list[Incident]:
        rows = self._conn.execute(
            "SELECT incident_json FROM incident WHERE host_id = ? ORDER BY updated_ts DESC",
            (self._host_id,),
        ).fetchall()
        incidents = []
        for r in rows:
            inc = Incident.from_dict(json.loads(r["incident_json"]))
            if inc.state == IncidentState.OPEN:
                incidents.append(inc)
        return incidents
