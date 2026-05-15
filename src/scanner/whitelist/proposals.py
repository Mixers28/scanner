"""Candidate whitelist proposal and approval workflow.

Generates candidate allow rules from stable baseline profiles
(high-confidence identities) and manages approval/persistence lifecycle.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from scanner.baseline.stats import IdentityProfile, compute_confidence
from scanner.whitelist.rules import RuleScope, WhitelistRule
from scanner.whitelist.safety import validate_rule

logger = logging.getLogger(__name__)


def propose_candidates(
    profiles: dict[str, IdentityProfile],
    min_confidence: float = 0.8,
    min_samples: int = 30,
) -> list[WhitelistRule]:
    """Generate candidate whitelist rules from high-confidence baseline profiles.

    Only profiles meeting the confidence threshold are eligible.
    Each candidate is a program_allow rule with source='baseline_proposal'.
    Candidates are NOT approved — they require explicit user approval.
    """
    candidates: list[WhitelistRule] = []
    for key, profile in profiles.items():
        confidence = compute_confidence(profile, min_samples)
        if confidence < min_confidence:
            continue

        rule = WhitelistRule(
            scope=RuleScope.PROGRAM_ALLOW,
            identity_key=key,
            image_path_norm=profile.to_dict().get("image_path_norm", ""),
            source="baseline_proposal",
            rationale=f"auto-proposed: confidence={confidence:.2f}, launches={profile.launch_count}",
        )
        candidates.append(rule)
    return candidates


def approve_rule(rule: WhitelistRule, now: datetime | None = None) -> WhitelistRule:
    """Mark a rule as approved (sets approved_ts).

    Returns a new WhitelistRule with the timestamp set.
    """
    now = now or datetime.now(timezone.utc)
    return WhitelistRule(
        entry_id=rule.entry_id,
        scope=rule.scope,
        identity_key=rule.identity_key,
        behavior_type=rule.behavior_type,
        behavior_value=rule.behavior_value,
        expires_ts=rule.expires_ts,
        image_path_norm=rule.image_path_norm,
        signer_publisher=rule.signer_publisher,
        file_hash=rule.file_hash,
        source=rule.source,
        rationale=rule.rationale,
        created_ts=rule.created_ts,
        approved_ts=now.isoformat(),
    )


class WhitelistStore:
    """Persists versioned whitelist rules to SQLite."""

    def __init__(self, conn: Any, host_id: str) -> None:
        self._conn = conn
        self._host_id = host_id

    def save_rules(self, version: int, rules: list[WhitelistRule]) -> int:
        """Persist rules under a version.  Returns row count."""
        rows = 0
        for rule in rules:
            vr = validate_rule(rule)
            if not vr.valid:
                logger.warning("Skipping invalid rule %s: %s", rule.entry_id, vr.errors)
                continue
            self._conn.execute(
                """INSERT OR REPLACE INTO whitelist_entry
                   (entry_id, whitelist_version, host_id, scope, entry_json)
                   VALUES (?, ?, ?, ?, ?)""",
                (rule.entry_id, version, self._host_id, rule.scope.value, json.dumps(rule.to_dict())),
            )
            rows += 1
        self._conn.commit()
        return rows

    def load_rules(self, version: int) -> list[WhitelistRule]:
        """Load all rules for a given version."""
        rows = self._conn.execute(
            "SELECT entry_json FROM whitelist_entry WHERE whitelist_version = ? AND host_id = ?",
            (version, self._host_id),
        ).fetchall()
        return [WhitelistRule.from_dict(json.loads(r["entry_json"])) for r in rows]

    def load_active_rules(self) -> list[WhitelistRule]:
        """Load all approved rules from the latest version."""
        latest = self.latest_version()
        if latest is None:
            return []
        rules = self.load_rules(latest)
        return [r for r in rules if r.approved_ts]

    def latest_version(self) -> int | None:
        row = self._conn.execute(
            "SELECT MAX(whitelist_version) AS v FROM whitelist_entry WHERE host_id = ?",
            (self._host_id,),
        ).fetchone()
        if row is None or row["v"] is None:
            return None
        return int(row["v"])

    def list_versions(self) -> list[int]:
        rows = self._conn.execute(
            "SELECT DISTINCT whitelist_version FROM whitelist_entry WHERE host_id = ? ORDER BY whitelist_version ASC",
            (self._host_id,),
        ).fetchall()
        return [int(r["whitelist_version"]) for r in rows]

    def prune_old_versions(self, keep: int = 50) -> int:
        versions = self.list_versions()
        if len(versions) <= keep:
            return 0
        to_delete = versions[: len(versions) - keep]
        total = 0
        for v in to_delete:
            cur = self._conn.execute(
                "DELETE FROM whitelist_entry WHERE whitelist_version = ? AND host_id = ?",
                (v, self._host_id),
            )
            total += cur.rowcount
        self._conn.commit()
        return total
