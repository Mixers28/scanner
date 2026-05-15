"""Whitelist rule model and matching engine.

Rule scopes (per SPEC §4.2 / §5.3):
  - program_allow:   allow all behavior from a specific identity key.
  - behavior_allow:  allow a specific behavior (e.g. network dest) for an identity key.
  - temporary_allow: time-bounded program_allow that expires after a deadline.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class RuleScope(str, Enum):
    PROGRAM_ALLOW = "program_allow"
    BEHAVIOR_ALLOW = "behavior_allow"
    TEMPORARY_ALLOW = "temporary_allow"


@dataclass
class WhitelistRule:
    """A single whitelist rule."""
    entry_id: str = ""
    scope: RuleScope = RuleScope.PROGRAM_ALLOW
    identity_key: str = ""
    # For behavior_allow: the specific behavior being allowed
    behavior_type: str = ""        # e.g. "network_dest", "parent_chain"
    behavior_value: str = ""       # e.g. "8.8.8.8:53"
    # For temporary_allow: expiry deadline (ISO 8601)
    expires_ts: str = ""
    # Metadata
    image_path_norm: str = ""
    signer_publisher: str = ""
    file_hash: str = ""
    source: str = ""               # "baseline_proposal" | "user_manual" | ...
    rationale: str = ""
    created_ts: str = ""
    approved_ts: str = ""

    def __post_init__(self) -> None:
        if not self.entry_id:
            self.entry_id = uuid.uuid4().hex
        if not self.created_ts:
            self.created_ts = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "scope": self.scope.value,
            "identity_key": self.identity_key,
            "behavior_type": self.behavior_type,
            "behavior_value": self.behavior_value,
            "expires_ts": self.expires_ts,
            "image_path_norm": self.image_path_norm,
            "signer_publisher": self.signer_publisher,
            "file_hash": self.file_hash,
            "source": self.source,
            "rationale": self.rationale,
            "created_ts": self.created_ts,
            "approved_ts": self.approved_ts,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WhitelistRule:
        return cls(
            entry_id=data.get("entry_id", ""),
            scope=RuleScope(data["scope"]),
            identity_key=data.get("identity_key", ""),
            behavior_type=data.get("behavior_type", ""),
            behavior_value=data.get("behavior_value", ""),
            expires_ts=data.get("expires_ts", ""),
            image_path_norm=data.get("image_path_norm", ""),
            signer_publisher=data.get("signer_publisher", ""),
            file_hash=data.get("file_hash", ""),
            source=data.get("source", ""),
            rationale=data.get("rationale", ""),
            created_ts=data.get("created_ts", ""),
            approved_ts=data.get("approved_ts", ""),
        )


@dataclass
class MatchResult:
    """Outcome of matching a process/behavior against the whitelist."""
    matched: bool
    rule: WhitelistRule | None = None
    reason: str = ""


def _is_expired(rule: WhitelistRule, now: datetime) -> bool:
    if not rule.expires_ts:
        return False
    try:
        expires = datetime.fromisoformat(rule.expires_ts)
        return now >= expires
    except (ValueError, TypeError):
        return False


def match_program(
    identity_key: str,
    rules: list[WhitelistRule],
    now: datetime | None = None,
) -> MatchResult:
    """Check if a process identity key is allowed by any program-level rule.

    Checks program_allow and temporary_allow (if not expired).
    """
    now = now or datetime.now(timezone.utc)

    for rule in rules:
        if rule.identity_key != identity_key:
            continue

        if rule.scope == RuleScope.PROGRAM_ALLOW:
            return MatchResult(
                matched=True, rule=rule,
                reason=f"program_allow: {rule.rationale or rule.entry_id}",
            )

        if rule.scope == RuleScope.TEMPORARY_ALLOW:
            if _is_expired(rule, now):
                continue
            return MatchResult(
                matched=True, rule=rule,
                reason=f"temporary_allow (expires {rule.expires_ts}): {rule.rationale or rule.entry_id}",
            )

    return MatchResult(matched=False, reason="no matching program rule")


def match_behavior(
    identity_key: str,
    behavior_type: str,
    behavior_value: str,
    rules: list[WhitelistRule],
    now: datetime | None = None,
) -> MatchResult:
    """Check if a specific behavior is allowed for a process.

    First checks program-level allow (which covers all behaviors),
    then checks behavior-specific rules.
    """
    now = now or datetime.now(timezone.utc)

    # A program-level allow covers all behaviors
    prog_match = match_program(identity_key, rules, now)
    if prog_match.matched:
        return prog_match

    for rule in rules:
        if rule.scope != RuleScope.BEHAVIOR_ALLOW:
            continue
        if rule.identity_key != identity_key:
            continue
        if rule.behavior_type != behavior_type:
            continue
        if rule.behavior_value != behavior_value:
            continue
        return MatchResult(
            matched=True, rule=rule,
            reason=f"behavior_allow ({behavior_type}={behavior_value}): {rule.rationale or rule.entry_id}",
        )

    return MatchResult(matched=False, reason=f"no matching rule for {behavior_type}={behavior_value}")
