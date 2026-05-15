"""Anomaly score aggregation and severity mapping.

SPEC §5.4 severity bands:
  - info:     score 1–2
  - warning:  score 3–5
  - critical: score ≥ 6  OR  hard-flag condition met
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from scanner.anomaly.signals import Signal, check_hard_escalation
from scanner.common.types import Severity


@dataclass
class ScoringResult:
    score: int
    severity: Severity
    signals: list[Signal]
    hard_flag: bool


def compute_score(signals: list[Signal]) -> int:
    """Sum signal points."""
    return sum(s.points for s in signals)


def map_severity(score: int, hard_flag: bool = False) -> Severity:
    """Map aggregate score to severity per SPEC thresholds."""
    if hard_flag or score >= 6:
        return Severity.CRITICAL
    if score >= 3:
        return Severity.WARNING
    if score >= 1:
        return Severity.INFO
    # score 0 shouldn't normally reach here, but default to INFO
    return Severity.INFO


def score_signals(
    signals: list[Signal],
    payload: dict[str, Any],
) -> ScoringResult:
    """Aggregate signals into a final score and severity.

    Checks the hard-escalation condition from the payload fields.
    """
    score = compute_score(signals)
    hard_flag = check_hard_escalation(
        signer_publisher=payload.get("signer_publisher", "unknown"),
        image_path_norm=payload.get("image_path_norm", ""),
        has_outbound_network=bool(payload.get("remote_ip")),
    )
    severity = map_severity(score, hard_flag)

    return ScoringResult(
        score=score,
        severity=severity,
        signals=signals,
        hard_flag=hard_flag,
    )
