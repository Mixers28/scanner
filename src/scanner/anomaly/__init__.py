"""Anomaly detection – signal calculation, scoring, and incident lifecycle."""

from .signals import (
    Signal,
    check_new_identity,
    check_unsigned_writable,
    check_unusual_parent,
    check_new_network_dest,
    check_resource_spike,
    check_burst_launch,
    check_hard_escalation,
    evaluate_signals,
)
from .scoring import ScoringResult, compute_score, map_severity, score_signals
from .incidents import Incident, IncidentManager, build_incident_signature

__all__ = [
    "Signal",
    "ScoringResult",
    "Incident",
    "IncidentManager",
    "build_incident_signature",
    "check_new_identity",
    "check_unsigned_writable",
    "check_unusual_parent",
    "check_new_network_dest",
    "check_resource_spike",
    "check_burst_launch",
    "check_hard_escalation",
    "evaluate_signals",
    "compute_score",
    "map_severity",
    "score_signals",
]
