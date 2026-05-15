"""Whitelist module – rule model, matching, and safety rails."""

from .rules import (
    RuleScope,
    WhitelistRule,
    MatchResult,
    match_program,
    match_behavior,
)
from .safety import ValidationResult, validate_rule
from .proposals import propose_candidates, approve_rule, WhitelistStore

__all__ = [
    "RuleScope",
    "WhitelistRule",
    "MatchResult",
    "ValidationResult",
    "WhitelistStore",
    "match_program",
    "match_behavior",
    "validate_rule",
    "propose_candidates",
    "approve_rule",
]
