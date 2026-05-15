"""Tests for S3-T1: Whitelist rule model and matching engine."""

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scanner.whitelist.rules import (
    RuleScope,
    WhitelistRule,
    MatchResult,
    match_program,
    match_behavior,
)


class WhitelistRuleTests(unittest.TestCase):
    def test_defaults(self) -> None:
        r = WhitelistRule(identity_key="k1")
        self.assertEqual(len(r.entry_id), 32)  # uuid hex
        self.assertIn("T", r.created_ts)
        self.assertEqual(r.scope, RuleScope.PROGRAM_ALLOW)

    def test_roundtrip_dict(self) -> None:
        r = WhitelistRule(
            scope=RuleScope.BEHAVIOR_ALLOW,
            identity_key="k1",
            behavior_type="network_dest",
            behavior_value="8.8.8.8:53",
            rationale="DNS resolver",
        )
        d = r.to_dict()
        r2 = WhitelistRule.from_dict(d)
        self.assertEqual(r2.scope, RuleScope.BEHAVIOR_ALLOW)
        self.assertEqual(r2.behavior_value, "8.8.8.8:53")
        self.assertEqual(r2.rationale, "DNS resolver")


class MatchProgramTests(unittest.TestCase):
    def test_program_allow_match(self) -> None:
        rules = [
            WhitelistRule(scope=RuleScope.PROGRAM_ALLOW, identity_key="k1", rationale="trusted"),
        ]
        result = match_program("k1", rules)
        self.assertTrue(result.matched)
        self.assertIn("program_allow", result.reason)

    def test_no_match(self) -> None:
        rules = [
            WhitelistRule(scope=RuleScope.PROGRAM_ALLOW, identity_key="k1"),
        ]
        result = match_program("k2", rules)
        self.assertFalse(result.matched)

    def test_temporary_allow_active(self) -> None:
        now = datetime(2026, 2, 1, tzinfo=timezone.utc)
        rules = [
            WhitelistRule(
                scope=RuleScope.TEMPORARY_ALLOW,
                identity_key="k1",
                expires_ts=(now + timedelta(hours=1)).isoformat(),
            ),
        ]
        result = match_program("k1", rules, now=now)
        self.assertTrue(result.matched)
        self.assertIn("temporary_allow", result.reason)

    def test_temporary_allow_expired(self) -> None:
        now = datetime(2026, 2, 1, tzinfo=timezone.utc)
        rules = [
            WhitelistRule(
                scope=RuleScope.TEMPORARY_ALLOW,
                identity_key="k1",
                expires_ts=(now - timedelta(hours=1)).isoformat(),
            ),
        ]
        result = match_program("k1", rules, now=now)
        self.assertFalse(result.matched)

    def test_deterministic_first_match(self) -> None:
        """First matching rule wins — deterministic order."""
        rules = [
            WhitelistRule(scope=RuleScope.PROGRAM_ALLOW, identity_key="k1", rationale="first"),
            WhitelistRule(scope=RuleScope.PROGRAM_ALLOW, identity_key="k1", rationale="second"),
        ]
        result = match_program("k1", rules)
        self.assertTrue(result.matched)
        self.assertIn("first", result.reason)


class MatchBehaviorTests(unittest.TestCase):
    def test_program_allow_covers_all_behavior(self) -> None:
        rules = [
            WhitelistRule(scope=RuleScope.PROGRAM_ALLOW, identity_key="k1"),
        ]
        result = match_behavior("k1", "network_dest", "1.2.3.4:80", rules)
        self.assertTrue(result.matched)
        self.assertIn("program_allow", result.reason)

    def test_behavior_allow_specific_match(self) -> None:
        rules = [
            WhitelistRule(
                scope=RuleScope.BEHAVIOR_ALLOW,
                identity_key="k1",
                behavior_type="network_dest",
                behavior_value="8.8.8.8:53",
                rationale="DNS",
            ),
        ]
        result = match_behavior("k1", "network_dest", "8.8.8.8:53", rules)
        self.assertTrue(result.matched)
        self.assertIn("behavior_allow", result.reason)

    def test_behavior_allow_wrong_value(self) -> None:
        rules = [
            WhitelistRule(
                scope=RuleScope.BEHAVIOR_ALLOW,
                identity_key="k1",
                behavior_type="network_dest",
                behavior_value="8.8.8.8:53",
            ),
        ]
        result = match_behavior("k1", "network_dest", "1.1.1.1:53", rules)
        self.assertFalse(result.matched)

    def test_behavior_allow_wrong_type(self) -> None:
        rules = [
            WhitelistRule(
                scope=RuleScope.BEHAVIOR_ALLOW,
                identity_key="k1",
                behavior_type="network_dest",
                behavior_value="8.8.8.8:53",
            ),
        ]
        result = match_behavior("k1", "parent_chain", "8.8.8.8:53", rules)
        self.assertFalse(result.matched)

    def test_no_rules_no_match(self) -> None:
        result = match_behavior("k1", "network_dest", "1.2.3.4:80", [])
        self.assertFalse(result.matched)


if __name__ == "__main__":
    unittest.main()
