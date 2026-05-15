"""Tests for S3-T2: Whitelist safety rails enforcement."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scanner.whitelist.rules import RuleScope, WhitelistRule
from scanner.whitelist.safety import validate_rule


class DenyNameOnlyTests(unittest.TestCase):
    def test_rejects_empty_identity_key(self) -> None:
        rule = WhitelistRule(scope=RuleScope.PROGRAM_ALLOW, identity_key="")
        result = validate_rule(rule)
        self.assertFalse(result.valid)
        self.assertTrue(any("name-only" in e for e in result.errors))

    def test_rejects_whitespace_identity_key(self) -> None:
        rule = WhitelistRule(scope=RuleScope.PROGRAM_ALLOW, identity_key="   ")
        result = validate_rule(rule)
        self.assertFalse(result.valid)

    def test_accepts_valid_identity_key(self) -> None:
        rule = WhitelistRule(
            scope=RuleScope.PROGRAM_ALLOW,
            identity_key="abc123",
            image_path_norm=r"c:\program files\app.exe",
            signer_publisher="Microsoft Corporation",
        )
        result = validate_rule(rule)
        self.assertTrue(result.valid)
        self.assertEqual(result.errors, [])


class UnsignedWritableHashTests(unittest.TestCase):
    def test_rejects_unsigned_writable_no_hash(self) -> None:
        rule = WhitelistRule(
            scope=RuleScope.PROGRAM_ALLOW,
            identity_key="abc123",
            image_path_norm=r"c:\users\alice\downloads\sketch.exe",
            signer_publisher="unsigned",
            file_hash="",
        )
        result = validate_rule(rule)
        self.assertFalse(result.valid)
        self.assertTrue(any("file_hash" in e for e in result.errors))

    def test_accepts_unsigned_writable_with_hash(self) -> None:
        rule = WhitelistRule(
            scope=RuleScope.PROGRAM_ALLOW,
            identity_key="abc123",
            image_path_norm=r"c:\users\alice\downloads\sketch.exe",
            signer_publisher="unsigned",
            file_hash="deadbeef1234",
        )
        result = validate_rule(rule)
        self.assertTrue(result.valid)

    def test_accepts_unsigned_nonwritable(self) -> None:
        rule = WhitelistRule(
            scope=RuleScope.PROGRAM_ALLOW,
            identity_key="abc123",
            image_path_norm=r"c:\program files\app.exe",
            signer_publisher="unsigned",
            file_hash="",
        )
        result = validate_rule(rule)
        self.assertTrue(result.valid)

    def test_accepts_signed_writable(self) -> None:
        rule = WhitelistRule(
            scope=RuleScope.PROGRAM_ALLOW,
            identity_key="abc123",
            image_path_norm=r"c:\users\alice\downloads\signed.exe",
            signer_publisher="Trusted Corp",
            file_hash="",
        )
        result = validate_rule(rule)
        self.assertTrue(result.valid)

    def test_appdata_roaming_is_writable(self) -> None:
        rule = WhitelistRule(
            scope=RuleScope.PROGRAM_ALLOW,
            identity_key="abc123",
            image_path_norm=r"c:\users\bob\appdata\roaming\tool.exe",
            signer_publisher="unsigned",
            file_hash="",
        )
        result = validate_rule(rule)
        self.assertFalse(result.valid)

    def test_empty_signer_treated_as_unsigned(self) -> None:
        rule = WhitelistRule(
            scope=RuleScope.PROGRAM_ALLOW,
            identity_key="abc123",
            image_path_norm=r"c:\users\alice\downloads\app.exe",
            signer_publisher="",
            file_hash="",
        )
        result = validate_rule(rule)
        self.assertFalse(result.valid)


class CombinedViolationsTests(unittest.TestCase):
    def test_multiple_violations(self) -> None:
        rule = WhitelistRule(
            scope=RuleScope.PROGRAM_ALLOW,
            identity_key="",
            image_path_norm=r"c:\users\alice\downloads\app.exe",
            signer_publisher="unsigned",
            file_hash="",
        )
        result = validate_rule(rule)
        self.assertFalse(result.valid)
        self.assertEqual(len(result.errors), 2)


if __name__ == "__main__":
    unittest.main()
