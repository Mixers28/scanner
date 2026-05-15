"""Tests for S5-T1: Verification adapter framework."""

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scanner.common.types import Verdict
from scanner.verify.adapters import (
    VerificationResult,
    VerificationAdapter,
    SignatureAdapter,
    AdapterRegistry,
    create_default_registry,
)
from scanner.verify.windows_authenticode import (
    AuthenticodeCheck,
    extract_common_name,
    run_authenticode_check,
)


class VerificationResultTests(unittest.TestCase):
    def test_defaults(self) -> None:
        r = VerificationResult(adapter_name="test", verdict=Verdict.CLEAN)
        self.assertIn("T", r.timestamp)
        self.assertEqual(r.duration_ms, 0)

    def test_roundtrip_dict(self) -> None:
        r = VerificationResult(
            adapter_name="sig", verdict=Verdict.SUSPICIOUS,
            evidence={"key": "val"}, duration_ms=42,
        )
        d = r.to_dict()
        r2 = VerificationResult.from_dict(d)
        self.assertEqual(r2.verdict, Verdict.SUSPICIOUS)
        self.assertEqual(r2.evidence["key"], "val")
        self.assertEqual(r2.duration_ms, 42)

    def test_contract_fields(self) -> None:
        """Adapter output must have verdict, evidence, timestamp, duration_ms."""
        r = VerificationResult(adapter_name="x", verdict=Verdict.CLEAN)
        d = r.to_dict()
        for field in ("verdict", "evidence", "timestamp", "duration_ms"):
            self.assertIn(field, d)


class SignatureAdapterTests(unittest.TestCase):
    def test_name(self) -> None:
        self.assertEqual(SignatureAdapter().name, "signature")

    def test_empty_path_returns_unknown(self) -> None:
        r = SignatureAdapter().check("", "")
        self.assertEqual(r.verdict, Verdict.UNKNOWN)
        self.assertIn("no image path", r.evidence.get("reason", ""))

    def test_nonexistent_path_returns_unknown(self) -> None:
        r = SignatureAdapter().check(r"C:\nonexistent\path\fake.exe")
        self.assertEqual(r.verdict, Verdict.UNKNOWN)

    @patch("scanner.verify.adapters.os.path.isfile", return_value=True)
    @patch("scanner.verify.adapters.platform.system", return_value="Linux")
    def test_non_windows_host_returns_unknown(self, mock_system, mock_isfile) -> None:
        r = SignatureAdapter().check("/tmp/fake.exe")
        self.assertEqual(r.verdict, Verdict.UNKNOWN)
        self.assertIn("Windows hosts", r.evidence.get("reason", ""))

    @patch("scanner.verify.adapters.run_authenticode_check")
    @patch("scanner.verify.adapters.os.path.isfile", return_value=True)
    @patch("scanner.verify.adapters.platform.system", return_value="Windows")
    def test_valid_signature_returns_clean(
        self,
        mock_system,
        mock_isfile,
        mock_check,
    ) -> None:
        mock_check.return_value = AuthenticodeCheck(
            status="Valid",
            signer_subject="CN=Microsoft Corporation, O=Microsoft Corporation, C=US",
            signer_thumbprint="ABC123",
            status_message="Signature verified.",
            is_os_binary=True,
        )
        r = SignatureAdapter().check(r"C:\Windows\System32\cmd.exe")
        self.assertEqual(r.verdict, Verdict.CLEAN)
        self.assertEqual(r.evidence["publisher"], "Microsoft Corporation")
        self.assertEqual(r.evidence["trust_status"], "valid")

    @patch("scanner.verify.adapters.run_authenticode_check")
    @patch("scanner.verify.adapters.os.path.isfile", return_value=True)
    @patch("scanner.verify.adapters.platform.system", return_value="Windows")
    def test_invalid_signature_returns_suspicious(
        self,
        mock_system,
        mock_isfile,
        mock_check,
    ) -> None:
        mock_check.return_value = AuthenticodeCheck(
            status="HashMismatch",
            status_message="File hash does not match the embedded signature.",
            signer_subject="CN=Suspicious Publisher",
        )
        r = SignatureAdapter().check(r"C:\Users\alice\Downloads\bad.exe")
        self.assertEqual(r.verdict, Verdict.SUSPICIOUS)
        self.assertEqual(r.evidence["trust_status"], "hashmismatch")

    @patch("scanner.verify.adapters.run_authenticode_check")
    @patch("scanner.verify.adapters.os.path.isfile", return_value=True)
    @patch("scanner.verify.adapters.platform.system", return_value="Windows")
    def test_unsigned_file_returns_unknown(
        self,
        mock_system,
        mock_isfile,
        mock_check,
    ) -> None:
        mock_check.return_value = AuthenticodeCheck(status="NotSigned")
        r = SignatureAdapter().check(r"C:\Users\alice\Downloads\tool.exe")
        self.assertEqual(r.verdict, Verdict.UNKNOWN)
        self.assertEqual(r.evidence["trust_status"], "notsigned")

    def test_safe_check_catches_exceptions(self) -> None:
        class BadAdapter(VerificationAdapter):
            @property
            def name(self) -> str:
                return "bad"
            def check(self, image_path: str, file_hash: str = "") -> VerificationResult:
                raise RuntimeError("boom")

        result = BadAdapter().safe_check("test")
        self.assertEqual(result.verdict, Verdict.ERROR)
        self.assertIn("boom", result.evidence.get("error", ""))

    def test_safe_check_records_duration(self) -> None:
        r = SignatureAdapter().safe_check("")
        self.assertGreaterEqual(r.duration_ms, 0)


class AdapterRegistryTests(unittest.TestCase):
    def test_register_and_get(self) -> None:
        reg = AdapterRegistry()
        adapter = SignatureAdapter()
        reg.register(adapter)
        self.assertIs(reg.get("signature"), adapter)

    def test_list_adapters(self) -> None:
        reg = AdapterRegistry()
        reg.register(SignatureAdapter())
        self.assertEqual(reg.list_adapters(), ["signature"])

    def test_get_missing_returns_none(self) -> None:
        reg = AdapterRegistry()
        self.assertIsNone(reg.get("nonexistent"))

    def test_run_all(self) -> None:
        reg = create_default_registry()
        results = reg.run_all("")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].adapter_name, "signature")

    def test_unknown_enabled_adapter_raises(self) -> None:
        with self.assertRaises(ValueError):
            create_default_registry(["signature", "defender"])


class CreateDefaultRegistryTests(unittest.TestCase):
    def test_has_signature_adapter(self) -> None:
        reg = create_default_registry()
        self.assertIn("signature", reg.list_adapters())

    def test_filter_enabled_adapters(self) -> None:
        reg = create_default_registry(["signature"])
        self.assertEqual(reg.list_adapters(), ["signature"])


class AuthenticodeHelpersTests(unittest.TestCase):
    def test_extract_common_name(self) -> None:
        self.assertEqual(
            extract_common_name("CN=Microsoft Corporation, O=Microsoft Corporation, C=US"),
            "Microsoft Corporation",
        )

    @patch("scanner.verify.windows_authenticode.subprocess.run")
    @patch("scanner.verify.windows_authenticode.locate_powershell", return_value="powershell.exe")
    def test_run_authenticode_check_parses_powershell_output(
        self,
        mock_locate,
        mock_run,
    ) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps(
                {
                    "Status": "Valid",
                    "StatusMessage": "Signature verified.",
                    "SignerSubject": "CN=Microsoft Corporation, O=Microsoft Corporation, C=US",
                    "SignerThumbprint": "ABC123",
                    "SignerNotAfter": "2030-01-01T00:00:00",
                    "TimeStamperSubject": "CN=Microsoft Time-Stamp Service",
                    "IsOSBinary": True,
                }
            ),
            stderr="",
        )
        result = run_authenticode_check(r"C:\Windows\System32\cmd.exe")
        self.assertEqual(result.status, "Valid")
        self.assertEqual(result.publisher, "Microsoft Corporation")
        self.assertTrue(result.is_os_binary)


if __name__ == "__main__":
    unittest.main()
