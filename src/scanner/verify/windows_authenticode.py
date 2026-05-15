"""Windows Authenticode helpers.

Uses PowerShell's Get-AuthenticodeSignature cmdlet as a thin wrapper around
the Windows trust APIs. This keeps the adapter implementation small while
still performing a real OS-backed signature evaluation on Windows hosts.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


_POWERSHELL_SCRIPT = r"""
$sig = Get-AuthenticodeSignature -LiteralPath $args[0]
[pscustomobject]@{
  Status = [string]$sig.Status
  StatusMessage = [string]$sig.StatusMessage
  SignerSubject = if ($sig.SignerCertificate) { [string]$sig.SignerCertificate.Subject } else { "" }
  SignerThumbprint = if ($sig.SignerCertificate) { [string]$sig.SignerCertificate.Thumbprint } else { "" }
  SignerNotAfter = if ($sig.SignerCertificate) { [string]$sig.SignerCertificate.NotAfter.ToString("o") } else { "" }
  TimeStamperSubject = if ($sig.TimeStamperCertificate) { [string]$sig.TimeStamperCertificate.Subject } else { "" }
  IsOSBinary = [bool]$sig.IsOSBinary
} | ConvertTo-Json -Compress
""".strip()


@dataclass(frozen=True)
class AuthenticodeCheck:
    """Normalized Authenticode result returned by the PowerShell wrapper."""

    status: str
    status_message: str = ""
    signer_subject: str = ""
    signer_thumbprint: str = ""
    signer_not_after: str = ""
    timestamp_subject: str = ""
    is_os_binary: bool = False

    @property
    def publisher(self) -> str:
        return extract_common_name(self.signer_subject)

    def to_evidence(self) -> dict[str, str]:
        evidence = {
            "trust_status": self.status.lower() or "unknown",
            "status_message": self.status_message,
            "publisher": self.publisher,
            "signer_subject": self.signer_subject,
            "signer_thumbprint": self.signer_thumbprint,
            "signer_not_after": self.signer_not_after,
            "timestamp_subject": self.timestamp_subject,
            "is_os_binary": str(self.is_os_binary).lower(),
        }
        return {key: value for key, value in evidence.items() if value}


def extract_common_name(subject: str) -> str:
    """Extract CN from an X.509 subject string when present."""
    for part in subject.split(","):
        token = part.strip()
        if token[:3].lower() == "cn=":
            return token[3:].strip()
    return subject.strip()


def locate_powershell() -> str | None:
    """Return an available PowerShell executable, preferring Windows PowerShell."""
    return shutil.which("powershell.exe") or shutil.which("pwsh")


def run_authenticode_check(image_path: str, powershell_exe: str | None = None) -> AuthenticodeCheck:
    """Execute a real Authenticode check through PowerShell."""
    ps = powershell_exe or locate_powershell()
    if not ps:
        raise RuntimeError("PowerShell is not available")

    completed = subprocess.run(
        [
            ps,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            _POWERSHELL_SCRIPT,
            str(Path(image_path)),
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(stderr or "PowerShell Authenticode check failed")

    payload = json.loads(completed.stdout.strip() or "{}")
    return AuthenticodeCheck(
        status=str(payload.get("Status", "")),
        status_message=str(payload.get("StatusMessage", "")),
        signer_subject=str(payload.get("SignerSubject", "")),
        signer_thumbprint=str(payload.get("SignerThumbprint", "")),
        signer_not_after=str(payload.get("SignerNotAfter", "")),
        timestamp_subject=str(payload.get("TimeStamperSubject", "")),
        is_os_binary=bool(payload.get("IsOSBinary", False)),
    )
