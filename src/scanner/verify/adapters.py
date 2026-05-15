"""Verification adapter framework.

Defines the adapter contract and registry.  Each adapter performs a
local check on a file/process and returns a normalized VerificationResult.

SPEC §5.5 adapter return contract:
  - verdict: clean | suspicious | malicious | unknown | error
  - evidence: key/value list
  - timestamp, duration_ms
"""

from __future__ import annotations

import abc
import logging
import os
import platform
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from scanner.common.types import Verdict
from scanner.verify.windows_authenticode import run_authenticode_check

logger = logging.getLogger(__name__)


@dataclass
class VerificationResult:
    """Normalized output from any verification adapter."""
    adapter_name: str
    verdict: Verdict
    evidence: dict[str, str] = field(default_factory=dict)
    timestamp: str = ""
    duration_ms: int = 0

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter_name": self.adapter_name,
            "verdict": self.verdict.value,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
            "duration_ms": self.duration_ms,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VerificationResult:
        return cls(
            adapter_name=data.get("adapter_name", ""),
            verdict=Verdict(data.get("verdict", "unknown")),
            evidence=data.get("evidence", {}),
            timestamp=data.get("timestamp", ""),
            duration_ms=data.get("duration_ms", 0),
        )


class VerificationAdapter(abc.ABC):
    """Base class for all verification adapters."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        ...

    @abc.abstractmethod
    def check(self, image_path: str, file_hash: str = "") -> VerificationResult:
        """Run verification and return normalized result."""
        ...

    def safe_check(self, image_path: str, file_hash: str = "") -> VerificationResult:
        """Run check with timing and error handling."""
        start = time.monotonic()
        try:
            result = self.check(image_path, file_hash)
        except Exception as exc:
            elapsed = int((time.monotonic() - start) * 1000)
            logger.warning("Adapter %s failed: %s", self.name, exc)
            result = VerificationResult(
                adapter_name=self.name,
                verdict=Verdict.ERROR,
                evidence={"error": str(exc)},
                duration_ms=elapsed,
            )
        else:
            result.duration_ms = int((time.monotonic() - start) * 1000)
        return result


class SignatureAdapter(VerificationAdapter):
    """Windows Authenticode verification adapter."""

    @property
    def name(self) -> str:
        return "signature"

    def check(self, image_path: str, file_hash: str = "") -> VerificationResult:
        evidence: dict[str, str] = {"image_path": image_path}
        if file_hash:
            evidence["file_hash"] = file_hash

        if not image_path:
            return VerificationResult(
                adapter_name=self.name,
                verdict=Verdict.UNKNOWN,
                evidence={**evidence, "reason": "no image path provided"},
            )

        if not os.path.isfile(image_path):
            return VerificationResult(
                adapter_name=self.name,
                verdict=Verdict.UNKNOWN,
                evidence={**evidence, "reason": "file not found on disk"},
            )

        if platform.system() != "Windows":
            return VerificationResult(
                adapter_name=self.name,
                verdict=Verdict.UNKNOWN,
                evidence={**evidence, "reason": "Authenticode is only available on Windows hosts"},
            )

        check = run_authenticode_check(image_path)
        trust_status = check.status.strip().lower()

        if trust_status == "valid":
            verdict = Verdict.CLEAN
        elif trust_status in {"notsigned", "notsupportedfileformat", "incompatible"}:
            verdict = Verdict.UNKNOWN
        else:
            verdict = Verdict.SUSPICIOUS

        return VerificationResult(
            adapter_name=self.name,
            verdict=verdict,
            evidence={**evidence, **check.to_evidence()},
        )


class AdapterRegistry:
    """Registry of available verification adapters."""

    def __init__(self) -> None:
        self._adapters: dict[str, VerificationAdapter] = {}

    def register(self, adapter: VerificationAdapter) -> None:
        self._adapters[adapter.name] = adapter

    def get(self, name: str) -> VerificationAdapter | None:
        return self._adapters.get(name)

    def list_adapters(self) -> list[str]:
        return list(self._adapters.keys())

    def run_all(self, image_path: str, file_hash: str = "") -> list[VerificationResult]:
        """Run all registered adapters and return results."""
        return [a.safe_check(image_path, file_hash) for a in self._adapters.values()]


def create_default_registry(adapters_enabled: list[str] | None = None) -> AdapterRegistry:
    """Create registry with default adapters, filtered by config when provided."""
    registry = AdapterRegistry()
    available = {
        "signature": SignatureAdapter(),
    }
    enabled = adapters_enabled or list(available.keys())
    unknown = [name for name in enabled if name not in available]
    if unknown:
        raise ValueError(f"unknown verification adapters: {', '.join(sorted(unknown))}")
    for name in enabled:
        registry.register(available[name])
    return registry
