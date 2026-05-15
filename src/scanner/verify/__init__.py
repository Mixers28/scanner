"""Verification module – adapter framework, caching, and orchestration."""

from .adapters import (
    VerificationResult,
    VerificationAdapter,
    SignatureAdapter,
    AdapterRegistry,
    create_default_registry,
)
from .windows_authenticode import AuthenticodeCheck
from .cache import VerificationCache, run_verification_with_budget

__all__ = [
    "VerificationResult",
    "VerificationAdapter",
    "SignatureAdapter",
    "AdapterRegistry",
    "AuthenticodeCheck",
    "VerificationCache",
    "create_default_registry",
    "run_verification_with_budget",
]
