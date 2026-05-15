"""Shared contracts and utilities for Scanner."""

from .config import DEFAULT_CONFIG, validate_config
from .identity import build_identity_key, is_user_writable_dir, normalize_windows_path
from .types import IncidentState, Severity, Verdict

__all__ = [
    "DEFAULT_CONFIG",
    "validate_config",
    "build_identity_key",
    "is_user_writable_dir",
    "normalize_windows_path",
    "IncidentState",
    "Severity",
    "Verdict",
]
