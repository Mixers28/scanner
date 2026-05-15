"""Identity and path-normalization helpers."""

from __future__ import annotations

import hashlib
import os
from typing import Iterable

_USER_WRITABLE_PREFIXES: tuple[str, ...] = (
    "c:\\users\\",
    "c:\\windows\\temp\\",
)


def normalize_signer_publisher(signer_publisher: str | None) -> str:
    """Normalize signer state while preserving unknown vs unsigned."""
    return (signer_publisher or "unknown").strip().lower()


def normalize_windows_path(path: str) -> str:
    """Normalize a Windows path for stable matching."""
    if not path:
        return ""

    expanded = os.path.expandvars(path).strip().replace("/", "\\")
    if expanded.startswith("\\\\?\\"):
        expanded = expanded[4:]

    try:
        normalized = os.path.normpath(expanded)
    except (TypeError, ValueError):
        normalized = expanded
    return normalized.lower()


def _matches_prefixes(value: str, prefixes: Iterable[str]) -> bool:
    return any(value.startswith(prefix) for prefix in prefixes)


def is_user_writable_dir(path: str) -> bool:
    """Best-effort writable-path heuristic for MVP."""
    norm = normalize_windows_path(path)
    if _matches_prefixes(norm, _USER_WRITABLE_PREFIXES):
        return True
    return (
        "\\appdata\\roaming\\" in norm
        or "\\appdata\\local\\" in norm
        or "\\downloads\\" in norm
    )


def build_identity_key(
    image_path_norm: str,
    signer_publisher: str,
    file_hash: str | None = None,
) -> str:
    """Build process identity key.

    Note: product_name is metadata only and intentionally excluded from identity.
    """
    path_norm = normalize_windows_path(image_path_norm)
    signer_norm = normalize_signer_publisher(signer_publisher)
    hash_or_empty = (file_hash or "").strip().lower()
    payload = f"{path_norm}|{signer_norm}|{hash_or_empty}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
