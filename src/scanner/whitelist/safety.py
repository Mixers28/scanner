"""Whitelist safety rails.

Validates proposed whitelist rules before they can be persisted.

SPEC §5.3 safety rails:
  1. Deny name-only allow rules (must have identity_key bound to path+signer).
  2. Unsigned executables in user-writable paths must include file_hash binding.
"""

from __future__ import annotations

from dataclasses import dataclass
from scanner.common.identity import is_user_writable_dir
from scanner.whitelist.rules import WhitelistRule


@dataclass
class ValidationResult:
    valid: bool
    errors: list[str]


def validate_rule(rule: WhitelistRule) -> ValidationResult:
    """Validate a whitelist rule against safety rails.

    Returns a ValidationResult with any violations listed.
    """
    errors: list[str] = []

    # Rail 1: Must have identity_key (no name-only rules)
    if not rule.identity_key or not rule.identity_key.strip():
        errors.append("name-only rules are denied: identity_key is required")

    # Rail 2: Unsigned + user-writable must have file_hash
    signer = (rule.signer_publisher or "").strip().lower()
    is_unsigned = signer in ("", "unsigned")
    is_writable = bool(rule.image_path_norm) and is_user_writable_dir(rule.image_path_norm)

    if is_unsigned and is_writable:
        if not rule.file_hash or not rule.file_hash.strip():
            errors.append(
                "unsigned executable in user-writable path must include file_hash binding"
            )

    return ValidationResult(valid=len(errors) == 0, errors=errors)
