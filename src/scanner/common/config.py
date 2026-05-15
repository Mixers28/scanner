"""Configuration defaults and validation for Scanner MVP."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

DEFAULT_CONFIG: dict[str, Any] = {
    "collector": {
        "process_poll_interval_seconds": 2,
        "resource_poll_interval_seconds": 5,
        "network_poll_interval_seconds": 10,
        "capture_command_line": False,
        "max_events_per_minute": 6000,
    },
    "baseline": {
        "learning_window_days": 7,
        "enable_drift": True,
        "drift_min_confidence": 0.8,
    },
    "anomaly": {
        "cooldown_minutes": 30,
        "resource_spike_intervals": 3,
    },
    "verify": {
        "total_timeout_seconds": 30,
        "cache_ttl_days": 7,
        "adapters_enabled": ["signature"],
    },
    "reporting": {
        "formats": ["json", "html"],
        "include_technical_appendix": True,
        "out_dir": "reports",
    },
    "retention": {
        "telemetry_days": 7,
        "incidents_days": 90,
        "max_baseline_versions": 10,
        "max_whitelist_versions": 50,
        "max_db_mb": 500,
    },
}


def _require_int_in_range(
    section: Mapping[str, Any],
    key: str,
    minimum: int,
    maximum: int,
    errors: list[str],
) -> None:
    value = section.get(key)
    if not isinstance(value, int):
        errors.append(f"{key} must be an integer")
        return
    if not (minimum <= value <= maximum):
        errors.append(f"{key} must be in range [{minimum}, {maximum}]")


def validate_config(config: Mapping[str, Any]) -> dict[str, Any]:
    """Validate scanner config and return a deep-copied dict."""
    required_sections = ("collector", "retention", "verify", "reporting")
    errors: list[str] = []

    for section_name in required_sections:
        if section_name not in config:
            errors.append(f"missing required section: {section_name}")

    if errors:
        raise ValueError("; ".join(errors))

    collector = config["collector"]
    retention = config["retention"]
    verify = config["verify"]

    if not isinstance(collector, Mapping):
        errors.append("collector must be an object")
    else:
        _require_int_in_range(collector, "process_poll_interval_seconds", 1, 30, errors)
        _require_int_in_range(collector, "resource_poll_interval_seconds", 1, 60, errors)
        _require_int_in_range(collector, "network_poll_interval_seconds", 1, 120, errors)
        _require_int_in_range(collector, "max_events_per_minute", 100, 60000, errors)

    if not isinstance(retention, Mapping):
        errors.append("retention must be an object")
    else:
        _require_int_in_range(retention, "telemetry_days", 1, 90, errors)
        _require_int_in_range(retention, "incidents_days", 7, 365, errors)
        _require_int_in_range(retention, "max_db_mb", 50, 5000, errors)

    if not isinstance(verify, Mapping):
        errors.append("verify must be an object")
    else:
        _require_int_in_range(verify, "total_timeout_seconds", 5, 300, errors)
        _require_int_in_range(verify, "cache_ttl_days", 1, 30, errors)
        adapters = verify.get("adapters_enabled", [])
        if not isinstance(adapters, list):
            errors.append("verify.adapters_enabled must be a list")
        elif not all(isinstance(adapter, str) and adapter for adapter in adapters):
            errors.append("verify.adapters_enabled must contain non-empty strings")

    if errors:
        raise ValueError("; ".join(errors))

    return deepcopy(dict(config))
