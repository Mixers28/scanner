"""Core shared types and enums for Scanner."""

from dataclasses import dataclass
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class IncidentState(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class Verdict(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"
    ERROR = "error"


@dataclass(frozen=True)
class ProcessIdentity:
    image_path_norm: str
    signer_publisher: str
    file_hash: str = ""
    product_name: str = ""


@dataclass(frozen=True)
class TelemetryEvent:
    event_id: str
    host_id: str
    ts: str
    event_type: str
    pid: int
    payload: dict[str, Any]
