"""Process telemetry collector for Windows.

Captures process start/stop events with PID, PPID, image path,
and best-effort signer information.  Uses psutil for enumeration
and a polling-based diff approach to detect new/exited processes.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

import psutil

from scanner.common.identity import build_identity_key, normalize_windows_path
from scanner.common.types import TelemetryEvent

logger = logging.getLogger(__name__)


def _safe_proc_info(proc: psutil.Process) -> dict[str, Any] | None:
    """Extract process info safely; returns None if process vanished."""
    try:
        info = proc.as_dict(attrs=[
            "pid", "ppid", "name", "exe", "create_time", "status",
        ])
        return info
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def _get_signer(exe_path: str | None) -> str:
    """Best-effort Authenticode signer extraction.

    Full Authenticode verification requires ctypes/win32 calls.
    For MVP we stub this and return 'unknown' — the verify module
    will perform real signature checks when triggered.
    """
    # TODO(S5): Wire real Authenticode verification via ctypes
    return "unknown"


def normalize_process_fields(
    pid: int,
    ppid: int | None,
    exe_path: str | None,
    name: str | None,
    create_time: float | None,
) -> dict[str, Any]:
    """Normalize raw process fields into a canonical payload dict."""
    image_path_norm = normalize_windows_path(exe_path or "")
    signer = _get_signer(exe_path)
    identity_key = build_identity_key(image_path_norm, signer)

    return {
        "pid": pid,
        "ppid": ppid or 0,
        "name": name or "",
        "image_path": exe_path or "",
        "image_path_norm": image_path_norm,
        "signer_publisher": signer,
        "identity_key": identity_key,
        "create_time": create_time,
    }


def make_telemetry_event(
    host_id: str,
    event_type: str,
    pid: int,
    payload: dict[str, Any],
) -> TelemetryEvent:
    """Build a TelemetryEvent envelope."""
    return TelemetryEvent(
        event_id=uuid.uuid4().hex,
        host_id=host_id,
        ts=datetime.now(timezone.utc).isoformat(),
        event_type=event_type,
        pid=pid,
        payload=payload,
    )


class ProcessCollector:
    """Polls for process start/stop events via diff of PID snapshots."""

    def __init__(self, host_id: str) -> None:
        self.host_id = host_id
        self._known_pids: dict[int, dict[str, Any]] = {}

    def snapshot(self) -> tuple[list[TelemetryEvent], list[TelemetryEvent]]:
        """Take a snapshot and return (started, stopped) event lists."""
        current: dict[int, dict[str, Any]] = {}
        for proc in psutil.process_iter():
            info = _safe_proc_info(proc)
            if info is None:
                continue
            pid = info["pid"]
            current[pid] = info

        started: list[TelemetryEvent] = []
        stopped: list[TelemetryEvent] = []

        # Detect new processes
        for pid, info in current.items():
            if pid not in self._known_pids:
                payload = normalize_process_fields(
                    pid=pid,
                    ppid=info.get("ppid"),
                    exe_path=info.get("exe"),
                    name=info.get("name"),
                    create_time=info.get("create_time"),
                )
                event = make_telemetry_event(
                    self.host_id, "process_start", pid, payload,
                )
                started.append(event)

        # Detect exited processes
        for pid, info in self._known_pids.items():
            if pid not in current:
                payload = normalize_process_fields(
                    pid=pid,
                    ppid=info.get("ppid"),
                    exe_path=info.get("exe"),
                    name=info.get("name"),
                    create_time=info.get("create_time"),
                )
                event = make_telemetry_event(
                    self.host_id, "process_stop", pid, payload,
                )
                stopped.append(event)

        self._known_pids = current
        return started, stopped
