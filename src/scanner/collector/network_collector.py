"""Network telemetry collector (best-effort).

Captures per-process outbound network connections using psutil.
Fields that are unavailable degrade gracefully rather than crashing.
"""

from __future__ import annotations

import logging
from typing import Any

import psutil

from scanner.collector.process_collector import make_telemetry_event
from scanner.common.identity import (
    build_identity_key,
    normalize_signer_publisher,
    normalize_windows_path,
)

logger = logging.getLogger(__name__)


def _connection_to_dict(conn: Any, pid: int) -> dict[str, Any] | None:
    """Convert a psutil connection object to a payload dict.

    Returns None for listening/unconnected sockets (no remote address).
    """
    raddr = getattr(conn, "raddr", None)
    if not raddr:
        return None

    return {
        "pid": pid,
        "local_ip": conn.laddr.ip if conn.laddr else "",
        "local_port": conn.laddr.port if conn.laddr else 0,
        "remote_ip": raddr.ip if raddr else "",
        "remote_port": raddr.port if raddr else 0,
        "status": getattr(conn, "status", ""),
        "type": str(getattr(conn, "type", "")),
        "family": str(getattr(conn, "family", "")),
    }


def collect_network_connections(host_id: str) -> list[Any]:
    """Snapshot current outbound network connections per-process.

    Returns a list of TelemetryEvent with event_type='net_conn'.
    Best-effort: silently skips connections where PID or remote address
    is unavailable.
    """
    events = []
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError) as exc:
        logger.warning("net_connections unavailable: %s", exc)
        return events

    # Group by PID and resolve exe once per PID
    pid_exe_cache: dict[int, str] = {}

    for conn in connections:
        pid = getattr(conn, "pid", None)
        if pid is None or pid <= 0:
            continue

        payload = _connection_to_dict(conn, pid)
        if payload is None:
            continue

        # Resolve exe path (cached per PID)
        if pid not in pid_exe_cache:
            try:
                proc = psutil.Process(pid)
                pid_exe_cache[pid] = proc.exe() or ""
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pid_exe_cache[pid] = ""

        exe = pid_exe_cache[pid]
        image_norm = normalize_windows_path(exe)
        signer = normalize_signer_publisher(None)
        identity_key = build_identity_key(image_norm, signer)
        payload["exe"] = exe
        payload["image_path"] = exe
        payload["image_path_norm"] = image_norm
        payload["signer_publisher"] = signer
        payload["identity_key"] = identity_key

        ev = make_telemetry_event(
            host_id=host_id,
            event_type="net_conn",
            pid=pid,
            payload=payload,
        )
        events.append(ev)
    return events
