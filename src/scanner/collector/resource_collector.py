"""Resource telemetry collector.

Polls per-process CPU%, memory, and disk I/O at a configurable interval
and emits `resource_sample` telemetry events.
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


def _safe_resource_sample(proc: psutil.Process) -> dict[str, Any] | None:
    """Collect resource metrics for a single process.  Returns None on failure."""
    try:
        with proc.oneshot():
            pid = proc.pid
            exe = proc.exe() or ""
            cpu = proc.cpu_percent(interval=0)
            mem_info = proc.memory_info()
            try:
                io = proc.io_counters()
                read_bytes = io.read_bytes
                write_bytes = io.write_bytes
            except (psutil.AccessDenied, AttributeError):
                read_bytes = 0
                write_bytes = 0

        return {
            "pid": pid,
            "exe": exe,
            "cpu_percent": cpu,
            "memory_rss_bytes": mem_info.rss,
            "memory_vms_bytes": mem_info.vms,
            "disk_read_bytes": read_bytes,
            "disk_write_bytes": write_bytes,
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def collect_resource_samples(
    host_id: str,
    pids: list[int] | None = None,
) -> list[Any]:
    """Poll resource metrics for all (or specified) processes.

    Returns a list of TelemetryEvent with event_type='resource_sample'.
    """
    events = []

    if pids is not None:
        procs = []
        for pid in pids:
            try:
                procs.append(psutil.Process(pid))
            except psutil.NoSuchProcess:
                continue
    else:
        procs = list(psutil.process_iter())

    for proc in procs:
        sample = _safe_resource_sample(proc)
        if sample is None:
            continue

        image_norm = normalize_windows_path(sample["exe"])
        signer = normalize_signer_publisher(None)
        identity_key = build_identity_key(image_norm, signer)
        sample["image_path"] = sample["exe"]
        sample["image_path_norm"] = image_norm
        sample["signer_publisher"] = signer
        sample["identity_key"] = identity_key

        ev = make_telemetry_event(
            host_id=host_id,
            event_type="resource_sample",
            pid=sample["pid"],
            payload=sample,
        )
        events.append(ev)
    return events
