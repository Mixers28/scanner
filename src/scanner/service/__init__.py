"""Service/orchestrator module – lifecycle, scheduling, and health."""

from .orchestrator import ScannerService, run_foreground

__all__ = [
    "ScannerService",
    "run_foreground",
]
