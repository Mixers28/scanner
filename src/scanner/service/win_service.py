"""Windows Service wrapper for the scanner.

Requires pywin32 (optional dependency).
If pywin32 is not installed, the scanner can still run in foreground mode
or be scheduled via Windows Task Scheduler.

Install:   python -m scanner install-service
Uninstall: python -m scanner uninstall-service
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

_SERVICE_NAME = "ScannerService"
_SERVICE_DISPLAY = "Scanner Security Monitor"
_SERVICE_DESCRIPTION = "Local process scanner – monitors for anomalous behavior."

# Guard: pywin32 may not be installed
_HAS_WIN32 = False
try:
    import win32serviceutil  # type: ignore[import-untyped]
    import win32service  # type: ignore[import-untyped]
    import win32event  # type: ignore[import-untyped]
    import servicemanager  # type: ignore[import-untyped]
    _HAS_WIN32 = True
except ImportError:
    pass


def _check_win32() -> None:
    if not _HAS_WIN32:
        raise ImportError(
            "pywin32 is required for Windows Service support. "
            "Install with: pip install pywin32"
        )


if _HAS_WIN32:
    class _ScannerWinService(win32serviceutil.ServiceFramework):
        """Win32 service wrapper around ScannerService."""

        _svc_name_ = _SERVICE_NAME
        _svc_display_name_ = _SERVICE_DISPLAY
        _svc_description_ = _SERVICE_DESCRIPTION

        def __init__(self, args: list) -> None:
            super().__init__(args)
            self._stop_event = win32event.CreateEvent(None, 0, 0, None)
            self._svc = None

        def SvcStop(self) -> None:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self._stop_event)
            if self._svc:
                self._svc.stop()

        def SvcDoRun(self) -> None:
            from scanner.common.config import DEFAULT_CONFIG
            from scanner.service.orchestrator import ScannerService

            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )

            db_path = Path(sys.prefix) / "scanner" / "scanner.db"
            db_path.parent.mkdir(parents=True, exist_ok=True)

            self._svc = ScannerService(db_path=db_path)
            self._svc.start()

            interval_ms = DEFAULT_CONFIG["collector"].get(
                "process_poll_interval_seconds", 2
            ) * 1000

            while True:
                rc = win32event.WaitForSingleObject(
                    self._stop_event, int(interval_ms)
                )
                if rc == win32event.WAIT_OBJECT_0:
                    break
                try:
                    self._svc.run_cycle()
                except Exception:
                    logger.exception("Error in service cycle")

            if self._svc:
                self._svc.stop()


def install_service() -> int:
    """Install the scanner as a Windows Service."""
    _check_win32()
    try:
        win32serviceutil.InstallService(
            _ScannerWinService._svc_reg_class_,
            _SERVICE_NAME,
            _SERVICE_DISPLAY,
            startType=win32service.SERVICE_AUTO_START,
            description=_SERVICE_DESCRIPTION,
        )
        print(f"Service '{_SERVICE_NAME}' installed successfully.")
        print(f"Start it with: net start {_SERVICE_NAME}")
        return 0
    except Exception as exc:
        print(f"Failed to install service: {exc}")
        return 1


def uninstall_service() -> int:
    """Uninstall the scanner Windows Service."""
    _check_win32()
    try:
        win32serviceutil.RemoveService(_SERVICE_NAME)
        print(f"Service '{_SERVICE_NAME}' removed successfully.")
        return 0
    except Exception as exc:
        print(f"Failed to remove service: {exc}")
        return 1
