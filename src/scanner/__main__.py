"""Scanner CLI entry point.

Usage:
    python -m scanner run [--db PATH] [--max-cycles N]
    python -m scanner status [--db PATH]
    python -m scanner install-service
    python -m scanner uninstall-service
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from scanner.common.config import DEFAULT_CONFIG, validate_config
from scanner.service.orchestrator import ScannerService, run_foreground


def _setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(name)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


def cmd_run(args: argparse.Namespace) -> int:
    """Run scanner in foreground mode."""
    _setup_logging(args.log_level)
    max_cycles = args.max_cycles if args.max_cycles > 0 else 0
    svc = run_foreground(
        db_path=args.db,
        max_cycles=max_cycles,
        hub_url=getattr(args, "hub_url", ""),
        hub_api_key=getattr(args, "hub_api_key", ""),
    )
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Show scanner status from a running or last-known database."""
    _setup_logging("WARNING")
    from pathlib import Path

    from scanner.storage.sqlite_store import SQLiteStorage

    db_path = Path(args.db)
    if not db_path.exists():
        print(f"Database not found: {db_path}")
        return 1

    storage = SQLiteStorage(db_path)
    storage.initialize()
    status = storage.load_status() or {
        "running": False,
        "host_id": "",
        "started_ts": "",
        "updated_ts": "",
        "mode": "unknown",
        "cycle_count": 0,
        "total_events": 0,
        "total_incidents": 0,
        "rate_limiter_dropped": 0,
    }
    status["db_path"] = str(db_path)
    storage.close()

    print(json.dumps(status, indent=2))
    return 0


def cmd_install_service(args: argparse.Namespace) -> int:
    """Install as a Windows Service (requires pywin32)."""
    try:
        from scanner.service.win_service import install_service
        return install_service()
    except ImportError:
        print("Error: pywin32 is required for Windows Service support.")
        print("Install it with: pip install pywin32")
        print("")
        print("Alternative: use Task Scheduler to run 'python -m scanner run' at startup.")
        return 1


def cmd_uninstall_service(args: argparse.Namespace) -> int:
    """Uninstall the Windows Service (requires pywin32)."""
    try:
        from scanner.service.win_service import uninstall_service
        return uninstall_service()
    except ImportError:
        print("Error: pywin32 is required for Windows Service support.")
        print("Install it with: pip install pywin32")
        return 1


def cmd_export_report(args: argparse.Namespace) -> int:
    """Export JSON/HTML/text report for a stored incident."""
    import json
    from pathlib import Path

    from scanner.reporting.renderer import (
        IncidentReport,
        build_plain_language_summary,
        render_html,
        render_json,
        render_text,
    )
    from scanner.storage.sqlite_store import SQLiteStorage

    db_path = Path(args.db)
    if not db_path.exists():
        print(f"Database not found: {db_path}")
        return 1

    storage = SQLiteStorage(db_path)
    storage.initialize()
    conn = storage.connection

    row = conn.execute(
        "SELECT incident_json FROM incident WHERE incident_id = ?",
        (args.incident,),
    ).fetchone()
    if row is None:
        print(f"Incident not found: {args.incident}")
        storage.close()
        return 1

    incident_data = json.loads(row["incident_json"])

    vr_rows = conn.execute(
        "SELECT adapter_name, verdict, evidence_json, ts, duration_ms FROM verification_result"
        " WHERE incident_id = ?",
        (args.incident,),
    ).fetchall()
    verify_results = [
        {
            "adapter_name": r["adapter_name"],
            "verdict": r["verdict"],
            "evidence": json.loads(r["evidence_json"]),
            "ts": r["ts"],
            "duration_ms": r["duration_ms"],
        }
        for r in vr_rows
    ]
    storage.close()

    summary = build_plain_language_summary(incident_data, verify_results)
    report = IncidentReport(
        incident_id=incident_data["incident_id"],
        severity=incident_data.get("severity", "unknown"),
        score=incident_data.get("score", 0),
        summary=summary,
        signals=incident_data.get("signals", []),
        verification_results=verify_results,
    )

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    base = out_dir / args.incident

    formats = [f.strip() for f in args.formats.split(",") if f.strip()]
    written = []
    if "json" in formats:
        p = base.with_suffix(".json")
        p.write_text(render_json(report), encoding="utf-8")
        written.append(str(p))
    if "html" in formats:
        p = base.with_suffix(".html")
        p.write_text(render_html(report), encoding="utf-8")
        written.append(str(p))
    if "text" in formats:
        p = base.with_suffix(".txt")
        p.write_text(render_text(report), encoding="utf-8")
        written.append(str(p))

    print("Report written:")
    for path in written:
        print(f"  {path}")
    return 0


def cmd_hub(args: argparse.Namespace) -> int:
    """Start the hub collector server."""
    _setup_logging(args.log_level)
    try:
        from scanner.hub.server import run_hub
        run_hub(
            host=args.host,
            port=args.port,
            api_key=args.api_key,
            data_dir=args.data_dir,
        )
    except ImportError as exc:
        print(f"Error: {exc}")
        return 1
    except ValueError as exc:
        print(f"Error: {exc}")
        return 1
    return 0


def cmd_gui(args: argparse.Namespace) -> int:
    """Launch the scanner GUI dashboard."""
    try:
        import tkinter  # noqa: F401
    except ImportError:
        print("Error: tkinter is not available in this Python installation.")
        return 1
    from scanner.gui.app import run_gui
    run_gui(db_path=args.db, report_dir=args.report_dir)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="Local process scanner – background security monitor.",
    )
    parser.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO)",
    )

    sub = parser.add_subparsers(dest="command")

    # run
    p_run = sub.add_parser("run", help="Run scanner in foreground mode")
    p_run.add_argument("--db", default="scanner.db", help="Database path")
    p_run.add_argument("--max-cycles", type=int, default=0,
                       help="Stop after N cycles (0 = unlimited)")
    p_run.add_argument("--hub-url", default="",
                       help="Hub server URL (e.g. http://192.168.1.10:8765)")
    p_run.add_argument("--hub-api-key", default="",
                       help="Hub API key")
    p_run.set_defaults(func=cmd_run)

    # status
    p_status = sub.add_parser("status", help="Show scanner status")
    p_status.add_argument("--db", default="scanner.db", help="Database path")
    p_status.set_defaults(func=cmd_status)

    # install-service
    p_install = sub.add_parser("install-service",
                               help="Install as Windows Service")
    p_install.set_defaults(func=cmd_install_service)

    # uninstall-service
    p_uninstall = sub.add_parser("uninstall-service",
                                 help="Uninstall Windows Service")
    p_uninstall.set_defaults(func=cmd_uninstall_service)

    # export-report
    p_export = sub.add_parser("export-report",
                              help="Export report for a stored incident")
    p_export.add_argument("--incident", required=True, help="Incident ID to export")
    p_export.add_argument("--db", default="scanner.db", help="Database path")
    p_export.add_argument("--out-dir", default="reports", help="Output directory")
    p_export.add_argument(
        "--formats", default="json,html",
        help="Comma-separated formats: json,html,text (default: json,html)",
    )
    p_export.set_defaults(func=cmd_export_report)

    # hub
    p_hub = sub.add_parser("hub", help="Start the hub collector server")
    p_hub.add_argument("--host", default="0.0.0.0", help="Bind address")
    p_hub.add_argument("--port", type=int, default=8765, help="Port (default 8765)")
    p_hub.add_argument("--api-key", required=True, help="Shared API key for agents")
    p_hub.add_argument("--data-dir", default="hub_data",
                       help="Directory for per-host SQLite files")
    p_hub.set_defaults(func=cmd_hub)

    # gui
    p_gui = sub.add_parser("gui", help="Launch the dashboard GUI")
    p_gui.add_argument("--db", default="scanner.db", help="Database path")
    p_gui.add_argument("--report-dir", default="reports", help="Reports directory")
    p_gui.set_defaults(func=cmd_gui)

    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 1

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
