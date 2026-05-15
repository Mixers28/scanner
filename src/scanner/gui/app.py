"""Scanner GUI — local security monitor dashboard.

Layout:
  ┌─ Status bar ──────────────────────────────────┐
  │  Mode  Cycles  Events  DB size                │
  ├─ Controls ────────────────────────────────────┤
  │  [Start]  [Stop]   Learning window: [7] days  │
  ├─ Incidents ───────────────────────────────────┤
  │  Time | Severity | Score | Signals            │
  │  ...                                          │
  ├───────────────────────────────────────────────┤
  │  [Open Report]  [Refresh]                     │
  └───────────────────────────────────────────────┘
"""

from __future__ import annotations

import json
import sqlite3
import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import ttk, messagebox
from typing import Any

from scanner.common.config import DEFAULT_CONFIG
from scanner.service.orchestrator import ScannerService

_REFRESH_MS = 3000
_SEVERITY_COLORS = {
    "critical": "#dc3545",
    "warning":  "#e0a000",
    "info":     "#17a2b8",
}
_SEVERITY_FG = {
    "critical": "white",
    "warning":  "white",
    "info":     "white",
}


class ScannerApp(tk.Tk):
    def __init__(self, db_path: str = "scanner.db", report_dir: str = "reports") -> None:
        super().__init__()
        self._db_path = Path(db_path)
        self._report_dir = Path(report_dir)
        self._svc_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._ready_event = threading.Event()
        self._learn_days: int = 7
        self._cached_status: dict = {}

        self.title("Scanner Security Monitor")
        self.resizable(True, True)
        self.minsize(640, 420)
        self._build_ui()
        self._schedule_refresh()

    # ── UI construction ──────────────────────────────────────────────

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        self._build_status_frame()
        self._build_controls_frame()
        self._build_incidents_frame()
        self._build_footer_frame()

    def _build_status_frame(self) -> None:
        frame = ttk.LabelFrame(self, text="Status", padding=8)
        frame.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 4))
        frame.columnconfigure((1, 3, 5, 7), weight=1)

        self._lbl_indicator = tk.Label(frame, text="●", font=("Segoe UI", 14),
                                       fg="#aaaaaa")
        self._lbl_indicator.grid(row=0, column=0, padx=(0, 6))

        ttk.Label(frame, text="Mode:").grid(row=0, column=1, sticky="e")
        self._lbl_mode = ttk.Label(frame, text="—", width=10)
        self._lbl_mode.grid(row=0, column=2, sticky="w", padx=(4, 12))

        ttk.Label(frame, text="Cycles:").grid(row=0, column=3, sticky="e")
        self._lbl_cycles = ttk.Label(frame, text="—", width=8)
        self._lbl_cycles.grid(row=0, column=4, sticky="w", padx=(4, 12))

        ttk.Label(frame, text="Events:").grid(row=0, column=5, sticky="e")
        self._lbl_events = ttk.Label(frame, text="—", width=8)
        self._lbl_events.grid(row=0, column=6, sticky="w", padx=(4, 12))

        ttk.Label(frame, text="DB:").grid(row=0, column=7, sticky="e")
        self._lbl_db = ttk.Label(frame, text=str(self._db_path), width=24,
                                 anchor="w")
        self._lbl_db.grid(row=0, column=8, sticky="w", padx=(4, 0))

    def _build_controls_frame(self) -> None:
        frame = ttk.Frame(self, padding=(10, 4))
        frame.grid(row=1, column=0, sticky="ew", padx=10)

        self._btn_start = ttk.Button(frame, text="▶  Start", width=12,
                                     command=self._on_start)
        self._btn_start.pack(side="left", padx=(0, 6))

        self._btn_stop = ttk.Button(frame, text="■  Stop", width=12,
                                    command=self._on_stop, state="disabled")
        self._btn_stop.pack(side="left", padx=(0, 20))

        ttk.Label(frame, text="Learning window:").pack(side="left")
        self._var_learn_days = tk.IntVar(value=7)
        self._spin_learn = ttk.Spinbox(
            frame, from_=1, to=30, width=4,
            textvariable=self._var_learn_days,
        )
        self._spin_learn.pack(side="left", padx=(4, 2))
        ttk.Label(frame, text="days  ").pack(side="left")

        self._lbl_learn_hint = ttk.Label(
            frame, text="(editable when stopped)", foreground="#888888",
        )
        self._lbl_learn_hint.pack(side="left")

    def _build_incidents_frame(self) -> None:
        frame = ttk.LabelFrame(self, text="Incidents", padding=8)
        frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=4)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        cols = ("time", "severity", "score", "signals", "incident_id")
        self._tree = ttk.Treeview(
            frame, columns=cols, show="headings", selectmode="browse",
        )
        self._tree.heading("time",        text="Time")
        self._tree.heading("severity",    text="Severity")
        self._tree.heading("score",       text="Score")
        self._tree.heading("signals",     text="Signals")
        self._tree.heading("incident_id", text="ID")

        self._tree.column("time",        width=160, minwidth=140, anchor="w")
        self._tree.column("severity",    width=90,  minwidth=70,  anchor="center")
        self._tree.column("score",       width=60,  minwidth=50,  anchor="center")
        self._tree.column("signals",     width=260, minwidth=160, anchor="w")
        self._tree.column("incident_id", width=0,   minwidth=0,   stretch=False)

        scrollbar = ttk.Scrollbar(frame, orient="vertical",
                                  command=self._tree.yview)
        self._tree.configure(yscrollcommand=scrollbar.set)

        self._tree.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        # Color tags per severity
        for sev, color in _SEVERITY_COLORS.items():
            self._tree.tag_configure(sev, background=color,
                                     foreground=_SEVERITY_FG[sev])

        self._tree.bind("<Double-1>", self._on_open_report)

    def _build_footer_frame(self) -> None:
        frame = ttk.Frame(self, padding=(10, 4))
        frame.grid(row=3, column=0, sticky="ew", padx=10, pady=(0, 10))

        ttk.Button(frame, text="Open Report", command=self._on_open_report) \
            .pack(side="left", padx=(0, 6))
        ttk.Button(frame, text="Refresh", command=self._refresh) \
            .pack(side="left")

        self._lbl_footer = ttk.Label(frame, text="", foreground="#888888")
        self._lbl_footer.pack(side="right")

    # ── service control ──────────────────────────────────────────────

    def _on_start(self) -> None:
        if self._svc_thread and self._svc_thread.is_alive():
            return
        try:
            learn_days = max(1, min(30, int(self._var_learn_days.get())))
        except (ValueError, tk.TclError):
            learn_days = 7
        self._learn_days = learn_days

        self._stop_event.clear()
        self._ready_event.clear()
        self._cached_status = {}

        self._svc_thread = threading.Thread(target=self._service_loop,
                                            daemon=True, name="scanner-svc")
        self._svc_thread.start()
        self._ready_event.wait(timeout=5.0)

        self._btn_start.configure(state="disabled")
        self._btn_stop.configure(state="normal")
        self._spin_learn.configure(state="disabled")
        self._lbl_learn_hint.configure(text="(restart to change)")
        self._lbl_footer.configure(
            text=f"Service started  —  learning window: {learn_days} day(s)."
        )

    def _on_stop(self) -> None:
        self._stop_event.set()
        self._cached_status = {}
        self._btn_start.configure(state="normal")
        self._btn_stop.configure(state="disabled")
        self._spin_learn.configure(state="normal")
        self._lbl_learn_hint.configure(text="(editable when stopped)")
        self._lbl_indicator.configure(fg="#aaaaaa")
        self._lbl_mode.configure(text="—")
        self._lbl_cycles.configure(text="—")
        self._lbl_events.configure(text="—")
        self._lbl_footer.configure(text="Service stopped.")

    def _service_loop(self) -> None:
        # ── Everything SQLite-related lives in this thread. ──
        config = dict(DEFAULT_CONFIG)
        config["baseline"] = dict(DEFAULT_CONFIG.get("baseline", {}))
        config["baseline"]["learning_window_days"] = getattr(self, "_learn_days", 7)
        config["reporting"] = dict(DEFAULT_CONFIG.get("reporting", {}))
        config["reporting"]["out_dir"] = str(self._report_dir)

        svc = ScannerService(db_path=self._db_path, config=config)
        svc.start()
        self._ready_event.set()

        interval = DEFAULT_CONFIG["collector"].get("process_poll_interval_seconds", 2)
        while not self._stop_event.is_set():
            try:
                svc.run_cycle()
                self._cached_status = svc.status()  # cache for main thread
            except Exception as exc:
                print(f"[scanner] cycle error: {exc}")
            self._stop_event.wait(interval)

        svc.stop()

    # ── refresh / display ────────────────────────────────────────────

    def _schedule_refresh(self) -> None:
        self.after(_REFRESH_MS, self._tick)

    def _tick(self) -> None:
        self._refresh()
        self.after(_REFRESH_MS, self._tick)

    def _refresh(self) -> None:
        self._update_status()
        self._update_incidents()

    def _update_status(self) -> None:
        s = self._cached_status
        if not s:
            return
        self._lbl_indicator.configure(fg="#28a745")
        self._lbl_mode.configure(text=s.get("mode", "—").upper())
        self._lbl_cycles.configure(text=f"{s.get('cycle_count', 0):,}")
        self._lbl_events.configure(text=f"{s.get('total_events', 0):,}")

    def _update_incidents(self) -> None:
        if not self._db_path.exists():
            return
        try:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT incident_json FROM incident ORDER BY updated_ts DESC LIMIT 200"
            ).fetchall()
            conn.close()
        except Exception:
            return

        incidents = []
        for r in rows:
            try:
                incidents.append(json.loads(r["incident_json"]))
            except Exception:
                pass

        # Rebuild treeview
        for item in self._tree.get_children():
            self._tree.delete(item)

        for inc in incidents:
            sev = inc.get("severity", "info")
            score = inc.get("score", 0)
            ts = inc.get("updated_ts", inc.get("created_ts", ""))[:19].replace("T", " ")
            signal_codes = ", ".join(
                s.get("code", "") for s in inc.get("signals", [])
            )
            self._tree.insert(
                "", "end",
                values=(ts, sev.upper(), score, signal_codes, inc.get("incident_id", "")),
                tags=(sev,),
            )

    # ── report viewer ────────────────────────────────────────────────

    def _on_open_report(self, _event: Any = None) -> None:
        sel = self._tree.selection()
        if not sel:
            messagebox.showinfo("No selection", "Select an incident first.")
            return
        values = self._tree.item(sel[0], "values")
        incident_id = values[4] if len(values) > 4 else ""
        if not incident_id:
            return

        html_path = self._report_dir / f"{incident_id}.html"
        if html_path.exists():
            webbrowser.open(html_path.as_uri())
        else:
            messagebox.showwarning(
                "Report not found",
                f"No HTML report found for this incident.\n\n"
                f"Expected: {html_path}\n\n"
                f"The report is generated when an incident is detected while the service is running.",
            )


def run_gui(db_path: str = "scanner.db", report_dir: str = "reports") -> None:
    app = ScannerApp(db_path=db_path, report_dir=report_dir)
    app.mainloop()
