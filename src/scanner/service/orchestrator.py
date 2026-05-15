"""Service orchestrator – wires module lifecycle, scheduling, and health.

Coordinates: storage init → collector polling → baseline ingestion →
anomaly evaluation → verification → reporting → retention cleanup.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from scanner.common.config import DEFAULT_CONFIG, validate_config
from scanner.common.identity import build_identity_key, normalize_windows_path
from scanner.storage.sqlite_store import SQLiteStorage
from scanner.collector.process_collector import ProcessCollector
from scanner.collector.resource_collector import collect_resource_samples
from scanner.collector.network_collector import collect_network_connections
from scanner.collector.rate_limiter import EventRateLimiter, cleanup_old_telemetry
from scanner.baseline.mode import BaselineMode, BaselineModeManager
from scanner.baseline.stats import BaselineAggregator, compute_confidence
from scanner.baseline.snapshot import BaselineSnapshotStore
from scanner.anomaly.signals import evaluate_signals
from scanner.anomaly.scoring import score_signals
from scanner.anomaly.incidents import IncidentManager
from scanner.verify.adapters import create_default_registry
from scanner.verify.cache import VerificationCache, run_verification_with_budget
from scanner.agent.push import HubPushClient
from scanner.reporting.renderer import (
    IncidentReport,
    build_plain_language_summary,
    render_json,
    render_html,
    render_text,
)

logger = logging.getLogger(__name__)


class ScannerService:
    """Main orchestrator for the scanner background service."""

    def __init__(
        self,
        db_path: str | Path = "scanner.db",
        config: dict[str, Any] | None = None,
        host_id: str = "",
        hub_url: str = "",
        hub_api_key: str = "",
    ) -> None:
        self._config = validate_config(config or DEFAULT_CONFIG)
        self._db_path = Path(db_path)
        self._host_id = host_id or platform.node() or "localhost"
        self._hub_url = hub_url
        self._hub_api_key = hub_api_key
        self._running = False
        self._stop_event = threading.Event()

        # Initialized in start()
        self._push_client: HubPushClient | None = None
        self._storage: SQLiteStorage | None = None
        self._process_collector: ProcessCollector | None = None
        self._rate_limiter: EventRateLimiter | None = None
        self._mode_manager: BaselineModeManager | None = None
        self._aggregator: BaselineAggregator | None = None
        self._snapshot_store: BaselineSnapshotStore | None = None
        self._incident_manager: IncidentManager | None = None
        self._verify_cache: VerificationCache | None = None
        self._verify_registry = create_default_registry(
            self._config["verify"].get("adapters_enabled"),
        )
        self._last_resource_poll_at: float | None = None
        self._last_network_poll_at: float | None = None

        # Counters for health/status
        self._cycle_count: int = 0
        self._total_events: int = 0
        self._total_incidents: int = 0
        self._started_ts: str = ""

    # ── lifecycle ──────────────────────────────────────────────────

    def start(self) -> None:
        """Initialize all subsystems."""
        logger.info("Starting scanner service (host=%s, db=%s)", self._host_id, self._db_path)
        self._storage = SQLiteStorage(self._db_path)
        self._storage.initialize()
        conn = self._storage.connection

        coll_cfg = self._config["collector"]
        self._process_collector = ProcessCollector(self._host_id)
        self._rate_limiter = EventRateLimiter(coll_cfg["max_events_per_minute"])

        bl_cfg = self._config.get("baseline", {})
        self._mode_manager = BaselineModeManager(
            conn, self._host_id,
            learning_window_days=bl_cfg.get("learning_window_days", 7),
        )
        self._aggregator = BaselineAggregator()
        self._snapshot_store = BaselineSnapshotStore(conn, self._host_id)

        anomaly_cfg = self._config.get("anomaly", {})
        self._incident_manager = IncidentManager(
            conn, self._host_id,
            cooldown_minutes=anomaly_cfg.get("cooldown_minutes", 30),
        )

        verify_cfg = self._config["verify"]
        self._verify_cache = VerificationCache(
            conn, ttl_days=verify_cfg.get("cache_ttl_days", 7),
        )

        if self._hub_url and self._hub_api_key:
            self._push_client = HubPushClient(
                hub_url=self._hub_url,
                api_key=self._hub_api_key,
                db_path=self._db_path,
            )
            self._push_client.start()
            logger.info("Hub push client enabled (hub=%s)", self._hub_url)

        self._running = True
        self._started_ts = datetime.now(timezone.utc).isoformat()
        self._stop_event.clear()
        self._persist_status_snapshot()
        logger.info("Scanner service started")

    def stop(self) -> None:
        """Shut down gracefully."""
        logger.info("Stopping scanner service")
        self._running = False
        self._stop_event.set()
        if self._push_client:
            self._push_client.stop()
            self._push_client = None
        self._last_resource_poll_at = None
        self._last_network_poll_at = None
        self._persist_status_snapshot(running=False)
        if self._storage:
            self._storage.close()
            self._storage = None
        logger.info("Scanner service stopped")

    @property
    def is_running(self) -> bool:
        return self._running

    # ── single poll cycle ──────────────────────────────────────────

    def run_cycle(self) -> dict[str, int]:
        """Execute one poll cycle: collect → ingest → detect → verify → report.

        Returns a summary dict of events/incidents for the cycle.
        """
        if not self._running or self._storage is None:
            raise RuntimeError("Service is not started")

        conn = self._storage.connection
        coll_cfg = self._config["collector"]
        now = datetime.now(timezone.utc)
        stats = {"events": 0, "incidents_created": 0}

        # 1. Collect
        started, stopped = self._process_collector.snapshot()
        resource_events: list[Any] = []
        network_events: list[Any] = []

        if self._collector_due("resource", coll_cfg["resource_poll_interval_seconds"]):
            resource_events = collect_resource_samples(self._host_id)
        if self._collector_due("network", coll_cfg["network_poll_interval_seconds"]):
            network_events = collect_network_connections(self._host_id)

        all_events = started + stopped + resource_events + network_events
        accepted = self._rate_limiter.filter(all_events)
        self._storage.persist_events(accepted)
        stats["events"] = len(accepted)
        self._total_events += len(accepted)

        # 2. Baseline ingestion (learning mode only)
        mode = self._mode_manager.current_mode(now)
        if mode == BaselineMode.LEARNING:
            for ev in accepted:
                self._aggregator.ingest(ev.event_type, ev.payload, ev.ts)

        # 3. Anomaly detection (monitor mode only)
        if mode == BaselineMode.MONITOR:
            # Load latest baseline snapshot
            latest_ver = self._snapshot_store.latest_version()
            if latest_ver is not None:
                profiles = self._snapshot_store.load_snapshot(latest_ver)
            else:
                profiles = {}

            for ev in accepted:
                if ev.event_type not in ("process_start", "net_conn", "resource_sample"):
                    continue
                identity_key = ev.payload.get("identity_key", "")
                if not identity_key:
                    continue

                recent_launch_count = 0
                if ev.event_type == "process_start":
                    recent_launch_count = self._count_recent_launches(
                        identity_key,
                        window_minutes=10,
                    )

                signals = evaluate_signals(
                    identity_key,
                    ev.payload,
                    profiles,
                    recent_launch_count=recent_launch_count,
                    launch_window_minutes=10,
                )
                if not signals:
                    continue

                scoring = score_signals(signals, ev.payload)
                incident = self._incident_manager.process_scoring(identity_key, scoring, now)
                if incident:
                    stats["incidents_created"] += 1
                    self._total_incidents += 1

                    if self._push_client:
                        self._push_client.queue_incident(conn, incident.to_dict())

                    # 4. Verify
                    image_path = ev.payload.get("image_path", "")
                    file_hash = ev.payload.get("file_hash", "")
                    verify_results = run_verification_with_budget(
                        self._verify_registry, image_path, file_hash,
                        cache=self._verify_cache,
                        budget_seconds=self._config["verify"]["total_timeout_seconds"],
                    )
                    self._storage.persist_verification_results(
                        incident.incident_id,
                        verify_results,
                    )

                    # 5. Report
                    self._generate_report(incident.to_dict(), verify_results)

        self._cycle_count += 1
        self._persist_status_snapshot()
        return stats

    def _collector_due(self, collector_name: str, interval_seconds: int) -> bool:
        now_monotonic = time.monotonic()
        last_attr = f"_last_{collector_name}_poll_at"
        last_polled_at = getattr(self, last_attr)
        if last_polled_at is not None and (now_monotonic - last_polled_at) < interval_seconds:
            return False
        setattr(self, last_attr, now_monotonic)
        return True

    def _count_recent_launches(self, identity_key: str, window_minutes: int) -> int:
        if not self._storage:
            return 0

        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        rows = self._storage.connection.execute(
            """
            SELECT payload_json
            FROM telemetry_event
            WHERE host_id = ? AND event_type = ? AND ts >= ?
            """,
            (self._host_id, "process_start", cutoff.isoformat()),
        ).fetchall()
        count = 0
        for row in rows:
            payload = json.loads(row["payload_json"])
            if payload.get("identity_key") == identity_key:
                count += 1
        return count

    def _generate_report(self, incident_data: dict, verify_results: list) -> None:
        """Generate and save incident report."""
        vr_dicts = [vr.to_dict() for vr in verify_results]
        summary = build_plain_language_summary(incident_data, vr_dicts)
        report = IncidentReport(
            incident_id=incident_data["incident_id"],
            severity=incident_data["severity"],
            score=incident_data["score"],
            summary=summary,
            signals=incident_data.get("signals", []),
            verification_results=vr_dicts,
        )

        out_dir = Path(self._config["reporting"].get("out_dir", "reports"))
        out_dir.mkdir(parents=True, exist_ok=True)
        base = out_dir / incident_data["incident_id"]

        formats = self._config["reporting"].get("formats", ["json", "html"])
        if "json" in formats:
            (base.with_suffix(".json")).write_text(render_json(report), encoding="utf-8")
        if "html" in formats:
            (base.with_suffix(".html")).write_text(render_html(report), encoding="utf-8")
        if "text" in formats:
            (base.with_suffix(".txt")).write_text(render_text(report), encoding="utf-8")

    # ── retention ──────────────────────────────────────────────────

    def run_retention(self) -> dict[str, int]:
        """Run retention cleanup jobs. Returns counts of deleted items."""
        if not self._storage:
            return {}
        conn = self._storage.connection
        ret = self._config["retention"]

        deleted_telemetry = cleanup_old_telemetry(conn, ret["telemetry_days"])

        snap = self._snapshot_store
        deleted_baselines = snap.prune_old_versions(ret.get("max_baseline_versions", 10)) if snap else 0

        return {
            "deleted_telemetry": deleted_telemetry,
            "deleted_baselines": deleted_baselines,
        }

    # ── baseline commit ────────────────────────────────────────────

    def commit_baseline(self) -> int | None:
        """Save current aggregator state as a new baseline snapshot.

        Called at end of learning period or manually.
        Returns the new version number, or None if nothing to commit.
        """
        if not self._aggregator or not self._snapshot_store:
            return None
        profiles = self._aggregator.profiles
        if not profiles:
            return None

        latest = self._snapshot_store.latest_version()
        new_version = (latest or 0) + 1
        self._snapshot_store.save_snapshot(new_version, profiles)
        logger.info("Committed baseline version %d with %d profiles", new_version, len(profiles))
        return new_version

    # ── status / health ────────────────────────────────────────────

    def status(self) -> dict[str, Any]:
        """Return current service status for CLI/monitoring."""
        mode = "unknown"
        if self._mode_manager:
            mode = self._mode_manager.current_mode().value

        return {
            "running": self._running,
            "host_id": self._host_id,
            "started_ts": self._started_ts,
            "updated_ts": datetime.now(timezone.utc).isoformat(),
            "mode": mode,
            "cycle_count": self._cycle_count,
            "total_events": self._total_events,
            "total_incidents": self._total_incidents,
            "db_path": str(self._db_path),
            "rate_limiter_dropped": self._rate_limiter.total_dropped if self._rate_limiter else 0,
        }

    def _persist_status_snapshot(self, running: bool | None = None) -> None:
        if not self._storage:
            return
        snapshot = self.status()
        if running is not None:
            snapshot["running"] = running
        self._storage.persist_status(snapshot)


# ── foreground run loop ──────────────────────────────────────────

def run_foreground(
    db_path: str = "scanner.db",
    config: dict[str, Any] | None = None,
    max_cycles: int = 0,
    hub_url: str = "",
    hub_api_key: str = "",
) -> ScannerService:
    """Run the scanner in foreground CLI mode.

    If max_cycles > 0, stops after that many cycles (useful for testing).
    Otherwise runs until interrupted.
    """
    svc = ScannerService(
        db_path=db_path, config=config,
        hub_url=hub_url, hub_api_key=hub_api_key,
    )
    svc.start()

    coll_cfg = (config or DEFAULT_CONFIG)["collector"]
    interval = coll_cfg.get("process_poll_interval_seconds", 2)
    cycles = 0

    try:
        while svc.is_running:
            svc.run_cycle()
            cycles += 1
            if max_cycles and cycles >= max_cycles:
                break
            svc._stop_event.wait(timeout=interval)
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        svc.stop()

    return svc
