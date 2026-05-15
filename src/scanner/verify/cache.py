"""Verification cache and timeout-budgeted orchestration.

SPEC §5.5:
  - Cache verification results by file hash with 7-day default TTL.
  - Total verification budget: 30 seconds per incident (configurable).
  - Timeout returns partial results safely.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from scanner.verify.adapters import (
    AdapterRegistry,
    VerificationResult,
)
from scanner.common.types import Verdict

logger = logging.getLogger(__name__)


class VerificationCache:
    """In-memory + SQLite-backed cache keyed by file hash."""

    def __init__(self, conn: Any, ttl_days: int = 7) -> None:
        self._conn = conn
        self._ttl = timedelta(days=ttl_days)
        self._ensure_table()

    def _ensure_table(self) -> None:
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS verification_cache (
                file_hash TEXT PRIMARY KEY,
                result_json TEXT NOT NULL,
                cached_ts TEXT NOT NULL
            )
        """)
        self._conn.commit()

    def get(self, file_hash: str, now: datetime | None = None) -> VerificationResult | None:
        """Return cached result if not expired, else None."""
        if not file_hash:
            return None
        now = now or datetime.now(timezone.utc)
        row = self._conn.execute(
            "SELECT result_json, cached_ts FROM verification_cache WHERE file_hash = ?",
            (file_hash,),
        ).fetchone()
        if row is None:
            return None
        cached_ts = datetime.fromisoformat(row["cached_ts"])
        if now - cached_ts > self._ttl:
            self._conn.execute("DELETE FROM verification_cache WHERE file_hash = ?", (file_hash,))
            self._conn.commit()
            return None
        return VerificationResult.from_dict(json.loads(row["result_json"]))

    def put(self, file_hash: str, result: VerificationResult, now: datetime | None = None) -> None:
        """Store a verification result in the cache."""
        if not file_hash:
            return
        now = now or datetime.now(timezone.utc)
        self._conn.execute(
            "INSERT OR REPLACE INTO verification_cache (file_hash, result_json, cached_ts) VALUES (?, ?, ?)",
            (file_hash, json.dumps(result.to_dict()), now.isoformat()),
        )
        self._conn.commit()


def run_verification_with_budget(
    registry: AdapterRegistry,
    image_path: str,
    file_hash: str = "",
    cache: VerificationCache | None = None,
    budget_seconds: float = 30.0,
) -> list[VerificationResult]:
    """Run all adapters within a time budget, using cache when available.

    Returns partial results if the budget expires mid-run.
    """
    results: list[VerificationResult] = []

    # Check cache first
    if cache and file_hash:
        cached = cache.get(file_hash)
        if cached is not None:
            logger.debug("Cache hit for %s", file_hash)
            return [cached]

    deadline = time.monotonic() + budget_seconds
    adapter_names = registry.list_adapters()

    for name in adapter_names:
        if time.monotonic() >= deadline:
            logger.warning("Verification budget exhausted after %d/%d adapters", len(results), len(adapter_names))
            break

        adapter = registry.get(name)
        if adapter is None:
            continue

        result = adapter.safe_check(image_path, file_hash)
        results.append(result)

    # Cache only conclusive results so UNKNOWN does not suppress future checks.
    if cache and file_hash and results:
        best = next(
            (
                r for r in results
                if r.verdict in (Verdict.CLEAN, Verdict.SUSPICIOUS, Verdict.MALICIOUS)
            ),
            None,
        )
        if best:
            cache.put(file_hash, best)

    return results
