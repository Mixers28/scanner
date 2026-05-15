"""Tests for S5-T2: Verification cache and timeout budget."""

import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scanner.common.types import Verdict
from scanner.verify.adapters import (
    VerificationResult,
    VerificationAdapter,
    AdapterRegistry,
    create_default_registry,
)
from scanner.verify.cache import VerificationCache, run_verification_with_budget
from scanner.storage import SQLiteStorage


class VerificationCacheTests(unittest.TestCase):
    def _make_cache(self, tmpdir: str, ttl_days: int = 7) -> tuple:
        store = SQLiteStorage(Path(tmpdir) / "test.db")
        store.initialize()
        cache = VerificationCache(store.connection, ttl_days)
        return store, cache

    def test_put_and_get(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, cache = self._make_cache(tmpdir)
            result = VerificationResult("sig", Verdict.CLEAN, {"k": "v"})
            cache.put("hash1", result)

            cached = cache.get("hash1")
            self.assertIsNotNone(cached)
            self.assertEqual(cached.verdict, Verdict.CLEAN)
            self.assertEqual(cached.evidence["k"], "v")
            store.close()

    def test_miss_returns_none(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, cache = self._make_cache(tmpdir)
            self.assertIsNone(cache.get("nonexistent"))
            store.close()

    def test_expired_entry_returns_none(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, cache = self._make_cache(tmpdir, ttl_days=7)
            past = datetime(2025, 1, 1, tzinfo=timezone.utc)
            result = VerificationResult("sig", Verdict.CLEAN)
            cache.put("hash1", result, now=past)

            now = datetime(2026, 2, 1, tzinfo=timezone.utc)
            cached = cache.get("hash1", now=now)
            self.assertIsNone(cached)
            store.close()

    def test_within_ttl_returns_cached(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, cache = self._make_cache(tmpdir, ttl_days=7)
            now = datetime(2026, 2, 1, tzinfo=timezone.utc)
            result = VerificationResult("sig", Verdict.SUSPICIOUS)
            cache.put("hash1", result, now=now)

            later = now + timedelta(days=3)
            cached = cache.get("hash1", now=later)
            self.assertIsNotNone(cached)
            self.assertEqual(cached.verdict, Verdict.SUSPICIOUS)
            store.close()

    def test_empty_hash_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store, cache = self._make_cache(tmpdir)
            cache.put("", VerificationResult("sig", Verdict.CLEAN))
            self.assertIsNone(cache.get(""))
            store.close()


class RunVerificationWithBudgetTests(unittest.TestCase):
    def test_uses_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = SQLiteStorage(Path(tmpdir) / "test.db")
            store.initialize()
            cache = VerificationCache(store.connection)
            cached_result = VerificationResult("sig", Verdict.CLEAN, {"cached": "true"})
            cache.put("hash1", cached_result)

            registry = create_default_registry()
            results = run_verification_with_budget(
                registry, "", file_hash="hash1", cache=cache,
            )
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].evidence.get("cached"), "true")
            store.close()

    def test_runs_without_cache(self) -> None:
        registry = create_default_registry()
        results = run_verification_with_budget(registry, "")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].adapter_name, "signature")

    def test_caches_result_after_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = SQLiteStorage(Path(tmpdir) / "test.db")
            store.initialize()
            cache = VerificationCache(store.connection)

            class CleanAdapter(VerificationAdapter):
                @property
                def name(self) -> str:
                    return "clean"

                def check(self, image_path: str, file_hash: str = "") -> VerificationResult:
                    return VerificationResult("clean", Verdict.CLEAN)

            registry = AdapterRegistry()
            registry.register(CleanAdapter())
            run_verification_with_budget(
                registry, "", file_hash="newhash", cache=cache,
            )
            cached = cache.get("newhash")
            self.assertIsNotNone(cached)
            store.close()

    def test_unknown_results_not_cached(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = SQLiteStorage(Path(tmpdir) / "test.db")
            store.initialize()
            cache = VerificationCache(store.connection)

            registry = create_default_registry()
            run_verification_with_budget(
                registry, "", file_hash="unknownhash", cache=cache,
            )
            self.assertIsNone(cache.get("unknownhash"))
            store.close()

    def test_budget_returns_partial(self) -> None:
        class SlowAdapter(VerificationAdapter):
            @property
            def name(self) -> str:
                return "slow"
            def check(self, image_path: str, file_hash: str = "") -> VerificationResult:
                time.sleep(0.5)
                return VerificationResult("slow", Verdict.CLEAN)

        registry = AdapterRegistry()
        for i in range(10):
            # Create unique adapters
            adapter = SlowAdapter()
            adapter._name = f"slow_{i}"
            type(adapter).name = property(lambda self, n=f"slow_{i}": n)
            registry.register(adapter)

        results = run_verification_with_budget(
            registry, "", budget_seconds=0.8,
        )
        # Should get fewer than 10 results due to budget
        self.assertLess(len(results), 10)
        self.assertGreater(len(results), 0)

    def test_no_error_results_not_cached(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = SQLiteStorage(Path(tmpdir) / "test.db")
            store.initialize()
            cache = VerificationCache(store.connection)

            class ErrorAdapter(VerificationAdapter):
                @property
                def name(self) -> str:
                    return "err"
                def check(self, image_path: str, file_hash: str = "") -> VerificationResult:
                    raise RuntimeError("fail")

            registry = AdapterRegistry()
            registry.register(ErrorAdapter())
            run_verification_with_budget(
                registry, "", file_hash="h1", cache=cache,
            )
            # Error results should not be cached
            self.assertIsNone(cache.get("h1"))
            store.close()


if __name__ == "__main__":
    unittest.main()
