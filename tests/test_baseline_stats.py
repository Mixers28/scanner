"""Tests for S2-T2: Baseline statistics and confidence scoring."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scanner.baseline.stats import (
    ResourceStats,
    IdentityProfile,
    BaselineAggregator,
    compute_confidence,
)


class ResourceStatsTests(unittest.TestCase):
    def test_percentiles_empty(self) -> None:
        rs = ResourceStats()
        self.assertEqual(rs.cpu_percentiles()["p50"], 0.0)

    def test_percentiles_single(self) -> None:
        rs = ResourceStats()
        rs.add(10.0, 1024)
        self.assertAlmostEqual(rs.cpu_percentiles()["p50"], 10.0)
        self.assertAlmostEqual(rs.mem_percentiles()["p50"], 1024.0)

    def test_percentiles_multiple(self) -> None:
        rs = ResourceStats()
        for v in range(1, 101):
            rs.add(float(v), v * 100)
        cpu = rs.cpu_percentiles()
        self.assertAlmostEqual(cpu["p50"], 50.5)
        self.assertAlmostEqual(cpu["p90"], 90.1, places=0)
        self.assertGreater(cpu["p99"], 98.0)

    def test_to_dict_shape(self) -> None:
        rs = ResourceStats()
        rs.add(5.0, 2048)
        d = rs.to_dict()
        self.assertIn("cpu", d)
        self.assertIn("mem", d)
        self.assertEqual(d["cpu_sample_count"], 1)


class IdentityProfileTests(unittest.TestCase):
    def test_record_launch(self) -> None:
        p = IdentityProfile(identity_key="k1")
        p.record_launch("2026-01-01T00:00:00", parent_key="pk1")
        p.record_launch("2026-01-02T00:00:00", parent_key="pk2")
        self.assertEqual(p.launch_count, 2)
        self.assertEqual(p.first_seen_ts, "2026-01-01T00:00:00")
        self.assertEqual(p.last_seen_ts, "2026-01-02T00:00:00")
        self.assertEqual(p.parent_keys, {"pk1", "pk2"})

    def test_record_network(self) -> None:
        p = IdentityProfile(identity_key="k1")
        p.record_network("8.8.8.8", 53)
        p.record_network("8.8.8.8", 53)  # duplicate
        self.assertEqual(len(p.network_destinations), 1)

    def test_roundtrip_dict(self) -> None:
        p = IdentityProfile(identity_key="k1")
        p.record_launch("2026-01-01T00:00:00")
        p.record_resource(5.0, 1024)
        d = p.to_dict()
        p2 = IdentityProfile.from_dict(d)
        self.assertEqual(p2.identity_key, "k1")
        self.assertEqual(p2.launch_count, 1)

    def test_reproducibility(self) -> None:
        """Same input stream produces same profile dict."""
        events = [
            ("2026-01-01T00:00:00", "pk1"),
            ("2026-01-02T00:00:00", "pk2"),
        ]
        p1 = IdentityProfile(identity_key="k1")
        p2 = IdentityProfile(identity_key="k1")
        for ts, pk in events:
            p1.record_launch(ts, pk)
            p2.record_launch(ts, pk)
        self.assertEqual(p1.to_dict(), p2.to_dict())


class ComputeConfidenceTests(unittest.TestCase):
    def test_zero_observations(self) -> None:
        p = IdentityProfile(identity_key="k1")
        self.assertEqual(compute_confidence(p), 0.0)

    def test_full_confidence(self) -> None:
        p = IdentityProfile(identity_key="k1")
        for i in range(30):
            p.record_launch(f"2026-01-{i+1:02d}T00:00:00", "parent")
            p.record_resource(5.0, 1024)
        p.record_network("1.2.3.4", 80)
        c = compute_confidence(p, min_samples=30)
        self.assertAlmostEqual(c, 1.0)

    def test_partial_confidence(self) -> None:
        p = IdentityProfile(identity_key="k1")
        for i in range(15):
            p.record_launch(f"2026-01-{i+1:02d}T00:00:00")
        c = compute_confidence(p, min_samples=30)
        # 15/30 * 0.4 = 0.2, no resource/parent/net
        self.assertAlmostEqual(c, 0.2)

    def test_confidence_clamped_at_one(self) -> None:
        p = IdentityProfile(identity_key="k1")
        for i in range(100):
            p.record_launch(f"2026-01-01T{i:04d}", "parent")
            p.record_resource(5.0, 1024)
        p.record_network("1.2.3.4", 80)
        c = compute_confidence(p, min_samples=10)
        self.assertLessEqual(c, 1.0)


class BaselineAggregatorTests(unittest.TestCase):
    def test_ingest_process_start(self) -> None:
        agg = BaselineAggregator()
        agg.ingest("process_start", {"identity_key": "k1"}, "2026-01-01T00:00:00")
        self.assertIn("k1", agg.profiles)
        self.assertEqual(agg.profiles["k1"].launch_count, 1)

    def test_ingest_resource_sample(self) -> None:
        agg = BaselineAggregator()
        agg.ingest("resource_sample", {
            "identity_key": "k1", "cpu_percent": 3.5, "memory_rss_bytes": 4096,
        }, "2026-01-01T00:00:00")
        self.assertEqual(len(agg.profiles["k1"].resource.cpu_samples), 1)

    def test_ingest_net_conn(self) -> None:
        agg = BaselineAggregator()
        agg.ingest("net_conn", {
            "identity_key": "k1", "remote_ip": "8.8.8.8", "remote_port": 53,
        }, "2026-01-01T00:00:00")
        self.assertIn("8.8.8.8:53", agg.profiles["k1"].network_destinations)

    def test_skips_empty_identity(self) -> None:
        agg = BaselineAggregator()
        agg.ingest("process_start", {}, "2026-01-01T00:00:00")
        self.assertEqual(len(agg.profiles), 0)

    def test_mixed_stream_reproducible(self) -> None:
        events = [
            ("process_start", {"identity_key": "k1"}, "2026-01-01T00:00:00"),
            ("resource_sample", {"identity_key": "k1", "cpu_percent": 2.0, "memory_rss_bytes": 512}, "2026-01-01T01:00:00"),
            ("net_conn", {"identity_key": "k1", "remote_ip": "10.0.0.1", "remote_port": 443}, "2026-01-01T02:00:00"),
            ("process_start", {"identity_key": "k2"}, "2026-01-01T03:00:00"),
        ]
        agg1 = BaselineAggregator()
        agg2 = BaselineAggregator()
        for et, payload, ts in events:
            agg1.ingest(et, payload, ts)
            agg2.ingest(et, payload, ts)

        for key in agg1.profiles:
            self.assertEqual(agg1.profiles[key].to_dict(), agg2.profiles[key].to_dict())


if __name__ == "__main__":
    unittest.main()
