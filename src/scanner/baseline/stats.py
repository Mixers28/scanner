"""Per-identity baseline statistics and confidence scoring.

Consumes telemetry events and builds a behavioral profile per process
identity key.  Profiles track:
  - launch frequency (count, first/last seen)
  - parent process patterns (set of parent identity keys)
  - network destination norms (set of remote_ip:port tuples)
  - resource percentiles (p50, p90, p99 for CPU and memory)

Confidence grows with observation count relative to a configurable
minimum sample threshold.
"""

from __future__ import annotations

import json
import math
import statistics
from dataclasses import dataclass, field, asdict
from typing import Any, Sequence


@dataclass
class ResourceStats:
    """Aggregated resource metrics."""
    cpu_samples: list[float] = field(default_factory=list)
    mem_samples: list[int] = field(default_factory=list)
    cpu_percentile_cache: dict[str, float] = field(default_factory=dict)
    mem_percentile_cache: dict[str, float] = field(default_factory=dict)
    cpu_sample_count_cache: int = 0
    mem_sample_count_cache: int = 0

    def add(self, cpu: float, mem: int) -> None:
        self.cpu_percentile_cache = {}
        self.mem_percentile_cache = {}
        self.cpu_sample_count_cache = 0
        self.mem_sample_count_cache = 0
        self.cpu_samples.append(cpu)
        self.mem_samples.append(mem)

    def percentile(self, data: Sequence[float | int], pct: float) -> float:
        if not data:
            return 0.0
        sorted_data = sorted(data)
        k = (len(sorted_data) - 1) * (pct / 100.0)
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return float(sorted_data[int(k)])
        return float(sorted_data[f]) * (c - k) + float(sorted_data[c]) * (k - f)

    def cpu_percentiles(self) -> dict[str, float]:
        if not self.cpu_samples and self.cpu_percentile_cache:
            return dict(self.cpu_percentile_cache)
        return {
            "p50": self.percentile(self.cpu_samples, 50),
            "p90": self.percentile(self.cpu_samples, 90),
            "p99": self.percentile(self.cpu_samples, 99),
        }

    def mem_percentiles(self) -> dict[str, float]:
        if not self.mem_samples and self.mem_percentile_cache:
            return dict(self.mem_percentile_cache)
        return {
            "p50": self.percentile(self.mem_samples, 50),
            "p90": self.percentile(self.mem_samples, 90),
            "p99": self.percentile(self.mem_samples, 99),
        }

    def to_dict(self) -> dict[str, Any]:
        cpu_sample_count = len(self.cpu_samples) or self.cpu_sample_count_cache
        mem_sample_count = len(self.mem_samples) or self.mem_sample_count_cache
        return {
            "cpu": self.cpu_percentiles(),
            "mem": self.mem_percentiles(),
            "cpu_sample_count": cpu_sample_count,
            "mem_sample_count": mem_sample_count,
        }


@dataclass
class IdentityProfile:
    """Behavioral profile for a single process identity key."""
    identity_key: str
    launch_count: int = 0
    first_seen_ts: str = ""
    last_seen_ts: str = ""
    parent_keys: set[str] = field(default_factory=set)
    network_destinations: set[str] = field(default_factory=set)
    resource: ResourceStats = field(default_factory=ResourceStats)

    def record_launch(self, ts: str, parent_key: str = "") -> None:
        self.launch_count += 1
        if not self.first_seen_ts or ts < self.first_seen_ts:
            self.first_seen_ts = ts
        if not self.last_seen_ts or ts > self.last_seen_ts:
            self.last_seen_ts = ts
        if parent_key:
            self.parent_keys.add(parent_key)

    def record_network(self, remote_ip: str, remote_port: int) -> None:
        self.network_destinations.add(f"{remote_ip}:{remote_port}")

    def record_resource(self, cpu: float, mem: int) -> None:
        self.resource.add(cpu, mem)

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity_key": self.identity_key,
            "launch_count": self.launch_count,
            "first_seen_ts": self.first_seen_ts,
            "last_seen_ts": self.last_seen_ts,
            "parent_keys": sorted(self.parent_keys),
            "network_destinations": sorted(self.network_destinations),
            "resource": self.resource.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IdentityProfile:
        profile = cls(identity_key=data["identity_key"])
        profile.launch_count = data.get("launch_count", 0)
        profile.first_seen_ts = data.get("first_seen_ts", "")
        profile.last_seen_ts = data.get("last_seen_ts", "")
        profile.parent_keys = set(data.get("parent_keys", []))
        profile.network_destinations = set(data.get("network_destinations", []))
        res = data.get("resource", {})
        profile.resource.cpu_samples = res.get("cpu_samples", [])
        profile.resource.mem_samples = res.get("mem_samples", [])
        profile.resource.cpu_percentile_cache = dict(res.get("cpu", {}))
        profile.resource.mem_percentile_cache = dict(res.get("mem", {}))
        profile.resource.cpu_sample_count_cache = int(res.get("cpu_sample_count", 0))
        profile.resource.mem_sample_count_cache = int(res.get("mem_sample_count", 0))
        return profile


def compute_confidence(
    profile: IdentityProfile,
    min_samples: int = 30,
) -> float:
    """Compute confidence score in [0.0, 1.0].

    Confidence is based on observation richness:
      - launch count relative to min_samples (weight 0.4)
      - resource sample count relative to min_samples (weight 0.3)
      - parent diversity >= 1 (weight 0.15)
      - network observation present (weight 0.15)

    Each factor is clamped to [0, 1] before weighting.
    """
    launch_factor = min(profile.launch_count / max(min_samples, 1), 1.0)
    resource_count = len(profile.resource.cpu_samples) or profile.resource.cpu_sample_count_cache
    resource_factor = min(resource_count / max(min_samples, 1), 1.0)
    parent_factor = 1.0 if len(profile.parent_keys) >= 1 else 0.0
    network_factor = 1.0 if len(profile.network_destinations) >= 1 else 0.0

    confidence = (
        0.4 * launch_factor
        + 0.3 * resource_factor
        + 0.15 * parent_factor
        + 0.15 * network_factor
    )
    return round(confidence, 4)


class BaselineAggregator:
    """Aggregates telemetry events into per-identity profiles."""

    def __init__(self) -> None:
        self._profiles: dict[str, IdentityProfile] = {}

    @property
    def profiles(self) -> dict[str, IdentityProfile]:
        return self._profiles

    def _get_or_create(self, identity_key: str) -> IdentityProfile:
        if identity_key not in self._profiles:
            self._profiles[identity_key] = IdentityProfile(identity_key=identity_key)
        return self._profiles[identity_key]

    def ingest(self, event_type: str, payload: dict[str, Any], ts: str) -> None:
        """Ingest a single telemetry event payload."""
        identity_key = payload.get("identity_key", "")
        if not identity_key:
            return

        if event_type == "process_start":
            profile = self._get_or_create(identity_key)
            parent_key = payload.get("parent_identity_key", "")
            profile.record_launch(ts, parent_key)

        elif event_type == "resource_sample":
            profile = self._get_or_create(identity_key)
            cpu = payload.get("cpu_percent", 0.0)
            mem = payload.get("memory_rss_bytes", 0)
            profile.record_resource(cpu, mem)

        elif event_type == "net_conn":
            profile = self._get_or_create(identity_key)
            remote_ip = payload.get("remote_ip", "")
            remote_port = payload.get("remote_port", 0)
            if remote_ip:
                profile.record_network(remote_ip, remote_port)
