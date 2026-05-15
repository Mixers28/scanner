"""Anomaly signal detection.

Each signal function evaluates one specific deviation type and returns
a Signal with a code, score contribution, and human-readable description.

SPEC §5.4 required signals:
  - new_identity          (2 pts)
  - unsigned_writable     (2 pts)
  - unusual_parent        (2 pts)
  - new_network_dest      (2 pts)
  - resource_spike        (1 pt)
  - burst_launch          (1 pt)

Hard escalation (overrides score):
  unsigned + user-writable + outbound network → minimum critical (score ≥ 6).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from scanner.baseline.stats import IdentityProfile
from scanner.common.identity import is_user_writable_dir, normalize_signer_publisher


@dataclass(frozen=True)
class Signal:
    code: str
    points: int
    description: str


def check_new_identity(
    identity_key: str,
    baseline_profiles: dict[str, IdentityProfile],
) -> Signal | None:
    """Process identity not present in the baseline."""
    if identity_key not in baseline_profiles:
        return Signal("new_identity", 2, "Process identity not seen during baseline period")
    return None


def check_unsigned_writable(
    signer_publisher: str,
    image_path_norm: str,
) -> Signal | None:
    """Unsigned executable in a user-writable location."""
    is_unsigned = normalize_signer_publisher(signer_publisher) == "unsigned"
    if is_unsigned and is_user_writable_dir(image_path_norm):
        return Signal("unsigned_writable", 2, "Unsigned executable in user-writable directory")
    return None


def check_unusual_parent(
    identity_key: str,
    parent_identity_key: str,
    baseline_profiles: dict[str, IdentityProfile],
) -> Signal | None:
    """Parent process not in the known parent set for this identity."""
    profile = baseline_profiles.get(identity_key)
    if profile is None:
        return None  # new_identity already covers this
    if not parent_identity_key:
        return None
    if parent_identity_key not in profile.parent_keys:
        return Signal("unusual_parent", 2, "Launched by an unusual parent process")
    return None


def check_new_network_dest(
    identity_key: str,
    remote_ip: str,
    remote_port: int,
    baseline_profiles: dict[str, IdentityProfile],
) -> Signal | None:
    """Network destination not seen during baseline."""
    profile = baseline_profiles.get(identity_key)
    dest = f"{remote_ip}:{remote_port}"
    if profile is None:
        return Signal("new_network_dest", 2, f"New network destination {dest} (unknown identity)")
    if dest not in profile.network_destinations:
        return Signal("new_network_dest", 2, f"New network destination {dest}")
    return None


def check_resource_spike(
    identity_key: str,
    cpu_percent: float,
    memory_rss_bytes: int,
    baseline_profiles: dict[str, IdentityProfile],
    spike_factor: float = 2.0,
) -> Signal | None:
    """CPU or memory exceeds baseline p90 by spike_factor."""
    profile = baseline_profiles.get(identity_key)
    if profile is None:
        return None
    cpu_p90 = profile.resource.cpu_percentiles().get("p90", 0.0)
    mem_p90 = profile.resource.mem_percentiles().get("p90", 0.0)

    cpu_threshold = max(cpu_p90 * spike_factor, 5.0)  # floor at 5%
    mem_threshold = max(mem_p90 * spike_factor, 50 * 1024 * 1024)  # floor at 50MB

    if cpu_percent > cpu_threshold:
        return Signal("resource_spike", 1, f"CPU {cpu_percent:.1f}% exceeds baseline p90 ({cpu_p90:.1f}%) by {spike_factor}x")
    if memory_rss_bytes > mem_threshold:
        return Signal("resource_spike", 1, f"Memory {memory_rss_bytes} bytes exceeds baseline p90 ({mem_p90:.0f}) by {spike_factor}x")
    return None


def check_burst_launch(
    identity_key: str,
    recent_launch_count: int,
    window_minutes: int,
    baseline_profiles: dict[str, IdentityProfile],
    burst_factor: float = 3.0,
) -> Signal | None:
    """Launch frequency in recent window exceeds baseline average by burst_factor."""
    profile = baseline_profiles.get(identity_key)
    if profile is None:
        return None
    if profile.launch_count == 0:
        return None

    # Estimate baseline launches per window (very rough: total / baseline days * window)
    # For MVP, compare raw recent count against a threshold derived from baseline
    baseline_avg_per_window = max(profile.launch_count / 7.0 * (window_minutes / 1440.0), 1.0)
    threshold = baseline_avg_per_window * burst_factor

    if recent_launch_count > threshold:
        return Signal(
            "burst_launch", 1,
            f"{recent_launch_count} launches in {window_minutes}min exceeds baseline norm ({baseline_avg_per_window:.1f}) by {burst_factor}x",
        )
    return None


def check_hard_escalation(
    signer_publisher: str,
    image_path_norm: str,
    has_outbound_network: bool,
) -> bool:
    """SPEC hard escalation: unsigned + user-writable + outbound network → critical."""
    is_unsigned = normalize_signer_publisher(signer_publisher) == "unsigned"
    return is_unsigned and is_user_writable_dir(image_path_norm) and has_outbound_network


def evaluate_signals(
    identity_key: str,
    payload: dict[str, Any],
    baseline_profiles: dict[str, IdentityProfile],
    recent_launch_count: int = 0,
    launch_window_minutes: int = 10,
) -> list[Signal]:
    """Run all signal checks and return detected signals."""
    signals: list[Signal] = []

    sig = check_new_identity(identity_key, baseline_profiles)
    if sig:
        signals.append(sig)

    image_path_norm = payload.get("image_path_norm", "")
    signer = payload.get("signer_publisher", "unknown")

    sig = check_unsigned_writable(signer, image_path_norm)
    if sig:
        signals.append(sig)

    parent_key = payload.get("parent_identity_key", "")
    sig = check_unusual_parent(identity_key, parent_key, baseline_profiles)
    if sig:
        signals.append(sig)

    remote_ip = payload.get("remote_ip", "")
    remote_port = payload.get("remote_port", 0)
    if remote_ip:
        sig = check_new_network_dest(identity_key, remote_ip, remote_port, baseline_profiles)
        if sig:
            signals.append(sig)

    cpu = payload.get("cpu_percent", 0.0)
    mem = payload.get("memory_rss_bytes", 0)
    if cpu or mem:
        sig = check_resource_spike(identity_key, cpu, mem, baseline_profiles)
        if sig:
            signals.append(sig)

    if recent_launch_count > 0:
        sig = check_burst_launch(identity_key, recent_launch_count, launch_window_minutes, baseline_profiles)
        if sig:
            signals.append(sig)

    return signals
