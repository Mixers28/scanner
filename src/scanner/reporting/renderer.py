"""Incident report renderer.

SPEC §5.6: JSON + HTML output with mandatory plain-language summary.
Required plain-language fields:
  - what happened
  - why it matters
  - what changed vs baseline
  - what checks ran
  - safe next actions
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class PlainLanguageSummary:
    """Mandatory user-facing explanation fields."""
    what_happened: str = ""
    why_it_matters: str = ""
    what_changed: str = ""
    checks_ran: str = ""
    safe_next_actions: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "what_happened": self.what_happened,
            "why_it_matters": self.why_it_matters,
            "what_changed": self.what_changed,
            "checks_ran": self.checks_ran,
            "safe_next_actions": self.safe_next_actions,
        }

    def validate(self) -> list[str]:
        """Return list of missing required fields."""
        missing = []
        for f in ("what_happened", "why_it_matters", "what_changed", "checks_ran", "safe_next_actions"):
            if not getattr(self, f, "").strip():
                missing.append(f)
        return missing


@dataclass
class IncidentReport:
    """Full incident report combining plain-language and technical data."""
    incident_id: str = ""
    severity: str = ""
    score: int = 0
    summary: PlainLanguageSummary = field(default_factory=PlainLanguageSummary)
    signals: list[dict[str, Any]] = field(default_factory=list)
    verification_results: list[dict[str, Any]] = field(default_factory=list)
    technical_appendix: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "severity": self.severity,
            "score": self.score,
            "summary": self.summary.to_dict(),
            "signals": self.signals,
            "verification_results": self.verification_results,
            "technical_appendix": self.technical_appendix,
        }


def build_plain_language_summary(
    incident_data: dict[str, Any],
    verification_results: list[dict[str, Any]],
) -> PlainLanguageSummary:
    """Generate a plain-language summary from incident and verification data."""
    signals = incident_data.get("signals", [])
    severity = incident_data.get("severity", "unknown")
    identity_key = incident_data.get("identity_key", "unknown process")

    signal_descriptions = [s.get("description", "") for s in signals if s.get("description")]
    what_happened = f"A {severity}-severity anomaly was detected involving process {identity_key[:12]}..."
    if signal_descriptions:
        what_happened += " Detected: " + "; ".join(signal_descriptions) + "."

    severity_explanations = {
        "critical": "This requires immediate attention. The combination of factors suggests a potentially serious security concern.",
        "warning": "This is unusual behavior that should be reviewed. It may be harmless but warrants investigation.",
        "info": "This is a minor deviation from normal behavior. No immediate action is required, but it has been logged for awareness.",
    }
    why_it_matters = severity_explanations.get(severity, "An anomaly was detected that differs from learned baseline behavior.")

    what_changed = "The following deviations from baseline were observed: "
    what_changed += ", ".join(s.get("code", "unknown") for s in signals) if signals else "unknown signals"
    what_changed += "."

    checks = [vr.get("adapter_name", "unknown") for vr in verification_results]
    verdicts = [vr.get("verdict", "unknown") for vr in verification_results]
    if checks:
        checks_ran = f"Verification checks run: {', '.join(checks)}. Verdicts: {', '.join(verdicts)}."
    else:
        checks_ran = "No verification checks were run."

    safe_next_actions = _suggest_actions(severity, signals)

    return PlainLanguageSummary(
        what_happened=what_happened,
        why_it_matters=why_it_matters,
        what_changed=what_changed,
        checks_ran=checks_ran,
        safe_next_actions=safe_next_actions,
    )


def _suggest_actions(severity: str, signals: list[dict[str, Any]]) -> str:
    signal_codes = {s.get("code", "") for s in signals}
    actions = []

    if severity == "critical":
        actions.append("Review this process immediately and consider terminating it if unrecognized.")
        if "unsigned_writable" in signal_codes:
            actions.append("Check whether you intentionally downloaded or installed this program.")
        if "new_network_dest" in signal_codes:
            actions.append("Verify the network destination is expected (not a command-and-control server).")
    elif severity == "warning":
        actions.append("Monitor this process for further unusual activity.")
        actions.append("If this is a program you trust, consider adding it to the whitelist.")
    else:
        actions.append("No action required. This event has been logged for future baseline reference.")

    return " ".join(actions)


def render_json(report: IncidentReport) -> str:
    """Render report as formatted JSON."""
    return json.dumps(report.to_dict(), indent=2)


def render_html(report: IncidentReport) -> str:
    """Render report as self-contained HTML page."""
    s = report.summary
    severity_colors = {"critical": "#dc3545", "warning": "#ffc107", "info": "#17a2b8"}
    color = severity_colors.get(report.severity, "#6c757d")

    signals_html = ""
    for sig in report.signals:
        code = html.escape(sig.get("code", ""))
        pts = sig.get("points", 0)
        desc = html.escape(sig.get("description", ""))
        signals_html += f"<tr><td>{code}</td><td>{pts}</td><td>{desc}</td></tr>\n"

    verifications_html = ""
    for vr in report.verification_results:
        adapter = html.escape(vr.get("adapter_name", ""))
        verdict = html.escape(vr.get("verdict", ""))
        duration = vr.get("duration_ms", 0)
        verifications_html += f"<tr><td>{adapter}</td><td>{verdict}</td><td>{duration}ms</td></tr>\n"

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Incident Report {html.escape(report.incident_id)}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 800px; margin: 2em auto; padding: 0 1em; }}
.severity {{ display: inline-block; padding: 4px 12px; border-radius: 4px; color: #fff; background: {color}; font-weight: bold; }}
table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
th {{ background: #f5f5f5; }}
.section {{ margin: 1.5em 0; }}
h2 {{ border-bottom: 1px solid #eee; padding-bottom: 0.3em; }}
</style></head>
<body>
<h1>Incident Report</h1>
<p><strong>ID:</strong> {html.escape(report.incident_id)}</p>
<p><strong>Severity:</strong> <span class="severity">{html.escape(report.severity.upper())}</span>
   <strong>Score:</strong> {report.score}</p>

<div class="section">
<h2>What Happened</h2>
<p>{html.escape(s.what_happened)}</p>
</div>

<div class="section">
<h2>Why It Matters</h2>
<p>{html.escape(s.why_it_matters)}</p>
</div>

<div class="section">
<h2>What Changed vs Baseline</h2>
<p>{html.escape(s.what_changed)}</p>
</div>

<div class="section">
<h2>Verification Checks</h2>
<p>{html.escape(s.checks_ran)}</p>
</div>

<div class="section">
<h2>Recommended Actions</h2>
<p>{html.escape(s.safe_next_actions)}</p>
</div>

<div class="section">
<h2>Signals</h2>
<table><tr><th>Code</th><th>Points</th><th>Description</th></tr>
{signals_html}</table>
</div>

<div class="section">
<h2>Verification Results</h2>
<table><tr><th>Adapter</th><th>Verdict</th><th>Duration</th></tr>
{verifications_html}</table>
</div>

</body></html>"""


def render_text(report: IncidentReport) -> str:
    """Render report as plain text."""
    s = report.summary
    lines = [
        f"INCIDENT REPORT: {report.incident_id}",
        f"Severity: {report.severity.upper()} (score: {report.score})",
        "",
        "WHAT HAPPENED:",
        s.what_happened,
        "",
        "WHY IT MATTERS:",
        s.why_it_matters,
        "",
        "WHAT CHANGED VS BASELINE:",
        s.what_changed,
        "",
        "VERIFICATION CHECKS:",
        s.checks_ran,
        "",
        "RECOMMENDED ACTIONS:",
        s.safe_next_actions,
    ]
    return "\n".join(lines)
