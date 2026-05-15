"""Tests for S5-T3: Report renderer."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scanner.reporting.renderer import (
    PlainLanguageSummary,
    IncidentReport,
    build_plain_language_summary,
    render_json,
    render_html,
    render_text,
)


def _sample_incident_data() -> dict:
    return {
        "incident_id": "abc123",
        "severity": "critical",
        "score": 6,
        "identity_key": "deadbeef12345678",
        "signals": [
            {"code": "new_identity", "points": 2, "description": "Process identity not seen during baseline period"},
            {"code": "unsigned_writable", "points": 2, "description": "Unsigned executable in user-writable directory"},
            {"code": "new_network_dest", "points": 2, "description": "New network destination 8.8.8.8:53"},
        ],
    }


def _sample_verification_results() -> list[dict]:
    return [
        {"adapter_name": "signature", "verdict": "unknown", "duration_ms": 15, "evidence": {}},
    ]


def _build_report() -> IncidentReport:
    data = _sample_incident_data()
    vr = _sample_verification_results()
    summary = build_plain_language_summary(data, vr)
    return IncidentReport(
        incident_id=data["incident_id"],
        severity=data["severity"],
        score=data["score"],
        summary=summary,
        signals=data["signals"],
        verification_results=vr,
    )


class PlainLanguageSummaryTests(unittest.TestCase):
    def test_validate_all_present(self) -> None:
        s = PlainLanguageSummary(
            what_happened="x", why_it_matters="x",
            what_changed="x", checks_ran="x", safe_next_actions="x",
        )
        self.assertEqual(s.validate(), [])

    def test_validate_missing_fields(self) -> None:
        s = PlainLanguageSummary()
        missing = s.validate()
        self.assertEqual(len(missing), 5)

    def test_to_dict(self) -> None:
        s = PlainLanguageSummary(what_happened="test")
        d = s.to_dict()
        self.assertEqual(d["what_happened"], "test")
        self.assertIn("safe_next_actions", d)


class BuildPlainLanguageSummaryTests(unittest.TestCase):
    def test_all_fields_populated(self) -> None:
        summary = build_plain_language_summary(
            _sample_incident_data(), _sample_verification_results(),
        )
        self.assertEqual(summary.validate(), [])
        self.assertIn("critical", summary.what_happened)
        self.assertIn("immediate attention", summary.why_it_matters)
        self.assertIn("new_identity", summary.what_changed)
        self.assertIn("signature", summary.checks_ran)
        self.assertTrue(len(summary.safe_next_actions) > 0)

    def test_warning_severity(self) -> None:
        data = _sample_incident_data()
        data["severity"] = "warning"
        summary = build_plain_language_summary(data, [])
        self.assertIn("unusual", summary.why_it_matters)
        self.assertIn("whitelist", summary.safe_next_actions)

    def test_info_severity(self) -> None:
        data = _sample_incident_data()
        data["severity"] = "info"
        data["signals"] = [{"code": "resource_spike", "points": 1, "description": "CPU spike"}]
        summary = build_plain_language_summary(data, [])
        self.assertIn("minor", summary.why_it_matters)
        self.assertIn("No action required", summary.safe_next_actions)

    def test_no_verification_results(self) -> None:
        summary = build_plain_language_summary(_sample_incident_data(), [])
        self.assertIn("No verification checks", summary.checks_ran)


class RenderJsonTests(unittest.TestCase):
    def test_valid_json(self) -> None:
        report = _build_report()
        output = render_json(report)
        parsed = json.loads(output)
        self.assertEqual(parsed["incident_id"], "abc123")
        self.assertIn("summary", parsed)
        self.assertEqual(len(parsed["signals"]), 3)

    def test_json_has_plain_language_fields(self) -> None:
        report = _build_report()
        parsed = json.loads(render_json(report))
        summary = parsed["summary"]
        for field in ("what_happened", "why_it_matters", "what_changed", "checks_ran", "safe_next_actions"):
            self.assertIn(field, summary)
            self.assertTrue(len(summary[field]) > 0, f"{field} should not be empty")


class RenderHtmlTests(unittest.TestCase):
    def test_contains_html_structure(self) -> None:
        report = _build_report()
        output = render_html(report)
        self.assertIn("<!DOCTYPE html>", output)
        self.assertIn("<h1>Incident Report</h1>", output)

    def test_contains_all_sections(self) -> None:
        report = _build_report()
        output = render_html(report)
        for heading in ("What Happened", "Why It Matters", "What Changed", "Verification Checks", "Recommended Actions"):
            self.assertIn(heading, output)

    def test_severity_badge(self) -> None:
        report = _build_report()
        output = render_html(report)
        self.assertIn("CRITICAL", output)

    def test_html_escaping(self) -> None:
        report = _build_report()
        report.summary.what_happened = "Test <script>alert('xss')</script>"
        output = render_html(report)
        self.assertNotIn("<script>", output)
        self.assertIn("&lt;script&gt;", output)


class RenderTextTests(unittest.TestCase):
    def test_contains_all_sections(self) -> None:
        report = _build_report()
        output = render_text(report)
        for section in ("WHAT HAPPENED:", "WHY IT MATTERS:", "WHAT CHANGED VS BASELINE:", "VERIFICATION CHECKS:", "RECOMMENDED ACTIONS:"):
            self.assertIn(section, output)

    def test_contains_severity(self) -> None:
        report = _build_report()
        output = render_text(report)
        self.assertIn("CRITICAL", output)


if __name__ == "__main__":
    unittest.main()
