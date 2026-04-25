"""Unit tests for the executive-summary HTML renderer + the polished
XLSX exporter."""

from __future__ import annotations

from datetime import UTC, datetime

from twisted.core.reporting import (
    FindingSummary,
    ReportData,
    render_executive_html,
    render_html,
    render_markdown,
)


def _data(*severities: str) -> ReportData:
    findings = [
        FindingSummary(
            id=i + 1, title=f"finding {i + 1}", severity=sev,
            cvss_score=8.5 if sev == "critical" else 6.0 if sev == "high" else 4.0,
            cvss_vector=None, cwe="CWE-1",
            affected_component=None, description="desc",
            root_cause=None, repro_steps=None, impact=None,
            remediation="reset and patch",
        )
        for i, sev in enumerate(severities)
    ]
    return ReportData(
        client="ACME", primary_domain="acme.example",
        engagement_started=datetime(2026, 4, 1, tzinfo=UTC),
        engagement_ended=datetime(2026, 4, 25, tzinfo=UTC),
        scope_summary="wildcard: acme.example",
        findings=findings, asset_count=12,
    )


class TestExecutiveHtml:
    def test_includes_client_and_window(self) -> None:
        html = render_executive_html(_data("high", "medium"))
        assert "ACME" in html
        assert "2026-04-01" in html
        assert "2026-04-25" in html
        assert "12 assets" in html

    def test_severity_table_renders(self) -> None:
        html = render_executive_html(_data("critical", "high", "low"))
        for sev in ("Critical", "High", "Medium", "Low", "Informational"):
            assert sev in html
        # Counts in the table for severities present
        assert ">1<" in html  # at least one count cell shows 1

    def test_top_findings_capped_at_five(self) -> None:
        import re
        html = render_executive_html(_data(*(["high"] * 8)))
        # Count only items inside the top-findings <ol>, not the
        # recommendations <ul>.
        ol_match = re.search(r"<ol>(.*?)</ol>", html, re.DOTALL)
        assert ol_match is not None
        assert ol_match.group(1).count("<li>") == 5

    def test_no_findings_message(self) -> None:
        html = render_executive_html(_data())
        assert "No findings yet" in html

    def test_recommendation_for_critical(self) -> None:
        html = render_executive_html(_data("critical", "high"))
        assert "Critical finding" in html
        assert "24-48 hours" in html

    def test_recommendation_when_no_findings(self) -> None:
        html = render_executive_html(_data())
        assert "No remediation actions required" in html


class TestStandardRenderersStillWork:
    """Regression: make sure the existing markdown + html renderers
    still work after we added render_executive_html alongside them."""

    def test_markdown_renderer_unchanged(self) -> None:
        md = render_markdown(_data("high"))
        assert "# Vulnerability Assessment Report — ACME" in md
        assert "## Executive Summary" in md

    def test_html_renderer_unchanged(self) -> None:
        html = render_html(_data("high"))
        assert "<title>ACME — Vulnerability Assessment</title>" in html
        assert "<h2>Risk Metrics</h2>" in html
