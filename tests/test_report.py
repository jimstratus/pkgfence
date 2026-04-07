"""Tests for the markdown report generator."""
from scripts.lib.types import new_finding
from scripts.report import render_markdown_report


def test_render_markdown_report_basic_structure():
    findings = [new_finding(
        purl="pkg:npm/lodash@4.17.10",
        vuln_id="GHSA-jf85-cpcp-j695",
        severity="high",
        manifest_path="D:\\projects\\foo\\package-lock.json",
        target="foo",
        description="Prototype Pollution in lodash",
        actively_exploited=False,
        diff_status="NEW",
    )]
    snapshot = {
        "scanner_version": "osv-scanner 2.3.3",
        "kev_timestamp": "2026-04-06T12:00:00Z",
        "targets_scanned": 1,
        "packages_checked": 100,
    }
    report = render_markdown_report(findings, snapshot, degraded_modes=[])
    assert "# Scan Report" in report
    assert "GHSA-jf85-cpcp-j695" in report


def test_render_markdown_report_contains_disclaimer_content():
    """M10 critic gap: assert disclaimer CONTENT, not just title presence."""
    findings = []
    snapshot = {
        "scanner_version": "osv-scanner 2.3.3",
        "kev_timestamp": "2026-04-06T12:00:00Z",
        "targets_scanned": 28,
        "packages_checked": 2847,
    }
    report = render_markdown_report(findings, snapshot, degraded_modes=[])
    # Disclaimer must contain these literal phrases
    assert "Calibrated trust disclaimer" in report
    assert "does not mean" in report.lower()
    assert "safe" in report.lower()
    # Snapshot context must appear in the rendered report
    assert "osv-scanner 2.3.3" in report
    assert "2026-04-06T12:00:00Z" in report
    assert "28" in report  # targets_scanned


def test_render_markdown_report_includes_clean_message_when_no_findings():
    findings = []
    snapshot = {
        "scanner_version": "osv-scanner 2.3.3",
        "kev_timestamp": "2026-04-06T12:00:00Z",
        "targets_scanned": 1,
        "packages_checked": 50,
    }
    report = render_markdown_report(findings, snapshot, degraded_modes=[])
    assert "No findings" in report or "0 findings" in report or "no vulnerabilities" in report.lower()


def test_render_report_with_degraded_modes_shows_warning():
    findings = []
    snapshot = {"scanner_version": "osv-scanner 2.3.3"}
    degraded = [
        "CISA KEV feed unreachable (last fresh cache: 2026-04-05) \u2014 exploit-status not enriched",
        "OSV API rate-limited (3\u00d7 429) \u2014 feed marked degraded for this run",
    ]
    report = render_markdown_report(findings, snapshot, degraded_modes=degraded)
    assert "Degraded mode" in report
    assert "CISA KEV" in report
    assert "OSV API" in report
    assert "\u26a0\ufe0f" in report
