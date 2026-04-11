"""Tests for the markdown report generator."""
from io import StringIO

from ruamel.yaml import YAML

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


def test_report_distinguishes_remote_targets_in_findings():
    """A finding whose target matches an ssh target name should be clearly
    labeled as a remote host in the report output alongside local findings.
    Regression lock: Task 10 wired SSH into scan_command, and this test
    confirms the existing report template correctly surfaces both local
    and remote target names."""
    findings = [
        new_finding(
            purl="pkg:npm/lodash@4.17.10",
            vuln_id="GHSA-jf85-cpcp-j695",
            severity="high",
            manifest_path="/var/www/app/package-lock.json",
            target="dev-host-1",  # ssh target name
            description="Prototype Pollution in lodash",
        ),
        new_finding(
            purl="pkg:npm/axios@0.21.0",
            vuln_id="CVE-2021-3749",
            severity="medium",
            manifest_path="D:/projects/local/package-lock.json",
            target="projects",  # local root name
            description="ReDoS in axios",
        ),
    ]
    snapshot = {
        "scanner_version": "2.3.3",
        "kev_timestamp": "2026-04-07T00:00:00Z",
        "targets_scanned": 2,
        "packages_checked": 2,
    }
    md = render_markdown_report(findings, snapshot, [])

    # Both target names must appear in the rendered output
    assert "dev-host-1" in md
    assert "projects" in md
    # Both vuln IDs must appear
    assert "GHSA-jf85-cpcp-j695" in md
    assert "CVE-2021-3749" in md


def test_report_includes_yaml_frontmatter_block():
    """The rendered report must start with a YAML frontmatter block (--- ... ---)
    so AI agents and log aggregators can parse scan metadata without regex
    over the human-readable body."""
    findings = [
        new_finding(
            purl="pkg:npm/lodash@4.17.10",
            vuln_id="GHSA-jf85-cpcp-j695",
            severity="high",
            manifest_path="/var/www/app/package-lock.json",
            target="dev-host-1",
            description="Prototype Pollution",
        ),
    ]
    snapshot = {
        "scanner_version": "2.3.3",
        "kev_timestamp": "2026-04-07T00:00:00Z",
        "targets_scanned": 3,
        "packages_checked": 1,
        "run_id": "20260408T123456Z-abc12345",
        "timestamp": "2026-04-08T12:34:56+00:00",
        "scanner_host": "SCANHOST",
        "pkgfence_version": "0.2.0-dev",
        "exit_code": 1,
        "ssh_targets": ["dev-host-1", "dev-host-2"],
        "local_roots": ["D:/projects/pkgfence"],
    }
    md = render_markdown_report(findings, snapshot, [])

    # Must start with YAML frontmatter delimiter
    assert md.startswith("---\n")
    # The frontmatter must end with a closing ---
    frontmatter_end = md.index("\n---\n", 4)
    frontmatter = md[4:frontmatter_end]
    # Every required field must be present in the frontmatter
    assert "run_id: 20260408T123456Z-abc12345" in frontmatter
    assert "scanner_host: SCANHOST" in frontmatter
    assert "pkgfence_version: 0.2.0-dev" in frontmatter
    assert "scanner_version: 2.3.3" in frontmatter
    assert "exit_code: 1" in frontmatter
    assert "targets_scanned: 3" in frontmatter
    assert "findings_total: 1" in frontmatter
    # Severity breakdown
    assert "findings_by_severity:" in frontmatter
    assert "high: 1" in frontmatter
    assert "critical: 0" in frontmatter
    # Target lists (order matters for reproducibility)
    assert "ssh_targets:" in frontmatter
    assert "dev-host-1" in frontmatter
    assert "dev-host-2" in frontmatter
    # Body still exists after the frontmatter
    body = md[frontmatter_end + 5:]
    assert body.startswith("# Scan Report")


def test_report_frontmatter_parses_as_valid_yaml():
    """The frontmatter must be valid YAML that can be loaded into a dict
    with expected keys. This locks the contract for downstream parsers."""
    findings = []
    snapshot = {
        "scanner_version": "2.3.3",
        "kev_timestamp": "2026-04-07T00:00:00Z",
        "targets_scanned": 0,
        "packages_checked": 0,
        "run_id": "20260408T000000Z-deadbeef",
        "timestamp": "2026-04-08T00:00:00+00:00",
        "scanner_host": "test-host",
        "pkgfence_version": "0.2.0-dev",
        "exit_code": 0,
        "ssh_targets": [],
        "local_roots": ["/tmp/workspace"],
    }
    md = render_markdown_report(findings, snapshot, ["CISA KEV degraded"])

    # Extract the frontmatter block
    assert md.startswith("---\n")
    end = md.index("\n---\n", 4)
    frontmatter_text = md[4:end]

    # Parse it as YAML
    yaml = YAML(typ="safe")
    data = yaml.load(StringIO(frontmatter_text))

    assert data["run_id"] == "20260408T000000Z-deadbeef"
    assert data["scanner_host"] == "test-host"
    assert data["pkgfence_version"] == "0.2.0-dev"
    assert data["scanner_version"] == "2.3.3"
    assert data["targets_scanned"] == 0
    assert data["findings_total"] == 0
    assert data["exit_code"] == 0
    assert isinstance(data["findings_by_severity"], dict)
    assert data["findings_by_severity"]["critical"] == 0
    assert data["findings_by_severity"]["high"] == 0
    assert data["ssh_targets"] == []
    assert data["local_roots"] == ["/tmp/workspace"]
    assert data["degraded_modes"] == ["CISA KEV degraded"]


def test_frontmatter_routes_unknown_severity_to_other_bucket():
    """Findings with non-canonical severities (e.g., 'unknown') must be
    counted in the 'other' bucket so sum(findings_by_severity) == findings_total.
    Without this, downstream consumers can't trust the breakdown."""
    findings = [
        new_finding(
            purl="pkg:npm/lodash@4.17.10",
            vuln_id="GHSA-jf85-cpcp-j695",
            severity="high",  # canonical
            manifest_path="/var/www/app/package-lock.json",
            target="dev-host-1",
            description="real high",
        ),
        new_finding(
            purl="pkg:scan-error/dev-host-1@-",
            vuln_id="SCAN_ERROR",
            severity="unknown",  # non-canonical
            manifest_path="",
            target="dev-host-1",
            description="weird severity",
        ),
        new_finding(
            purl="pkg:npm/foo@1.0.0",
            vuln_id="CVE-2024-9999",
            severity="bogus",  # also non-canonical
            manifest_path="/var/www/app/package-lock.json",
            target="dev-host-1",
            description="another weird one",
        ),
    ]
    snapshot = {
        "scanner_version": "2.3.3",
        "kev_timestamp": "2026-04-07T00:00:00Z",
        "targets_scanned": 1,
        "packages_checked": 3,
        "run_id": "test-run",
        "timestamp": "2026-04-07T00:00:00+00:00",
        "scanner_host": "test-host",
        "pkgfence_version": "0.2.0-dev",
        "exit_code": 1,
        "ssh_targets": [],
        "local_roots": [],
    }
    md = render_markdown_report(findings, snapshot, [])

    # Extract frontmatter
    end = md.index("\n---\n", 4)
    frontmatter_text = md[4:end]
    yaml = YAML(typ="safe")
    data = yaml.load(StringIO(frontmatter_text))

    # Sum of severity buckets must equal total findings
    severity_sum = sum(data["findings_by_severity"].values())
    assert severity_sum == data["findings_total"] == 3

    # Specifically: 1 high, 2 other
    assert data["findings_by_severity"]["high"] == 1
    assert data["findings_by_severity"]["other"] == 2
    # Canonical buckets unchanged
    assert data["findings_by_severity"]["critical"] == 0
    assert data["findings_by_severity"]["medium"] == 0
    assert data["findings_by_severity"]["low"] == 0
    assert data["findings_by_severity"]["info"] == 0


def test_report_shows_demotion_note():
    """Demoted findings show original severity and not-installed note."""
    f = new_finding(purl="pkg:npm/evil@1.0", vuln_id="MAL-123",
                    severity="info", manifest_path="/a/package-lock.json", target="local")
    f["installed"] = False
    f["original_severity"] = "critical"
    report = render_markdown_report([f], {"scanner_version": "2.3.3"}, [])
    report_lower = report.lower()
    assert "was critical" in report_lower
    assert "not installed" in report_lower


def test_report_shows_eol_finding():
    """EOL findings render with their vuln_id and description."""
    f = new_finding(purl="pkg:generic/pydio@8.2.5", vuln_id="EOL-Pydio-8.2.5",
                    severity="high", manifest_path="/var/www/apps/pydio/",
                    target="mars", description="Pydio 8.2.5 is end-of-life.")
    report = render_markdown_report([f], {"scanner_version": "2.3.3"}, [])
    assert "EOL-Pydio-8.2.5" in report
    assert "end-of-life" in report.lower()


def test_report_no_demotion_note_when_not_demoted():
    """Normal findings don't show demotion note."""
    f = new_finding(purl="pkg:npm/foo@1.0", vuln_id="GHSA-1",
                    severity="high", manifest_path="/a/package-lock.json", target="local")
    report = render_markdown_report([f], {"scanner_version": "2.3.3"}, [])
    assert "was " not in report.lower() or "was high" not in report.lower()
    assert "not installed" not in report.lower()


def test_report_shows_priority_line():
    f = new_finding(purl="pkg:npm/x@1", vuln_id="CVE-2024-1",
                    severity="critical", manifest_path="/a", target="local")
    f["cvss_score"] = 9.5
    f["epss_score"] = 0.78
    f["epss_percentile"] = 0.99
    f["actively_exploited"] = True
    f["priority_score"] = 0.95
    report = render_markdown_report([f], {"scanner_version": "2.3.3"}, [])
    assert "Priority" in report
    assert "0.95" in report
    assert "0.78" in report  # EPSS in component breakdown
    assert "p99" in report  # percentile display


def test_report_priority_line_with_no_epss():
    f = new_finding(purl="pkg:npm/x@1", vuln_id="CVE-2024-2",
                    severity="high", manifest_path="/a", target="local")
    f["cvss_score"] = 8.0
    f["priority_score"] = 0.32
    report = render_markdown_report([f], {"scanner_version": "2.3.3"}, [])
    assert "Priority" in report
    assert "EPSS=0.00" in report
    assert "KEV=false" in report


def test_report_no_priority_line_when_score_absent():
    """Findings without priority_score don't get a priority line."""
    f = new_finding(purl="pkg:npm/x@1", vuln_id="GHSA-1",
                    severity="medium", manifest_path="/a", target="local")
    # No priority_score set
    report = render_markdown_report([f], {"scanner_version": "2.3.3"}, [])
    assert "Priority:" not in report or "**Priority:**" not in report


def test_frontmatter_includes_epss_feed_timestamp():
    snapshot = {
        "scanner_version": "2.3.3",
        "epss_feed_timestamp": "2026-04-11T00:00:00+00:00",
    }
    report = render_markdown_report([], snapshot, [])
    assert "epss_feed_timestamp" in report
    assert "2026-04-11" in report


def test_frontmatter_severity_keys_in_severity_rank_order():
    """findings_by_severity should appear in severity-rank order
    (critical, high, medium, low, info, other) — NOT alphabetical —
    so humans reading the frontmatter and consumers iterating keys
    get the intuitive order."""
    findings = []
    snapshot = {
        "scanner_version": "2.3.3",
        "kev_timestamp": "2026-04-07T00:00:00Z",
        "targets_scanned": 0,
        "packages_checked": 0,
        "run_id": "test-run",
        "timestamp": "2026-04-07T00:00:00+00:00",
        "scanner_host": "test-host",
        "pkgfence_version": "0.2.0-dev",
        "exit_code": 0,
        "ssh_targets": [],
        "local_roots": [],
    }
    md = render_markdown_report(findings, snapshot, [])

    # Find the indices of each severity key in the frontmatter text
    end = md.index("\n---\n", 4)
    frontmatter_text = md[4:end]
    keys_in_order = ["critical", "high", "medium", "low", "info", "other"]
    indices = [frontmatter_text.find(f"  {k}:") for k in keys_in_order]
    # All keys must be present
    assert all(idx >= 0 for idx in indices), f"missing keys in {frontmatter_text}"
    # Indices must be strictly increasing (severity-rank order, not alphabetical)
    assert indices == sorted(indices), (
        f"severity keys not in rank order: {list(zip(keys_in_order, indices))}"
    )
