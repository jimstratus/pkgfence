"""Tests for the triage layer."""
from scripts.lib.types import new_finding
from scripts.triage import dedup_findings, sort_findings


def test_dedup_same_purl_same_vuln():
    findings = [
        new_finding(purl="pkg:npm/lodash@4.17.10", vuln_id="GHSA-jf85-cpcp-j695",
                    severity="high", manifest_path="/tmp/a", target="t"),
        new_finding(purl="pkg:npm/lodash@4.17.10", vuln_id="GHSA-jf85-cpcp-j695",
                    severity="high", manifest_path="/tmp/a", target="t"),
    ]
    result = dedup_findings(findings)
    assert len(result) == 1


def test_dedup_keeps_distinct_vulns():
    findings = [
        new_finding(purl="pkg:npm/lodash@4.17.10", vuln_id="GHSA-A",
                    severity="high", manifest_path="/tmp/a", target="t"),
        new_finding(purl="pkg:npm/lodash@4.17.10", vuln_id="GHSA-B",
                    severity="high", manifest_path="/tmp/a", target="t"),
    ]
    result = dedup_findings(findings)
    assert len(result) == 2


def test_dedup_keeps_same_vuln_different_purls():
    findings = [
        new_finding(purl="pkg:npm/lodash@4.17.10", vuln_id="GHSA-X",
                    severity="high", manifest_path="/tmp/a", target="t"),
        new_finding(purl="pkg:npm/lodash@4.17.11", vuln_id="GHSA-X",
                    severity="high", manifest_path="/tmp/a", target="t"),
    ]
    result = dedup_findings(findings)
    assert len(result) == 2


from scripts.triage import apply_mal_override


def test_mal_override_via_id():
    findings = [new_finding(
        purl="pkg:npm/foo@1.0.0", vuln_id="MAL-2026-2307",
        severity="low", manifest_path="/tmp/a", target="t",
    )]
    out = apply_mal_override(findings)
    assert out[0]["severity"] == "critical"
    assert out[0]["mal_flagged"] is True


def test_mal_override_via_aliases():
    """Round 2 finding: MAL-* can be in aliases[], not just primary id."""
    findings = [new_finding(
        purl="pkg:npm/axios@1.7.0",
        vuln_id="GHSA-fw8c-xr5c-95f9",
        severity="high",
        manifest_path="/tmp/a", target="t",
        aliases=["CVE-2026-99999", "MAL-2026-2307"],
    )]
    out = apply_mal_override(findings)
    assert out[0]["severity"] == "critical"
    assert out[0]["mal_flagged"] is True


def test_no_mal_override_when_absent():
    findings = [new_finding(
        purl="pkg:npm/foo@1.0.0", vuln_id="GHSA-xxx",
        severity="medium", manifest_path="/tmp/a", target="t",
    )]
    out = apply_mal_override(findings)
    assert out[0]["severity"] == "medium"
    assert out[0].get("mal_flagged", False) is False


def test_triage_filters_active_exceptions(tmp_path):
    """An active exception suppresses the matching finding."""
    from scripts.triage import apply_exceptions
    import datetime

    findings = [
        new_finding(purl="pkg:npm/lodash@4.17.10", vuln_id="GHSA-xxx",
                    severity="high", manifest_path="D:\\projects\\old",
                    target="t"),
        new_finding(purl="pkg:npm/foo@1.0", vuln_id="GHSA-yyy",
                    severity="high", manifest_path="D:\\projects\\new",
                    target="t"),
    ]
    exceptions = [
        {"id": "EXC-001", "vuln_id": "GHSA-xxx", "package": "lodash",
         "version_range": "any", "scope": "D:\\projects\\old",
         "reason": "x", "approved_by": "r", "approved_on": "2026-04-01",
         "expires": "2099-01-01"},
    ]
    today = datetime.date(2026, 4, 7)
    result = apply_exceptions(findings, exceptions, today=today)
    # Lodash is waived → only foo remains
    assert len(result) == 1
    assert "foo" in result[0]["purl"]


def test_triage_expired_exceptions_dont_filter():
    from scripts.triage import apply_exceptions
    import datetime

    findings = [
        new_finding(purl="pkg:npm/lodash@4.17.10", vuln_id="GHSA-xxx",
                    severity="high", manifest_path="D:\\projects\\old",
                    target="t"),
    ]
    exceptions = [
        {"id": "EXC-001", "vuln_id": "GHSA-xxx", "package": "lodash",
         "version_range": "any", "scope": "D:\\projects\\old",
         "reason": "x", "approved_by": "r", "approved_on": "2025-01-01",
         "expires": "2025-12-31"},  # already expired
    ]
    today = datetime.date(2026, 4, 7)
    result = apply_exceptions(findings, exceptions, today=today)
    assert len(result) == 1  # finding survives because exception is expired


def test_sort_findings_severity_then_alphabetical():
    """Sort by severity (critical > high > medium > low > info), then
    alphabetically by purl. Deterministic: same input → same order."""
    findings = [
        new_finding(purl="pkg:npm/zzz@1.0", vuln_id="A", severity="medium",
                    manifest_path="/tmp/a", target="t"),
        new_finding(purl="pkg:npm/aaa@1.0", vuln_id="B", severity="critical",
                    manifest_path="/tmp/a", target="t"),
        new_finding(purl="pkg:npm/bbb@1.0", vuln_id="C", severity="critical",
                    manifest_path="/tmp/a", target="t"),
        new_finding(purl="pkg:npm/ccc@1.0", vuln_id="D", severity="low",
                    manifest_path="/tmp/a", target="t"),
    ]
    sorted_list = sort_findings(findings)
    severities = [f["severity"] for f in sorted_list]
    assert severities == ["critical", "critical", "medium", "low"]
    # Alphabetical within severity
    purls_critical = [f["purl"] for f in sorted_list if f["severity"] == "critical"]
    assert purls_critical == ["pkg:npm/aaa@1.0", "pkg:npm/bbb@1.0"]


def test_apply_exclusions_filters_info_severity():
    from scripts.triage import apply_exclusions
    findings = [
        new_finding(purl="pkg:npm/foo@1.0", vuln_id="A", severity="critical",
                    manifest_path="/tmp/a", target="t"),
        new_finding(purl="pkg:npm/bar@1.0", vuln_id="B", severity="info",
                    manifest_path="/tmp/a", target="t"),
    ]
    config = {"exclude_severities_below": "low", "exclude_categories": []}
    result = apply_exclusions(findings, config)
    assert len(result) == 1
    assert result[0]["severity"] == "critical"


def test_apply_exclusions_keeps_scan_error_records():
    """SCAN_ERROR records must survive exclusions — they're status reports."""
    from scripts.triage import apply_exclusions
    findings = [
        new_finding(purl="pkg:scan-error/x@-", vuln_id="SCAN_ERROR",
                    severity="info", manifest_path="/tmp/a", target="t",
                    status="SCAN_ERROR"),
    ]
    config = {"exclude_severities_below": "low", "exclude_categories": []}
    result = apply_exclusions(findings, config)
    assert len(result) == 1  # SCAN_ERROR survives


def test_sort_findings_uses_priority_score_within_severity():
    """Within the same severity bucket, higher priority_score sorts first."""
    a = new_finding(purl="pkg:npm/a@1", vuln_id="CVE-1",
                    severity="critical", manifest_path="/a", target="local")
    a["priority_score"] = 0.50
    b = new_finding(purl="pkg:npm/b@1", vuln_id="CVE-2",
                    severity="critical", manifest_path="/a", target="local")
    b["priority_score"] = 0.95
    c = new_finding(purl="pkg:npm/c@1", vuln_id="CVE-3",
                    severity="high", manifest_path="/a", target="local")
    c["priority_score"] = 0.99

    result = sort_findings([a, b, c])
    # Critical bucket first; within it, b (0.95) before a (0.50)
    assert result[0]["vuln_id"] == "CVE-2"  # b
    assert result[1]["vuln_id"] == "CVE-1"  # a
    assert result[2]["vuln_id"] == "CVE-3"  # c (high, after both criticals)


def test_sort_findings_purl_tiebreaker_when_priority_equal():
    """When severity AND priority_score are equal, sort by purl."""
    a = new_finding(purl="pkg:npm/zebra@1", vuln_id="CVE-1",
                    severity="critical", manifest_path="/a", target="local")
    a["priority_score"] = 0.80
    b = new_finding(purl="pkg:npm/alpha@1", vuln_id="CVE-2",
                    severity="critical", manifest_path="/a", target="local")
    b["priority_score"] = 0.80
    result = sort_findings([a, b])
    # Same severity, same priority — alphabetical purl tiebreaker
    assert result[0]["purl"] == "pkg:npm/alpha@1"
    assert result[1]["purl"] == "pkg:npm/zebra@1"


def test_sort_findings_no_priority_score_treated_as_zero():
    """Findings without priority_score are sorted as if priority=0."""
    a = new_finding(purl="pkg:npm/a@1", vuln_id="CVE-1",
                    severity="critical", manifest_path="/a", target="local")
    a["priority_score"] = 0.5
    b = new_finding(purl="pkg:npm/b@1", vuln_id="CVE-2",
                    severity="critical", manifest_path="/a", target="local")
    # No priority_score on b — treated as 0.0
    result = sort_findings([a, b])
    assert result[0]["vuln_id"] == "CVE-1"  # a (0.5) before b (0.0)
    assert result[1]["vuln_id"] == "CVE-2"
