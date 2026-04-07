"""Tests for the triage layer."""
from scripts.lib.types import new_finding
from scripts.triage import dedup_findings


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
