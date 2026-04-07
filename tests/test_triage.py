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
