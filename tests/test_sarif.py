"""Tests for SARIF 2.1.0 emitter."""
import json
from scripts.lib.types import new_finding
from scripts.lib.sarif import findings_to_sarif


def test_sarif_basic_structure():
    findings = [new_finding(
        purl="pkg:npm/lodash@4.17.10",
        vuln_id="GHSA-jf85-cpcp-j695",
        severity="critical",
        manifest_path="D:\\projects\\foo\\package-lock.json",
        target="foo",
        description="Prototype Pollution",
    )]
    sarif = findings_to_sarif(findings, scanner_version="osv-scanner 2.3.3")
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-schema-2.1.0.json")
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "pkgfence"
    assert len(run["results"]) == 1


def test_sarif_severity_mapping_critical_to_error():
    findings = [new_finding(
        purl="pkg:npm/foo@1.0", vuln_id="X", severity="critical",
        manifest_path="/foo", target="t",
    )]
    sarif = findings_to_sarif(findings, scanner_version="t")
    assert sarif["runs"][0]["results"][0]["level"] == "error"


def test_sarif_severity_mapping_low_to_note():
    findings = [new_finding(
        purl="pkg:npm/foo@1.0", vuln_id="X", severity="low",
        manifest_path="/foo", target="t",
    )]
    sarif = findings_to_sarif(findings, scanner_version="t")
    assert sarif["runs"][0]["results"][0]["level"] == "note"


def test_sarif_includes_partial_fingerprint():
    findings = [new_finding(
        purl="pkg:npm/lodash@4.17.10", vuln_id="GHSA-x", severity="high",
        manifest_path="/foo/package-lock.json", target="t",
    )]
    sarif = findings_to_sarif(findings, scanner_version="t")
    result = sarif["runs"][0]["results"][0]
    assert "partialFingerprints" in result
    assert "primaryLocationLineHash" in result["partialFingerprints"]
