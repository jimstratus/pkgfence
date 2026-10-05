"""Tests for fix-recommendation document builder."""
from scripts.lib.types import new_finding
from scripts.recommend_fix import build_fix_document, generate_fix


def test_generate_fix_uses_fix_version():
    f = new_finding(
        purl="pkg:npm/lodash@4.17.10", vuln_id="GHSA-x",
        severity="high", manifest_path="/a", target="t",
        fix_version="4.17.21",
    )
    fix = generate_fix(f)
    assert fix is not None
    assert "4.17.21" in fix
    assert "lodash" in fix


def test_findings_count_excludes_scan_errors():
    findings = [
        new_finding(
            purl="pkg:npm/a@1", vuln_id="X", severity="high",
            manifest_path="/a", target="t", fix_version="2",
        ),
        {
            "status": "SCAN_ERROR",
            "vuln_id": "SCAN_ERROR",
            "purl": "",
            "severity": "info",
            "manifest_path": "/b",
            "target": "t",
        },
    ]
    doc = build_fix_document(findings)
    assert len(doc["recommendations"]) == 1
    assert doc["findings_count"] == 1
