"""Test the Finding TypedDict contract."""
from scripts.lib.types import Finding, new_finding, is_status_record


def test_finding_accepts_installed_and_original_severity():
    """Finding TypedDict accepts new is-installed fields."""
    f = new_finding(purl="pkg:npm/foo@1.0", vuln_id="GHSA-1", severity="high",
                    manifest_path="/a/package-lock.json", target="local")
    f["installed"] = False
    f["original_severity"] = "high"
    assert f["installed"] is False
    assert f["original_severity"] == "high"


def test_finding_accepts_cvss_and_priority_fields():
    f = new_finding(purl="pkg:npm/foo@1.0", vuln_id="CVE-2024-1",
                    severity="critical", manifest_path="/a", target="local")
    f["cvss_score"] = 9.8
    f["priority_score"] = 0.92
    assert f["cvss_score"] == 9.8
    assert f["priority_score"] == 0.92


def test_new_finding_has_all_required_fields():
    f = new_finding(
        purl="pkg:npm/lodash@4.17.20",
        vuln_id="GHSA-jf85-cpcp-j695",
        severity="high",
        manifest_path="D:/projects/foo/package-lock.json",
    )
    assert f["purl"] == "pkg:npm/lodash@4.17.20"
    assert f["vuln_id"] == "GHSA-jf85-cpcp-j695"
    assert f["severity"] == "high"
    assert f["manifest_path"] == "D:/projects/foo/package-lock.json"
    # Defaults for optional fields
    assert f["aliases"] == []
    assert f["actively_exploited"] is False
    assert f["diff_status"] == "NEW"
    assert f["status"] == "OK"


def test_is_status_record():
    assert is_status_record({"status": "SCAN_ERROR"})
    assert not is_status_record({"status": "OK"})
    assert not is_status_record({})
