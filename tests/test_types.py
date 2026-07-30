"""Test the Finding TypedDict contract."""
from scripts.lib.types import Finding, GHSAAdvisory, new_finding, is_status_record, SEVERITY_RANK, iter_vuln_ids


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


def test_severity_rank_is_single_source_of_truth():
    from scripts import triage, notify
    assert triage.SEVERITY_RANK is SEVERITY_RANK
    assert notify.SEVERITY_RANK is SEVERITY_RANK
    assert list(SEVERITY_RANK) == ["critical", "high", "medium", "low", "info"]


def test_iter_vuln_ids_skips_non_string_aliases():
    f = {"vuln_id": "GHSA-1", "aliases": ["CVE-2026-1", None, 42, ""]}
    assert list(iter_vuln_ids(f)) == ["GHSA-1", "CVE-2026-1"]


def test_iter_vuln_ids_handles_missing_fields():
    assert list(iter_vuln_ids({})) == []


def test_finding_accepts_ghsa_field():
    f = new_finding(purl="pkg:npm/foo@1.0", vuln_id="GHSA-abcd",
                    severity="high", manifest_path="/a", target="local")
    advisory: GHSAAdvisory = {
        "ghsa_id": "GHSA-abcd",
        "cve_id": "CVE-2024-1",
        "summary": "Test advisory",
        "description": "Full description",
        "severity": "critical",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwes": ["CWE-1321"],
        "permalink": "https://github.com/advisories/GHSA-abcd",
        "published_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-06-01T00:00:00Z",
        "withdrawn_at": None,
    }
    f["ghsa"] = advisory
    assert f["ghsa"]["severity"] == "critical"
    assert f["ghsa"]["cwes"] == ["CWE-1321"]
    assert f["ghsa"]["cvss_score"] == 9.8


def test_ghsaadvisory_withdrawn():
    advisory: GHSAAdvisory = {
        "ghsa_id": "GHSA-1234",
        "summary": "Withdrawn advisory",
        "description": "This was retracted",
        "severity": "high",
        "published_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-06-01T00:00:00Z",
        "withdrawn_at": "2024-07-01T00:00:00Z",
    }
    assert advisory["withdrawn_at"] == "2024-07-01T00:00:00Z"


def test_ghsaadvisory_omits_optional_fields():
    advisory: GHSAAdvisory = {
        "ghsa_id": "GHSA-minimal",
        "summary": "Minimal advisory",
        "description": "Just the essentials",
        "severity": "medium",
        "published_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-06-01T00:00:00Z",
    }
    assert "cve_id" not in advisory
    assert "cwes" not in advisory


def test_finding_accepts_heuristic_fields():
    f = new_finding(purl="pkg:npm/lodash@4.17.10", vuln_id="GHSA-jf85",
                    severity="high", manifest_path="/a", target="local")
    f["heuristic_flags"] = ["age:abandoned", "lifecycle:postinstall"]
    f["lifecycle_script"] = "postinstall:node ./install.js"
    f["missing_provenance"] = True
    f["entropy_score"] = 7.2
    assert "age:abandoned" in f["heuristic_flags"]
    assert "lifecycle:postinstall" in f["heuristic_flags"]
    assert f["lifecycle_script"].startswith("postinstall")
    assert f["missing_provenance"] is True
    assert f["entropy_score"] == 7.2
