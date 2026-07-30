"""Tests for GHSA enrichment module."""
from scripts.lib.types import new_finding
from scripts.enrich_ghsa import enrich_with_ghsa


class FakeGHSAHTTPClient:
    def __init__(self, advisories=None):
        self._advisories = advisories or {}
        self.is_degraded = False
        self.is_stale = False
        self.advisories_fetched = 0
        self.advisories_cached = 0

    def fetch(self, ghsa_id: str) -> dict | None:
        return self._advisories.get(ghsa_id)


def _make_ghsa_advisory(ghsa_id="GHSA-abcd", cve_id="CVE-2024-1",
                        severity="high", cvss_score=8.1, cwes=None,
                        withdrawn_at=None) -> dict:
    return {
        "ghsa_id": ghsa_id,
        "cve_id": cve_id,
        "summary": "Test advisory",
        "description": "Full description.",
        "severity": severity,
        "cvss_score": cvss_score,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwes": cwes or ["CWE-1321"],
        "permalink": f"https://github.com/advisories/{ghsa_id}",
        "published_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-06-01T00:00:00Z",
        "withdrawn_at": withdrawn_at,
    }


def test_enrich_attaches_advisory_to_ghsa_finding():
    ghsa = FakeGHSAHTTPClient({"GHSA-abcd": _make_ghsa_advisory()})
    f = new_finding(purl="pkg:npm/lodash@4.17.10", vuln_id="GHSA-abcd",
                    severity="high", manifest_path="/a", target="local")
    enrich_with_ghsa([f], ghsa)
    assert f.get("ghsa") is not None
    assert f["ghsa"]["severity"] == "high"
    assert f["ghsa"]["cve_id"] == "CVE-2024-1"


def test_enrich_injects_cve_alias():
    ghsa = FakeGHSAHTTPClient({"GHSA-abcd": _make_ghsa_advisory(
        cve_id="CVE-2024-99999")})
    f = new_finding(purl="pkg:npm/x@1", vuln_id="GHSA-abcd",
                    severity="high", manifest_path="/a", target="local",
                    aliases=["GHSA-9876"])
    enrich_with_ghsa([f], ghsa)
    assert "CVE-2024-99999" in f["aliases"]


def test_enrich_no_duplicate_cve_alias():
    ghsa = FakeGHSAHTTPClient({"GHSA-abcd": _make_ghsa_advisory(
        cve_id="CVE-2024-1")})
    f = new_finding(purl="pkg:npm/x@1", vuln_id="GHSA-abcd",
                    severity="high", manifest_path="/a", target="local",
                    aliases=["CVE-2024-1"])
    enrich_with_ghsa([f], ghsa)
    assert f["aliases"].count("CVE-2024-1") == 1


def test_enrich_fallback_cvss():
    ghsa = FakeGHSAHTTPClient({"GHSA-abcd": _make_ghsa_advisory(
        cvss_score=9.1)})
    f = new_finding(purl="pkg:npm/x@1", vuln_id="GHSA-abcd",
                    severity="high", manifest_path="/a", target="local")
    assert "cvss_score" not in f
    enrich_with_ghsa([f], ghsa)
    assert f["cvss_score"] == 9.1


def test_enrich_does_not_override_existing_cvss():
    ghsa = FakeGHSAHTTPClient({"GHSA-abcd": _make_ghsa_advisory(
        cvss_score=9.1)})
    f = new_finding(purl="pkg:npm/x@1", vuln_id="GHSA-abcd",
                    severity="high", manifest_path="/a", target="local")
    f["cvss_score"] = 9.8
    enrich_with_ghsa([f], ghsa)
    assert f["cvss_score"] == 9.8


def test_enrich_sets_description():
    ghsa = FakeGHSAHTTPClient({"GHSA-abcd": _make_ghsa_advisory()})
    f = new_finding(purl="pkg:npm/x@1", vuln_id="GHSA-abcd",
                    severity="high", manifest_path="/a", target="local")
    assert not f.get("description")
    enrich_with_ghsa([f], ghsa)
    assert f["description"] == "Test advisory"


def test_enrich_skips_non_ghsa_vuln_id():
    ghsa = FakeGHSAHTTPClient({})
    f = new_finding(purl="pkg:npm/x@1", vuln_id="CVE-2024-1",
                    severity="critical", manifest_path="/a", target="local")
    enrich_with_ghsa([f], ghsa)
    assert "ghsa" not in f


def test_enrich_skips_scan_error():
    ghsa = FakeGHSAHTTPClient({"GHSA-abcd": _make_ghsa_advisory()})
    f = new_finding(purl="pkg:scan-error/x@-", vuln_id="GHSA-abcd",
                    severity="info", manifest_path="/a", target="local",
                    status="SCAN_ERROR")
    enrich_with_ghsa([f], ghsa)
    assert "ghsa" not in f


def test_enrich_skips_when_advisory_not_found():
    ghsa = FakeGHSAHTTPClient({})
    f = new_finding(purl="pkg:npm/x@1", vuln_id="GHSA-missing",
                    severity="high", manifest_path="/a", target="local")
    enrich_with_ghsa([f], ghsa)
    assert "ghsa" not in f


def test_enrich_withdrawn_advisory_still_attached():
    ghsa = FakeGHSAHTTPClient({
        "GHSA-abcd": _make_ghsa_advisory(withdrawn_at="2025-01-01T00:00:00Z")
    })
    f = new_finding(purl="pkg:npm/x@1", vuln_id="GHSA-abcd",
                    severity="high", manifest_path="/a", target="local")
    enrich_with_ghsa([f], ghsa)
    assert f.get("ghsa") is not None
    assert f["ghsa"]["withdrawn_at"] == "2025-01-01T00:00:00Z"


def test_enrich_cve_in_aliases_prevents_re_injection():
    """CVE already in aliases from osv-scanner — GHSA advisory cve_id is not added twice."""
    ghsa = FakeGHSAHTTPClient({"GHSA-abcd": _make_ghsa_advisory(
        cve_id="CVE-2019-10744")})
    f = new_finding(purl="pkg:npm/lodash@4.17.10", vuln_id="GHSA-abcd",
                    severity="high", manifest_path="/a", target="local",
                    aliases=["CVE-2019-10744"])
    enrich_with_ghsa([f], ghsa)
    assert f["aliases"].count("CVE-2019-10744") == 1
