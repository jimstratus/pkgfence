import pytest

from scripts.lib.types import new_finding
from scripts.enrich_epss import enrich_with_epss, _find_cve_id


class FakeEPSSClient:
    """Test double — avoids hitting real EPSSClient.lookup logic."""
    def __init__(self, scores):
        self._scores = scores
        self.is_degraded = False

    def lookup(self, cve_id):
        return self._scores.get(cve_id)


def test_finding_with_cve_in_vuln_id_gets_epss():
    epss = FakeEPSSClient({"CVE-2024-1": (0.85, 0.99)})
    f = new_finding(purl="pkg:npm/x@1", vuln_id="CVE-2024-1",
                    severity="high", manifest_path="/a", target="local")
    enrich_with_epss([f], epss)
    assert f["epss_score"] == 0.85
    assert f["epss_percentile"] == 0.99


def test_finding_with_cve_in_aliases_gets_epss():
    epss = FakeEPSSClient({"CVE-2024-2": (0.70, 0.95)})
    f = new_finding(purl="pkg:npm/x@1", vuln_id="GHSA-abcd",
                    severity="high", manifest_path="/a", target="local",
                    aliases=["CVE-2024-2"])
    enrich_with_epss([f], epss)
    assert f["epss_score"] == 0.70
    assert f["epss_percentile"] == 0.95


def test_finding_without_cve_unchanged():
    epss = FakeEPSSClient({"CVE-2024-3": (0.5, 0.5)})
    f = new_finding(purl="pkg:npm/evil@1", vuln_id="MAL-2024-1",
                    severity="critical", manifest_path="/a", target="local")
    enrich_with_epss([f], epss)
    assert "epss_score" not in f


def test_finding_with_unknown_cve_unchanged():
    epss = FakeEPSSClient({})
    f = new_finding(purl="pkg:npm/x@1", vuln_id="CVE-9999-9999",
                    severity="high", manifest_path="/a", target="local")
    enrich_with_epss([f], epss)
    assert "epss_score" not in f


def test_scan_error_findings_skipped():
    epss = FakeEPSSClient({"CVE-2024-1": (0.5, 0.5)})
    f = new_finding(purl="pkg:scan-error/x@-", vuln_id="SCAN_ERROR",
                    severity="info", manifest_path="/a", target="local",
                    status="SCAN_ERROR", aliases=["CVE-2024-1"])
    enrich_with_epss([f], epss)
    assert "epss_score" not in f


def test_find_cve_id_prefers_vuln_id():
    f = {"vuln_id": "CVE-2024-1", "aliases": ["CVE-2024-99"]}
    assert _find_cve_id(f) == "CVE-2024-1"


def test_find_cve_id_falls_back_to_aliases():
    f = {"vuln_id": "GHSA-1", "aliases": ["GHSA-2", "CVE-2024-99"]}
    assert _find_cve_id(f) == "CVE-2024-99"


def test_find_cve_id_returns_none_when_no_cve():
    f = {"vuln_id": "GHSA-1", "aliases": ["GHSA-2"]}
    assert _find_cve_id(f) is None
