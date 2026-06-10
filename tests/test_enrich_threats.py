"""Tests for threat enrichment overlays."""
from unittest.mock import MagicMock
from scripts.lib.kev_client import KEVClient
from scripts.lib.types import new_finding


def test_enrich_with_kev_marks_actively_exploited(tmp_state):
    findings = [
        new_finding(
            purl="pkg:generic/xz@5.6.0",
            vuln_id="CVE-2024-3094",
            severity="critical",
            manifest_path="/tmp/foo",
            target="t",
        ),
        new_finding(
            purl="pkg:npm/foo@1.0.0",
            vuln_id="GHSA-xxx-yyy-zzz",
            severity="low",
            manifest_path="/tmp/bar",
            target="t",
            aliases=["CVE-2099-99999"],
        ),
    ]
    from scripts.enrich_threats import enrich_with_kev

    kev = KEVClient(cache_dir=tmp_state / "cache" / "kev")
    kev._known_set = {"CVE-2024-3094"}
    kev._loaded = True

    enriched = enrich_with_kev(findings, kev)
    assert enriched[0]["actively_exploited"] is True
    assert enriched[1]["actively_exploited"] is False


def test_enrich_with_kev_checks_aliases_for_cve_id():
    """If primary vuln_id is GHSA but aliases contain a CVE that's in KEV,
    the finding should still be marked actively_exploited."""
    from scripts.enrich_threats import enrich_with_kev
    from pathlib import Path
    from scripts.lib.kev_client import KEVClient
    import tempfile

    tmp = Path(tempfile.mkdtemp())
    findings = [
        new_finding(
            purl="pkg:npm/lodash@4.17.10",
            vuln_id="GHSA-jf85-cpcp-j695",  # not in KEV directly
            severity="high",
            manifest_path="/tmp/foo",
            target="t",
            aliases=["CVE-2019-10744"],  # this IS in KEV
        ),
    ]

    kev = KEVClient(cache_dir=tmp / "cache" / "kev")
    kev._known_set = {"CVE-2019-10744"}
    kev._loaded = True

    enriched = enrich_with_kev(findings, kev)
    assert enriched[0]["actively_exploited"] is True


def test_kev_enrichment_leaves_scan_error_records_unchanged():
    from scripts.enrich_threats import enrich_with_kev
    kev = MagicMock()
    f = {"purl": "pkg:scan-error/bespin@-", "vuln_id": "SCAN_ERROR",
         "severity": "info", "manifest_path": "/x", "target": "bespin",
         "status": "SCAN_ERROR"}
    result = enrich_with_kev([f], kev)
    assert "actively_exploited" not in result[0]
    kev.is_known_exploited.assert_not_called()
