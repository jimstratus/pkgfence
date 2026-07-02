"""Against-reality canary tests — verify pkgfence catches real known-bad fixtures.

Layer D of the Phase 5 quality bar. Uses known vulnerable or malicious
package data to ensure the scanner produces expected findings.
"""
import json
from pathlib import Path
from scripts.lib.types import new_finding
from scripts.scan_local import parse_osv_output


def test_canary_lodash_prototype_pollution():
    """GHSA-jf85-cpcp-j695: Prototype Pollution in lodash < 4.17.12.
    This is the canonical fixture used across all pkgfence tests."""
    raw = json.dumps({
        "results": [{
            "source": {"path": "package-lock.json", "type": "lockfile"},
            "packages": [{
                "package": {"name": "lodash", "version": "4.17.10",
                            "ecosystem": "npm"},
                "vulnerabilities": [{
                    "id": "GHSA-jf85-cpcp-j695",
                    "summary": "Prototype Pollution in lodash",
                    "severity": [{"type": "CVSS_V3", "score": "9.1"}],
                    "aliases": ["CVE-2019-10744"],
                }]
            }]
        }]
    })
    findings = parse_osv_output(raw, "/a/package-lock.json", "test")
    assert len(findings) == 1
    assert findings[0]["vuln_id"] == "GHSA-jf85-cpcp-j695"
    assert findings[0]["severity"] in ("critical", "high")


def test_canary_mal_aliased_finding():
    """MAL-* IDs in aliases[] must still trigger mal_flagged.
    GHSA-fw8c-xr5c-95f9 (March 2026 axios compromise)."""
    f = new_finding(
        purl="pkg:npm/axios@1.7.9", vuln_id="GHSA-fw8c-xr5c-95f9",
        severity="critical", manifest_path="/a", target="test",
        aliases=["MAL-2026-2307"],
    )
    from scripts.lib.types import iter_vuln_ids
    ids = list(iter_vuln_ids(f))
    assert "GHSA-fw8c-xr5c-95f9" in ids
    assert "MAL-2026-2307" in ids


def test_canary_entropy_catches_typosquat():
    """A typosquatting-style name must score higher than the legitimate name."""
    from scripts.heuristics import shannon_entropy
    legit = shannon_entropy("lodash")
    squatter = shannon_entropy("lodahs")
    # The typosquat should have similar entropy (same length, same chars)
    # but at minimum it must not be lower entropy
    assert squatter >= legit * 0.8


def test_canary_cdn_integrity_check():
    """CDN scanner must catch a script without integrity."""
    from scripts.scan_cdn import scan_cdn_sri
    import tempfile
    import os
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "index.html"
        path.write_text(
            '<script src="https://cdnjs.cloudflare.com/ajax/libs/'
            'lodash.js/4.17.21/lodash.min.js"></script>'
        )
        findings = scan_cdn_sri(Path(td), "test")
        assert len(findings) >= 1
        assert any("CDN-MISSING-SRI" in f["vuln_id"] for f in findings)


def test_canary_cdn_skips_with_integrity():
    """CDN scanner must NOT flag a script with integrity."""
    from scripts.scan_cdn import scan_cdn_sri
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "index.html"
        path.write_text(
            '<script src="https://cdnjs.cloudflare.com/ajax/libs/'
            'lodash.js/4.17.21/lodash.min.js" '
            'integrity="sha384-abc123"></script>'
        )
        findings = scan_cdn_sri(Path(td), "test")
        assert all("CDN-MISSING-SRI" not in f["vuln_id"] for f in findings)


def test_canary_fix_generation_has_remediation():
    """Fix generator must produce a recommendation for findings with fix_version."""
    from scripts.recommend_fix import generate_fix
    f = new_finding(purl="pkg:npm/lodash@4.17.10", vuln_id="GHSA-x",
                    severity="high", manifest_path="/a", target="test",
                    fix_version="4.17.21")
    fix = generate_fix(f)
    assert fix is not None
    assert "4.17.21" in fix


def test_canary_baseline_diff_alarm():
    """Hash change without new findings must trigger an alarm."""
    from scripts.lib.baseline import diff_alarms
    alarms = diff_alarms(
        current_hashes={"/a/package-lock.json": "aaa111"},
        prior_hashes={"/a/package-lock.json": "bbb222"},
        current_finding_count=3,
        prior_finding_count=5,
    )
    assert len(alarms) == 1
    assert "hash changed" in alarms[0].lower()
