"""Tests for local scanner orchestration."""
from unittest.mock import patch, MagicMock
import pytest

from scripts.scan_local import detect_scanner


def test_detect_osv_scanner_installed():
    fake_result = MagicMock()
    fake_result.returncode = 0
    fake_result.stdout = "osv-scanner version 2.3.3\nbuilt at 2026-02-11"
    with patch("scripts.scan_local.shutil.which", return_value="osv-scanner"):
        with patch("scripts.scan_local.subprocess.run", return_value=fake_result):
            version = detect_scanner("osv-scanner")
    assert version == "2.3.3"


def test_detect_osv_scanner_not_installed():
    with patch("scripts.scan_local.shutil.which", return_value=None):
        version = detect_scanner("osv-scanner")
    assert version is None


def test_detect_osv_scanner_below_minimum_version():
    """Scanner installed but below 2.0.0 floor — return version, caller filters."""
    fake_result = MagicMock()
    fake_result.returncode = 0
    fake_result.stdout = "osv-scanner version 1.9.0"
    with patch("scripts.scan_local.shutil.which", return_value="osv-scanner"):
        with patch("scripts.scan_local.subprocess.run", return_value=fake_result):
            version = detect_scanner("osv-scanner")
    assert version == "1.9.0"


from scripts.scan_local import run_osv_scanner_lockfile, ScannerError


SAMPLE_OSV_OUTPUT_NO_VULNS = """{
  "results": []
}"""

SAMPLE_OSV_OUTPUT_WITH_VULN = """{
  "results": [
    {
      "source": {"path": "package-lock.json", "type": "lockfile"},
      "packages": [
        {
          "package": {"name": "lodash", "version": "4.17.10", "ecosystem": "npm"},
          "vulnerabilities": [
            {
              "id": "GHSA-jf85-cpcp-j695",
              "summary": "Prototype Pollution in lodash",
              "severity": [{"type": "CVSS_V3", "score": "9.1"}]
            }
          ]
        }
      ]
    }
  ]
}"""


def test_osv_scanner_exit_code_0_is_success_no_vulns():
    fake_result = MagicMock()
    fake_result.returncode = 0
    fake_result.stdout = SAMPLE_OSV_OUTPUT_NO_VULNS
    fake_result.stderr = ""
    with patch("scripts.scan_local.subprocess.run", return_value=fake_result):
        raw_json = run_osv_scanner_lockfile("/tmp/fake/package-lock.json")
    assert '"results": []' in raw_json


def test_osv_scanner_exit_code_1_is_success_with_findings():
    """CRITICAL: exit code 1 means vulns found, NOT error. Treat as success."""
    fake_result = MagicMock()
    fake_result.returncode = 1
    fake_result.stdout = SAMPLE_OSV_OUTPUT_WITH_VULN
    fake_result.stderr = ""
    with patch("scripts.scan_local.subprocess.run", return_value=fake_result):
        raw_json = run_osv_scanner_lockfile("/tmp/fake/package-lock.json")
    assert "GHSA-jf85-cpcp-j695" in raw_json


def test_osv_scanner_exit_code_2_is_error():
    fake_result = MagicMock()
    fake_result.returncode = 2
    fake_result.stdout = ""
    fake_result.stderr = "scanner internal error: invalid input"
    with patch("scripts.scan_local.subprocess.run", return_value=fake_result):
        with pytest.raises(ScannerError, match="exit 2"):
            run_osv_scanner_lockfile("/tmp/fake/package-lock.json")


def test_osv_scanner_exit_code_128_is_empty_lockfile():
    """Exit 128 = 'No package sources found' — Task 8.5 handles via SCAN_ERROR.
    For Task 8.2's purposes, we raise a specific subclass that the orchestrator
    can catch and convert to a SCAN_ERROR finding."""
    from scripts.scan_local import EmptyLockfileError
    fake_result = MagicMock()
    fake_result.returncode = 128
    fake_result.stdout = ""
    fake_result.stderr = "No package sources found"
    with patch("scripts.scan_local.subprocess.run", return_value=fake_result):
        with pytest.raises(EmptyLockfileError):
            run_osv_scanner_lockfile("/tmp/fake/package-lock.json")


from scripts.scan_local import parse_osv_output, _extract_cvss_score, _extract_severity


def test_parse_osv_output_extracts_findings():
    findings = parse_osv_output(SAMPLE_OSV_OUTPUT_WITH_VULN, manifest_path="/tmp/fake/package-lock.json", target="fake-target")
    assert len(findings) == 1
    f = findings[0]
    assert f["vuln_id"] == "GHSA-jf85-cpcp-j695"
    assert f["purl"] == "pkg:npm/lodash@4.17.10"
    assert f["manifest_path"] == "/tmp/fake/package-lock.json"
    assert f["target"] == "fake-target"
    assert f["scanner_source"] == "osv-scanner"
    assert "Prototype Pollution" in f.get("description", "")


def test_parse_osv_output_empty_results_returns_empty_list():
    findings = parse_osv_output(SAMPLE_OSV_OUTPUT_NO_VULNS, manifest_path="/tmp/foo", target="t")
    assert findings == []


def test_scan_manifest_falls_back_to_osv_api_when_scanner_missing(tmp_path):
    """When osv-scanner isn't installed, scan_manifest reads the lockfile
    and queries OSV API directly via OSVClient."""
    from scripts.scan_local import scan_manifest

    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text("""{
  "name": "test", "version": "1.0.0", "lockfileVersion": 3,
  "packages": {
    "": {"name": "test", "version": "1.0.0"},
    "node_modules/lodash": {"version": "4.17.10"}
  }
}""")

    fake_osv_results = [{
        "vulns": [{"id": "GHSA-jf85-cpcp-j695", "summary": "Prototype pollution"}]
    }]

    # detect_scanner returns None (not installed) -> fall back to OSVClient
    with patch("scripts.scan_local.detect_scanner", return_value=None):
        with patch("scripts.scan_local.OSVClient") as mock_client_cls:
            mock_instance = MagicMock()
            mock_instance.querybatch.return_value = fake_osv_results
            mock_client_cls.return_value = mock_instance
            findings = scan_manifest(
                manifest={"path": str(lockfile), "ecosystem": "npm",
                          "target": "test", "manifest_hash": "abc"},
            )

    assert len(findings) == 1
    assert findings[0]["vuln_id"] == "GHSA-jf85-cpcp-j695"
    assert findings[0]["scanner_source"] == "osv-api"


def test_scan_manifest_safely_continues_on_empty_lockfile():
    """EmptyLockfileError -> SCAN_ERROR record, no exception propagates."""
    from scripts.scan_local import scan_manifest_safely, EmptyLockfileError

    with patch("scripts.scan_local.detect_scanner", return_value="2.3.3"):
        with patch("scripts.scan_local.run_osv_scanner_lockfile",
                   side_effect=EmptyLockfileError("no package sources found")):
            findings = scan_manifest_safely({
                "path": "/tmp/fake/package-lock.json",
                "ecosystem": "npm",
                "target": "fake",
                "manifest_hash": "abc",
            })
    assert len(findings) == 1
    assert findings[0]["status"] == "SCAN_ERROR"
    assert findings[0]["target"] == "fake"
    assert "no package sources found" in findings[0].get("description", "").lower()


def test_scan_manifest_safely_continues_on_scanner_error():
    """ScannerError -> SCAN_ERROR record, no exception propagates."""
    from scripts.scan_local import scan_manifest_safely

    with patch("scripts.scan_local.detect_scanner", return_value="2.3.3"):
        with patch("scripts.scan_local.run_osv_scanner_lockfile",
                   side_effect=ScannerError("scanner crashed")):
            findings = scan_manifest_safely({
                "path": "/tmp/fake/package-lock.json",
                "ecosystem": "npm",
                "target": "fake",
                "manifest_hash": "abc",
            })
    assert len(findings) == 1
    assert findings[0]["status"] == "SCAN_ERROR"


def test_detect_scanner_uses_shutil_which():
    """v0.1.1 fix: detect_scanner uses shutil.which() to resolve scoop
    shims and other PATH-based wrappers, then invokes via the resolved path."""
    fake_result = MagicMock()
    fake_result.returncode = 0
    fake_result.stdout = "osv-scanner version 2.3.3"
    with patch("scripts.scan_local.shutil.which", return_value="C:/Users/ryanm/scoop/shims/osv-scanner.cmd"):
        with patch("scripts.scan_local.subprocess.run", return_value=fake_result) as mock_run:
            version = detect_scanner("osv-scanner")
    assert version == "2.3.3"
    # Verify subprocess.run was called with the resolved path, not the bare name
    call_args = mock_run.call_args
    args_passed = call_args[0][0] if call_args[0] else call_args[1].get("args", [])
    assert args_passed[0] == "C:/Users/ryanm/scoop/shims/osv-scanner.cmd"


def test_detect_scanner_returns_none_when_which_returns_none():
    """v0.1.1 fix: if shutil.which can't find it, return None without
    even invoking subprocess."""
    with patch("scripts.scan_local.shutil.which", return_value=None):
        version = detect_scanner("osv-scanner")
    assert version is None


def test_detect_scanner_parses_colon_version_format():
    """v0.1.1 fix: osv-scanner v2.3.3 emits 'osv-scanner version: 2.3.3'
    (with a colon), not 'osv-scanner version 2.3.3'. The regex must
    accept both."""
    fake_result = MagicMock()
    fake_result.returncode = 0
    fake_result.stdout = (
        "osv-scanner version: 2.3.3\n"
        "osv-scalibr version: 0.4.2\n"
        "commit: b97d1de7d8c3c7de8c11308b3d9cb5bbf3f7a0e9\n"
        "built at: 2026-02-11T23:42:50Z\n"
    )
    with patch("scripts.scan_local.shutil.which", return_value="osv-scanner"):
        with patch("scripts.scan_local.subprocess.run", return_value=fake_result):
            version = detect_scanner("osv-scanner")
    assert version == "2.3.3"


def test_scan_all_manifests_continues_on_one_bad_target():
    """One target failing must not block other targets from scanning."""
    from scripts.scan_local import scan_all_manifests
    from scripts.lib.types import new_finding

    manifests = [
        {"path": "/tmp/good/package-lock.json", "ecosystem": "npm", "target": "good", "manifest_hash": "1"},
        {"path": "/tmp/bad/package-lock.json", "ecosystem": "npm", "target": "bad", "manifest_hash": "2"},
    ]

    def mock_scan(manifest):
        if manifest["target"] == "bad":
            raise ScannerError("simulated failure")
        return [new_finding(
            purl="pkg:npm/lodash@4.17.10",
            vuln_id="GHSA-jf85-cpcp-j695",
            severity="high",
            manifest_path=manifest["path"],
            target=manifest["target"],
        )]

    with patch("scripts.scan_local.scan_manifest", side_effect=mock_scan):
        all_findings = scan_all_manifests(manifests)

    # Should have 2 findings: one good (real vuln) + one SCAN_ERROR for bad
    targets = {f["target"] for f in all_findings}
    assert targets == {"good", "bad"}
    bad_findings = [f for f in all_findings if f["target"] == "bad"]
    assert len(bad_findings) == 1
    assert bad_findings[0]["status"] == "SCAN_ERROR"


def test_extract_cvss_score_numeric_string():
    sev = [{"type": "CVSS_V3", "score": "9.8"}]
    assert _extract_cvss_score(sev) == 9.8


def test_extract_cvss_score_from_vector():
    sev = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H 9.8"}]
    # Spec version 3.1 is in valid range, but 9.8 is larger — max wins
    assert _extract_cvss_score(sev) == 9.8


def test_extract_cvss_score_returns_none_when_absent():
    assert _extract_cvss_score([]) is None
    assert _extract_cvss_score([{"type": "OTHER", "score": "9.8"}]) is None


def test_parse_osv_output_sets_cvss_score():
    raw = '{"results":[{"source":{"path":"/a","type":"lockfile"},"packages":[{"package":{"name":"lodash","version":"4.17.21","ecosystem":"npm"},"vulnerabilities":[{"id":"CVE-2024-1","summary":"test","severity":[{"type":"CVSS_V3","score":"9.8"}],"aliases":[]}]}]}]}'
    findings = parse_osv_output(raw, "/a/package-lock.json", "local")
    assert len(findings) == 1
    assert findings[0].get("cvss_score") == 9.8


def test_extract_cvss_score_from_real_vector_only_string():
    """Real osv-scanner emits the bare CVSS vector with NO appended base
    score. 9.8-critical must not be read as spec-version 3.1 (issue #9)."""
    sev = [{"type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
    assert _extract_cvss_score(sev) == 9.8


def test_extract_severity_from_real_vector_only_string():
    sev = [{"type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
    assert _extract_severity(sev) == "critical"


def test_extract_cvss_score_v2_vector():
    sev = [{"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:C/I:C/A:C"}]
    assert _extract_cvss_score(sev) == 10.0


def test_extract_cvss_score_v4_vector():
    """CVSS_V4 entries are already common in OSV data — a V4 vector must
    decode (and never crash the scan)."""
    sev = [{"type": "CVSS_V4",
            "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}]
    assert _extract_cvss_score(sev) == 9.3
    assert _extract_severity(sev) == "critical"


def test_extract_cvss_score_invalid_vector_returns_none():
    sev = [{"type": "CVSS_V3", "score": "CVSS:3.1/GARBAGE"}]
    assert _extract_cvss_score(sev) is None
    assert _extract_severity(sev) == "medium"
