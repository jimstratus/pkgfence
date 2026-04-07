"""Tests for local scanner orchestration."""
from unittest.mock import patch, MagicMock
import pytest

from scripts.scan_local import detect_scanner


def test_detect_osv_scanner_installed():
    fake_result = MagicMock()
    fake_result.returncode = 0
    fake_result.stdout = "osv-scanner version 2.3.3\nbuilt at 2026-02-11"
    with patch("scripts.scan_local.subprocess.run", return_value=fake_result):
        version = detect_scanner("osv-scanner")
    assert version == "2.3.3"


def test_detect_osv_scanner_not_installed():
    with patch("scripts.scan_local.subprocess.run", side_effect=FileNotFoundError):
        version = detect_scanner("osv-scanner")
    assert version is None


def test_detect_osv_scanner_below_minimum_version():
    """Scanner installed but below 2.0.0 floor — return version, caller filters."""
    fake_result = MagicMock()
    fake_result.returncode = 0
    fake_result.stdout = "osv-scanner version 1.9.0"
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


from scripts.scan_local import parse_osv_output


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
