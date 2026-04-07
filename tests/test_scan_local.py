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
