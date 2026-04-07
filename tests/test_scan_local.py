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
