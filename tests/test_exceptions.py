"""Tests for the exceptions/waivers loader."""
import datetime
import pytest
from scripts.lib.exceptions import load_exceptions, is_exception_active, ExceptionsError


def test_load_empty_exceptions(tmp_path):
    exc_path = tmp_path / "exceptions.yaml"
    exc_path.write_text("[]\n")
    assert load_exceptions(exc_path) == []


def test_load_exceptions_returns_list(tmp_path):
    exc_path = tmp_path / "exceptions.yaml"
    exc_path.write_text("""
- id: EXC-001
  vuln_id: GHSA-xxx
  package: lodash
  version_range: "<4.17.21"
  scope: "D:\\\\projects\\\\old"
  reason: "Prototype, accepted"
  approved_by: ryan
  approved_on: "2026-04-06"
  expires: "2026-10-06"
""")
    excs = load_exceptions(exc_path)
    assert len(excs) == 1
    assert excs[0]["id"] == "EXC-001"
    assert excs[0]["vuln_id"] == "GHSA-xxx"


def test_load_missing_file_returns_empty(tmp_path):
    """No exceptions file = no exceptions, not an error."""
    nonexistent = tmp_path / "does-not-exist.yaml"
    assert load_exceptions(nonexistent) == []


def test_is_exception_active_unexpired():
    today = datetime.date(2026, 4, 6)
    exc = {"expires": "2026-10-06"}
    assert is_exception_active(exc, today) is True


def test_is_exception_active_expired():
    today = datetime.date(2026, 4, 6)
    exc = {"expires": "2026-04-05"}
    assert is_exception_active(exc, today) is False


def test_is_exception_active_no_expires_field():
    """Mandatory expires; missing → treat as inactive (defensive)."""
    exc = {}
    today = datetime.date(2026, 4, 6)
    assert is_exception_active(exc, today) is False
