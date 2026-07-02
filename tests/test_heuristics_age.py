"""Tests for age heuristic (new-package, new-version, abandoned)."""
import datetime
from scripts.lib.types import new_finding
from scripts.heuristics import _check_age


def _d(days_ago: int) -> str:
    dt = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days_ago)
    return dt.isoformat()


def test_check_age_flags_new_package():
    f = new_finding(purl="pkg:npm/new-kid@1.0.0", vuln_id="GHSA-x",
                    severity="medium", manifest_path="/a", target="local")
    manifest_data = {"/a": {"npm:new-kid": {"created": _d(5)}}}
    _check_age([f], manifest_data, {"age": {"new_package_days": 30}})
    assert any("age:new-package" in flag for flag in f.get("heuristic_flags", []))


def test_check_age_no_flag_for_old_package():
    f = new_finding(purl="pkg:npm/old-kid@1.0.0", vuln_id="GHSA-x",
                    severity="medium", manifest_path="/a", target="local")
    manifest_data = {"/a": {"npm:old-kid": {"created": _d(100)}}}
    _check_age([f], manifest_data, {"age": {"new_package_days": 30}})
    assert not any("age:new-package" in flag for flag in f.get("heuristic_flags", []))


def test_check_age_flags_abandoned():
    f = new_finding(purl="pkg:npm/old-kid@1.0.0", vuln_id="GHSA-x",
                    severity="low", manifest_path="/a", target="local")
    manifest_data = {"/a": {"npm:old-kid": {"modified": _d(400)}}}
    _check_age([f], manifest_data, {"age": {"abandoned_days": 365}})
    assert any("age:abandoned" in flag for flag in f.get("heuristic_flags", []))


def test_check_age_no_flag_for_maintained():
    f = new_finding(purl="pkg:npm/active@1.0.0", vuln_id="GHSA-x",
                    severity="medium", manifest_path="/a", target="local")
    manifest_data = {"/a": {"npm:active": {"modified": _d(100)}}}
    _check_age([f], manifest_data, {"age": {"abandoned_days": 365}})
    assert not any("age:abandoned" in flag for flag in f.get("heuristic_flags", []))


def test_check_age_skips_when_no_manifest_data():
    f = new_finding(purl="pkg:npm/unknown@1.0.0", vuln_id="GHSA-x",
                    severity="medium", manifest_path="/a", target="local")
    _check_age([f], {}, {"age": {"new_package_days": 30}})
    assert "heuristic_flags" not in f


def test_check_age_skips_scan_error():
    f = new_finding(purl="pkg:npm/x@1", vuln_id="GHSA-x",
                    severity="info", manifest_path="/a", target="local",
                    status="SCAN_ERROR")
    _check_age([f], {}, {"age": {"new_package_days": 1}})
    assert "heuristic_flags" not in f


def test_check_age_handles_missing_timestamps():
    f = new_finding(purl="pkg:npm/notimestamp@1.0.0", vuln_id="GHSA-x",
                    severity="medium", manifest_path="/a", target="local")
    manifest_data = {"/a": {"npm:notimestamp": {}}}  # No timestamps
    _check_age([f], manifest_data, {"age": {"new_package_days": 30}})
    assert "heuristic_flags" not in f
