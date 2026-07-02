"""Tests for Shannon entropy typosquatting detection."""
import pytest
from scripts.lib.types import new_finding
from scripts.heuristics import shannon_entropy, _check_entropy


def test_shannon_entropy_low_for_structured_name():
    assert shannon_entropy("lodash") == pytest.approx(2.5, abs=0.5)
    assert shannon_entropy("express") == pytest.approx(2.5, abs=0.5)
    assert shannon_entropy("react") == pytest.approx(2.0, abs=0.5)


def test_shannon_entropy_high_for_random_name():
    assert shannon_entropy("a1b2c3d4e5f6g7h8") >= 4.0


def test_shannon_entropy_max_for_unique_chars():
    assert shannon_entropy("abcdefghijklmnopqrstuvwxyz") == pytest.approx(4.7, abs=0.1)


def test_shannon_entropy_zero_for_empty():
    assert shannon_entropy("") == 0.0


def test_shannon_entropy_zero_for_single_char():
    assert shannon_entropy("a") == 0.0


def test_check_entropy_flags_above_threshold():
    f = new_finding(purl="pkg:npm/a1b2c3d4e5f6@1.0", vuln_id="GHSA-x",
                    severity="medium", manifest_path="/a", target="local")
    _check_entropy([f], {"entropy": {"threshold": 3.0}})
    assert any("entropy:" in flag for flag in f.get("heuristic_flags", []))


def test_check_entropy_skips_below_threshold():
    f = new_finding(purl="pkg:npm/lodash@4.17.10", vuln_id="GHSA-x",
                    severity="medium", manifest_path="/a", target="local")
    _check_entropy([f], {"entropy": {"threshold": 7.0}})
    flags = f.get("heuristic_flags", [])
    assert not any("entropy:" in flag for flag in flags)


def test_check_entropy_skips_scan_error():
    f = new_finding(purl="pkg:scan-error/x@-", vuln_id="GHSA-x",
                    severity="info", manifest_path="/a", target="local",
                    status="SCAN_ERROR")
    _check_entropy([f], {"entropy": {"threshold": 1.0}})
    assert "heuristic_flags" not in f


def test_check_entropy_stores_score_even_below_threshold():
    f = new_finding(purl="pkg:npm/express@4.18.2", vuln_id="GHSA-x",
                    severity="high", manifest_path="/a", target="local")
    _check_entropy([f], {"entropy": {"threshold": 7.0}})
    assert f.get("entropy_score") is not None
    assert 0.0 <= f["entropy_score"] <= 10.0
