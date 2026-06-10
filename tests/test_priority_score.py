import pytest
from unittest.mock import patch

from scripts.lib.types import new_finding
from scripts.lib.priority import (
    compute_priority_score,
    apply_priority_scores,
    _SEVERITY_MIDPOINTS,
)
from scripts.scan_command import run_scan


def test_critical_with_kev_and_epss_scores_high():
    f = new_finding(purl="pkg:npm/x@1", vuln_id="CVE-2024-1",
                    severity="critical", manifest_path="/a", target="local")
    f["cvss_score"] = 9.8
    f["epss_score"] = 0.85
    f["actively_exploited"] = True
    score = compute_priority_score(f)
    # 0.4 * 0.98 + 0.3 * 0.85 + 0.3 * 1.0 = 0.392 + 0.255 + 0.3 = 0.947
    assert score == pytest.approx(0.947, abs=0.01)


def test_critical_no_epss_no_kev_uses_cvss_only():
    f = new_finding(purl="pkg:npm/x@1", vuln_id="CVE-2024-2",
                    severity="critical", manifest_path="/a", target="local")
    f["cvss_score"] = 9.0
    score = compute_priority_score(f)
    # 0.4 * 0.9 + 0.3 * 0 + 0.3 * 0 = 0.36
    assert score == pytest.approx(0.36, abs=0.01)


def test_no_cvss_falls_back_to_severity_midpoint():
    f = new_finding(purl="pkg:npm/x@1", vuln_id="GHSA-1",
                    severity="high", manifest_path="/a", target="local")
    score = compute_priority_score(f)
    # high midpoint = 8.0, normalized 0.8, * 0.4 = 0.32
    assert score == pytest.approx(0.32, abs=0.01)


def test_high_with_epss_kev_outscores_critical_alone():
    """High finding with EPSS and KEV can outscore critical with no enrichment."""
    critical = new_finding(purl="pkg:npm/a@1", vuln_id="CVE-2024-3",
                           severity="critical", manifest_path="/a", target="local")
    critical["cvss_score"] = 9.5

    high = new_finding(purl="pkg:npm/b@1", vuln_id="CVE-2024-4",
                       severity="high", manifest_path="/a", target="local")
    high["cvss_score"] = 8.0
    high["epss_score"] = 0.9
    high["actively_exploited"] = True

    crit_score = compute_priority_score(critical)
    high_score = compute_priority_score(high)
    assert high_score > crit_score


def test_info_severity_with_no_data_returns_low_score():
    f = new_finding(purl="pkg:npm/x@1", vuln_id="GHSA-2",
                    severity="info", manifest_path="/a", target="local")
    score = compute_priority_score(f)
    # info midpoint 1.0, * 0.1 / 10 → 0.04
    assert score == pytest.approx(0.04, abs=0.01)


def test_severity_midpoints_match_spec():
    assert _SEVERITY_MIDPOINTS["critical"] == 9.5
    assert _SEVERITY_MIDPOINTS["high"] == 8.0
    assert _SEVERITY_MIDPOINTS["medium"] == 5.5
    assert _SEVERITY_MIDPOINTS["low"] == 3.5
    assert _SEVERITY_MIDPOINTS["info"] == 1.0


def test_priority_score_in_unit_range():
    """Score is always in [0.0, 1.0] regardless of inputs."""
    f = new_finding(purl="pkg:npm/x@1", vuln_id="CVE-2024-5",
                    severity="critical", manifest_path="/a", target="local")
    f["cvss_score"] = 10.0
    f["epss_score"] = 1.0
    f["actively_exploited"] = True
    score = compute_priority_score(f)
    assert 0.0 <= score <= 1.0
    assert score == pytest.approx(1.0, abs=0.01)


def test_weights_come_from_defaults_yaml_shape():
    """Issue #14: changing a weight changes the score — no hardcoding."""
    f = {"severity": "high", "cvss_score": 8.0, "epss_score": 0.5,
         "actively_exploited": True}
    default = compute_priority_score(f)
    assert default == pytest.approx(0.4 * 0.8 + 0.3 * 0.5 + 0.3 * 1.0)
    cvss_only = compute_priority_score(
        f, weights={"weight_cvss": 1.0, "weight_epss": 0.0, "weight_kev": 0.0}
    )
    assert cvss_only == pytest.approx(0.8)


def test_apply_priority_scores_runs_on_final_severity():
    """Issue #11: a MAL-promoted finding must be scored as critical
    (midpoint 9.5), not with its pre-override severity."""
    mal = {"vuln_id": "MAL-2026-1", "severity": "critical",  # post-override
           "aliases": [], "status": "OK"}
    out = apply_priority_scores([mal], defaults={"triage": {}})
    assert out[0]["priority_score"] == pytest.approx(0.4 * 0.95)


def test_apply_priority_scores_skips_scan_error(tmp_path):
    """Issue #15: status records get NO priority_score."""
    err = {"vuln_id": "SCAN_ERROR", "severity": "info", "status": "SCAN_ERROR",
           "priority_score": 0.04}  # stale score from an old baseline
    out = apply_priority_scores([err], defaults=None)
    assert "priority_score" not in out[0]


def test_run_scan_threads_defaults_into_priority_stage(tmp_state, tmp_registry):
    """Issue #14 end-to-end: run_scan must pass the LOADED defaults to the
    priority stage — the original bug was load_defaults() discarding its
    return value, which a unit test on apply_priority_scores can't catch."""
    sentinel = {"triage": {"weight_cvss": 1.0, "weight_epss": 0.0, "weight_kev": 0.0}}
    with patch("scripts.scan_command.apply_priority_scores",
               side_effect=lambda fs, d: fs) as aps, \
         patch("scripts.scan_command.load_defaults", return_value=sentinel):
        run_scan(tmp_registry, tmp_state)
    assert aps.call_args.args[1] == sentinel
