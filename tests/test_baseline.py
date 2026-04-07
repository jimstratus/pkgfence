"""Tests for baseline save/load and diff."""
import json
from pathlib import Path
from scripts.lib.baseline import save_baseline, load_baseline


def test_save_and_load_baseline_roundtrip(tmp_state):
    baseline = {
        "scan_timestamp": "2026-04-07T00:00:00Z",
        "manifest_hashes": {
            "D:\\projects\\foo\\package-lock.json": "abc123",
            "D:\\projects\\bar\\package-lock.json": "def456",
        },
        "findings": [
            {"purl": "pkg:npm/foo@1.0.0", "vuln_id": "GHSA-xxx", "manifest_path": "/foo"}
        ],
    }
    path = tmp_state / "baselines" / "default.json"
    save_baseline(path, baseline)
    loaded = load_baseline(path)
    assert loaded == baseline


def test_load_missing_baseline_returns_none(tmp_state):
    path = tmp_state / "baselines" / "does-not-exist.json"
    assert load_baseline(path) is None


def test_save_baseline_creates_parent_dir(tmp_path):
    """save_baseline mkdirs parents if missing."""
    path = tmp_path / "deep" / "nested" / "baseline.json"
    save_baseline(path, {"x": 1})
    assert path.exists()


def test_diff_findings_tags_new_and_existing():
    from scripts.lib.baseline import diff_findings
    baseline = [
        {"purl": "pkg:npm/foo@1.0.0", "vuln_id": "GHSA-x", "manifest_path": "/foo"},
    ]
    current = [
        {"purl": "pkg:npm/foo@1.0.0", "vuln_id": "GHSA-x", "manifest_path": "/foo"},   # EXISTING
        {"purl": "pkg:npm/bar@2.0.0", "vuln_id": "GHSA-y", "manifest_path": "/bar"},   # NEW
    ]
    tagged = diff_findings(current, baseline)
    by_id = {f["vuln_id"]: f["diff_status"] for f in tagged}
    assert by_id["GHSA-x"] == "EXISTING"
    assert by_id["GHSA-y"] == "NEW"


def test_diff_findings_no_baseline_marks_all_new():
    from scripts.lib.baseline import diff_findings
    current = [
        {"purl": "pkg:npm/foo@1.0", "vuln_id": "GHSA-x", "manifest_path": "/foo"},
        {"purl": "pkg:npm/bar@2.0", "vuln_id": "GHSA-y", "manifest_path": "/bar"},
    ]
    tagged = diff_findings(current, baseline=None)
    assert all(f["diff_status"] == "NEW" for f in tagged)


def test_diff_findings_dedup_key_includes_manifest_path():
    """Same purl+vuln in different manifests are different findings."""
    from scripts.lib.baseline import diff_findings
    baseline = [
        {"purl": "pkg:npm/foo@1.0", "vuln_id": "GHSA-x", "manifest_path": "/path-a"},
    ]
    current = [
        {"purl": "pkg:npm/foo@1.0", "vuln_id": "GHSA-x", "manifest_path": "/path-a"},  # EXISTING
        {"purl": "pkg:npm/foo@1.0", "vuln_id": "GHSA-x", "manifest_path": "/path-b"},  # NEW
    ]
    tagged = diff_findings(current, baseline)
    statuses = sorted(f["diff_status"] for f in tagged)
    assert statuses == ["EXISTING", "NEW"]
