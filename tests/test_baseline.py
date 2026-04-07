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
