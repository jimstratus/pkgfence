"""Cache-path safety for deps.dev and Scorecard clients.

Verifies sanitization blocks path traversal (`..`) and that cache paths never
resolve outside the cache directory, even for user-influenced inputs (lookup
mode takes a purl / repo URL from argv).
"""
from scripts.lib.depsdev_client import DepsDevClient, _safe_component as depsdev_safe
from scripts.lib.scorecard_client import ScorecardClient, _safe_component as scorecard_safe


def test_safe_component_collapses_dot_segments():
    for safe in (depsdev_safe, scorecard_safe):
        assert safe("..") == "_"
        assert safe(".") == "_"
        assert safe("") == "_"
        # dots inside a real name are preserved
        assert safe("lodash.js") == "lodash.js"


def test_safe_component_strips_slashes():
    for safe in (depsdev_safe, scorecard_safe):
        assert "/" not in safe("../../etc")
        assert "/" not in safe("foo/bar")


def test_depsdev_cache_path_stays_under_cache_dir(tmp_path):
    client = DepsDevClient(cache_dir=tmp_path / "deps")
    path = client._cache_path("..", "..", "..")
    resolved = path.resolve()
    assert resolved.is_relative_to((tmp_path / "deps").resolve()), resolved


def test_scorecard_cache_path_stays_under_cache_dir(tmp_path):
    client = ScorecardClient(cache_dir=tmp_path / "sc")
    path = client._cache_path("..", "..")
    resolved = path.resolve()
    assert resolved.is_relative_to((tmp_path / "sc").resolve()), resolved


def test_depsdev_cache_path_real_name_unchanged(tmp_path):
    client = DepsDevClient(cache_dir=tmp_path / "deps")
    path = client._cache_path("npm", "lodash.js", "4.17.21")
    assert path == (tmp_path / "deps" / "npm" / "lodash.js" / "4.17.21.json")