"""Tests for scripts/enrich_depsdev_scorecard.py — L3.7/L3.8 enrichment."""
from unittest.mock import MagicMock

from scripts.enrich_depsdev_scorecard import (
    _find_repo_url,
    _parse_github_url,
    _parse_purl_components,
    enrich_with_depsdev,
    enrich_with_scorecard,
)
from scripts.lib.types import new_finding


def test_parse_purl_components_basic():
    assert _parse_purl_components("pkg:npm/lodash@4.17.10") == (
        "npm", "lodash", "4.17.10",
    )


def test_parse_purl_components_scoped_npm():
    assert _parse_purl_components("pkg:npm/@babel/core@7.23.0") == (
        "npm", "@babel/core", "7.23.0",
    )


def test_parse_purl_components_rejects_non_purl():
    assert _parse_purl_components("npm/lodash@1.0.0") == ("", "", "")
    assert _parse_purl_components("pkg:npm") == ("", "", "")


def test_parse_purl_components_missing_version():
    assert _parse_purl_components("pkg:pypi/requests") == ("pypi", "requests", "")


def test_find_repo_url_accepts_depsdev_source_repo_label():
    """deps.dev real label is SOURCE_REPO, not 'source'/'repo'/'repository'."""
    f = new_finding(
        purl="pkg:npm/lodash@4.17.10",
        vuln_id="CVE-2019-10744",
        severity="high",
        manifest_path="/tmp/p",
        deps_dev={
            "links": [
                {"label": "HOMEPAGE", "url": "https://lodash.com"},
                {
                    "label": "SOURCE_REPO",
                    "url": "git+https://github.com/lodash/lodash.git",
                },
                {
                    "label": "ADVISORY",
                    "url": "https://github.com/advisories/GHSA-xxxx",
                },
            ],
        },
    )
    assert _find_repo_url(f) == "git+https://github.com/lodash/lodash.git"


def test_find_repo_url_ignores_ghsa_permalink_without_repo_label():
    f = new_finding(
        purl="pkg:npm/x@1",
        vuln_id="GHSA-aaaa-bbbb-cccc",
        severity="medium",
        manifest_path="/tmp/p",
        deps_dev={
            "links": [
                {
                    "label": "ADVISORY",
                    "url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
                },
            ],
        },
    )
    assert _find_repo_url(f) is None


def test_find_repo_url_accepts_repository_label_case_insensitive():
    f = new_finding(
        purl="pkg:npm/x@1",
        vuln_id="CVE-1",
        severity="low",
        manifest_path="/tmp/p",
        deps_dev={
            "links": [
                {"label": "Repository", "url": "https://github.com/foo/bar"},
            ],
        },
    )
    assert _find_repo_url(f) == "https://github.com/foo/bar"


def test_parse_github_url_basic():
    assert _parse_github_url("https://github.com/lodash/lodash") == (
        "lodash", "lodash",
    )


def test_parse_github_url_strips_git_suffix_and_git_plus_scheme():
    assert _parse_github_url("git+https://github.com/lodash/lodash.git") == (
        "lodash", "lodash",
    )


def test_parse_github_url_rejects_non_github_and_shallow_paths():
    assert _parse_github_url("https://gitlab.com/foo/bar") is None
    assert _parse_github_url("https://github.com/only-owner") is None
    assert _parse_github_url("https://www.github.com/foo/bar") is None


def test_parse_github_url_uses_owner_repo_ignoring_extra_path():
    assert _parse_github_url("https://github.com/foo/bar/tree/main") == (
        "foo", "bar",
    )


def test_enrich_with_depsdev_attaches_metadata():
    f = new_finding(
        purl="pkg:npm/lodash@4.17.10",
        vuln_id="CVE-2019-10744",
        severity="high",
        manifest_path="/tmp/p",
    )
    client = MagicMock()
    client.fetch_metadata.return_value = {
        "name": "lodash", "version": "4.17.10", "links": [],
    }
    enrich_with_depsdev([f], client)
    assert f["deps_dev"]["name"] == "lodash"
    client.fetch_metadata.assert_called_once_with("npm", "lodash", "4.17.10")


def test_enrich_with_depsdev_skips_scan_error_and_incomplete_purl():
    err = {
        "purl": "pkg:scan-error/x@-",
        "vuln_id": "SCAN_ERROR",
        "severity": "info",
        "manifest_path": "/x",
        "target": "t",
        "status": "SCAN_ERROR",
    }
    incomplete = new_finding(
        purl="pkg:npm/lodash",  # no version
        vuln_id="CVE-1",
        severity="low",
        manifest_path="/tmp/p",
    )
    client = MagicMock()
    enrich_with_depsdev([err, incomplete], client)
    client.fetch_metadata.assert_not_called()
    assert "deps_dev" not in err
    assert "deps_dev" not in incomplete


def test_enrich_with_scorecard_attaches_result_from_depsdev_source_repo():
    f = new_finding(
        purl="pkg:npm/lodash@4.17.10",
        vuln_id="CVE-2019-10744",
        severity="high",
        manifest_path="/tmp/p",
        deps_dev={
            "links": [
                {
                    "label": "SOURCE_REPO",
                    "url": "git+https://github.com/lodash/lodash.git",
                },
            ],
        },
    )
    client = MagicMock()
    client.get_score.return_value = {"repo": "lodash/lodash", "score": 7.5}
    enrich_with_scorecard([f], client)
    assert f["scorecard"]["score"] == 7.5
    client.get_score.assert_called_once_with("lodash", "lodash")


def test_enrich_with_scorecard_skips_without_repo_url():
    f = new_finding(
        purl="pkg:npm/x@1",
        vuln_id="CVE-1",
        severity="low",
        manifest_path="/tmp/p",
    )
    client = MagicMock()
    enrich_with_scorecard([f], client)
    client.get_score.assert_not_called()
    assert "scorecard" not in f
