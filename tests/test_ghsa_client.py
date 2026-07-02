"""Tests for GHSAHTTPClient — per-advisory REST fetch with file cache."""
import json
import os
import time
from pathlib import Path

import httpx
import pytest

from scripts.lib.ghsa_client import GHSAHTTPClient


def _make_advisory(ghsa_id="GHSA-abcd-efgh-ijkl") -> dict:
    return {
        "ghsa_id": ghsa_id,
        "cve_id": "CVE-2024-99999",
        "summary": "Test vulnerability",
        "description": "Full markdown description of the vulnerability.",
        "severity": "high",
        "cvss": {"score": 8.1, "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "cwes": [{"cwe_id": "CWE-1321", "name": "Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')"}],
        "html_url": "https://github.com/advisories/GHSA-abcd-efgh-ijkl",
        "published_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-06-01T00:00:00Z",
        "withdrawn_at": None,
    }


def _make_normalized_advisory(ghsa_id="GHSA-abcd-efgh-ijkl") -> dict:
    return {
        "ghsa_id": ghsa_id,
        "cve_id": "CVE-2024-99999",
        "summary": "Test vulnerability",
        "description": "Full markdown description of the vulnerability.",
        "severity": "high",
        "cvss_score": 8.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwes": ["CWE-1321"],
        "permalink": f"https://github.com/advisories/{ghsa_id}",
        "published_at": "2024-01-01T00:00:00Z",
        "updated_at": "2024-06-01T00:00:00Z",
        "withdrawn_at": None,
    }


def _mock_response(mocker, status_code=200, json_data=None, headers=None):
    resp = mocker.MagicMock(status_code=status_code)
    resp.json.return_value = json_data
    resp.headers = headers or {}
    resp.url = httpx.URL("https://api.github.com/advisories/GHSA-abcd-efgh-ijkl")
    mocker.patch("scripts.lib.ghsa_client.httpx.Client.get", return_value=resp)


class TestGHSAHTTPClientFetch:
    def test_fetch_returns_advisory(self, tmp_path, mocker):
        _mock_response(mocker, json_data=_make_advisory())
        client = GHSAHTTPClient(cache_dir=tmp_path / "ghsa")
        advisory = client.fetch("GHSA-abcd-efgh-ijkl")
        assert advisory is not None
        assert advisory["severity"] == "high"
        assert advisory["cve_id"] == "CVE-2024-99999"
        assert advisory["cwes"] == ["CWE-1321"]
        assert advisory["cvss_score"] == 8.1

    def test_fetch_returns_none_for_404(self, tmp_path, mocker):
        _mock_response(mocker, status_code=404)
        client = GHSAHTTPClient(cache_dir=tmp_path / "ghsa")
        advisory = client.fetch("GHSA-not-found-0000")
        assert advisory is None

    def test_fetch_caches_to_disk(self, tmp_path, mocker):
        _mock_response(mocker, json_data=_make_advisory())
        client = GHSAHTTPClient(cache_dir=tmp_path / "ghsa")
        client.fetch("GHSA-abcd-efgh-ijkl")
        cache_file = tmp_path / "ghsa" / "GHSA-abcd-efgh-ijkl.json"
        assert cache_file.exists()
        cached = json.loads(cache_file.read_text())
        assert cached["severity"] == "high"
        assert cached["cvss_score"] == 8.1

    def test_fetch_uses_cache_when_fresh(self, tmp_path, mocker):
        cache_dir = tmp_path / "ghsa"
        cache_dir.mkdir()
        (cache_dir / "GHSA-abcd-efgh-ijkl.json").write_text(
            json.dumps(_make_normalized_advisory()))

        mock_get = mocker.patch("scripts.lib.ghsa_client.httpx.Client.get")
        client = GHSAHTTPClient(cache_dir=cache_dir)
        advisory = client.fetch("GHSA-abcd-efgh-ijkl")

        mock_get.assert_not_called()
        assert advisory["severity"] == "high"

    def test_fetch_refetches_when_stale(self, tmp_path, mocker):
        cache_dir = tmp_path / "ghsa"
        cache_dir.mkdir()
        cache_file = cache_dir / "GHSA-abcd-efgh-ijkl.json"
        cache_file.write_text(json.dumps(_make_normalized_advisory()))
        old_time = time.time() - (5 * 60 * 60)
        os.utime(cache_file, (old_time, old_time))

        _mock_response(mocker, json_data=_make_advisory())
        client = GHSAHTTPClient(cache_dir=cache_dir)
        advisory = client.fetch("GHSA-abcd-efgh-ijkl")
        assert advisory is not None
        assert client.is_stale is False
        assert client.advisories_fetched == 1
        assert client.advisories_cached == 0

    def test_fetch_uses_stale_cache_on_network_failure(self, tmp_path, mocker):
        cache_dir = tmp_path / "ghsa"
        cache_dir.mkdir()
        cache_file = cache_dir / "GHSA-abcd-efgh-ijkl.json"
        cache_file.write_text(json.dumps(_make_normalized_advisory()))
        old_time = time.time() - (5 * 60 * 60)
        os.utime(cache_file, (old_time, old_time))

        mocker.patch("scripts.lib.ghsa_client.httpx.Client.get",
                     side_effect=httpx.HTTPError("network error"))
        client = GHSAHTTPClient(cache_dir=cache_dir)
        advisory = client.fetch("GHSA-abcd-efgh-ijkl")
        assert advisory is not None
        assert client.is_stale is True

    def test_fetch_writes_not_found_marker(self, tmp_path, mocker):
        resp = mocker.MagicMock(status_code=404)
        resp.url = httpx.URL("https://api.github.com/advisories/GHSA-xxxx-yyyy-zzzz")
        mocker.patch("scripts.lib.ghsa_client.httpx.Client.get", return_value=resp)
        client = GHSAHTTPClient(cache_dir=tmp_path / "ghsa")
        result = client.fetch("GHSA-xxxx-yyyy-zzzz")
        assert result is None
        marker_file = tmp_path / "ghsa" / "GHSA-xxxx-yyyy-zzzz.json"
        assert marker_file.exists()
        cached = json.loads(marker_file.read_text())
        assert cached.get("not_found") is True

    def test_fetch_skips_network_for_not_found_marker(self, tmp_path, mocker):
        cache_dir = tmp_path / "ghsa"
        cache_dir.mkdir()
        (cache_dir / "GHSA-xxxx-yyyy-zzzz.json").write_text(
            json.dumps({"ghsa_id": "GHSA-xxxx-yyyy-zzzz", "not_found": True}))

        mock_get = mocker.patch("scripts.lib.ghsa_client.httpx.Client.get")
        client = GHSAHTTPClient(cache_dir=cache_dir)
        result = client.fetch("GHSA-xxxx-yyyy-zzzz")
        assert result is None
        mock_get.assert_not_called()

    def test_fetch_handles_withdrawn_advisory(self, tmp_path, mocker):
        advisory_data = _make_advisory()
        advisory_data["withdrawn_at"] = "2025-01-01T00:00:00Z"
        _mock_response(mocker, json_data=advisory_data)
        client = GHSAHTTPClient(cache_dir=tmp_path / "ghsa")
        advisory = client.fetch("GHSA-abcd-efgh-ijkl")
        assert advisory is not None
        assert advisory["withdrawn_at"] == "2025-01-01T00:00:00Z"


class TestGHSAHTTPClientDegraded:
    def test_is_degraded_after_rate_limit(self, tmp_path, mocker):
        headers = {"X-RateLimit-Remaining": "0", "X-RateLimit-Limit": "60"}
        resp = mocker.MagicMock(status_code=429, headers=headers)
        resp.url = httpx.URL("https://api.github.com/advisories/GHSA-abcd-efgh-ijkl")
        mocker.patch("scripts.lib.ghsa_client.httpx.Client.get", return_value=resp)
        client = GHSAHTTPClient(cache_dir=tmp_path / "ghsa")
        result = client.fetch("GHSA-abcd-efgh-ijkl")
        assert result is None
        assert client.is_degraded is True

    def test_is_degraded_after_consecutive_errors(self, tmp_path, mocker):
        mocker.patch("scripts.lib.ghsa_client.httpx.Client.get",
                     side_effect=httpx.HTTPError("network error"))
        client = GHSAHTTPClient(cache_dir=tmp_path / "ghsa")
        client.fetch("GHSA-abcd-0001")
        assert not client.is_degraded
        client.fetch("GHSA-abcd-0002")
        assert not client.is_degraded
        client.fetch("GHSA-abcd-0003")
        assert client.is_degraded is True

    def test_degraded_blocks_further_fetches(self, tmp_path, mocker):
        mock_get = mocker.patch("scripts.lib.ghsa_client.httpx.Client.get",
                                side_effect=httpx.HTTPError("network error"))
        client = GHSAHTTPClient(cache_dir=tmp_path / "ghsa")
        for i in range(3):
            client.fetch(f"GHSA-abcd-{i:04d}")
        assert client.is_degraded is True
        call_count = mock_get.call_count
        client.fetch("GHSA-abcd-0004")
        assert mock_get.call_count == call_count  # no more calls


class TestGHSAHTTPClientToken:
    def test_token_from_env_used_in_headers(self, mocker, tmp_path):
        mock_get = mocker.patch("scripts.lib.ghsa_client.httpx.Client.get",
                                return_value=mocker.MagicMock(
                                    status_code=200,
                                    json=lambda: _make_advisory(),
                                    headers={},
                                    url=httpx.URL("https://api.github.com/advisories/GHSA-abcd-efgh-ijkl"),
                                ))
        client = GHSAHTTPClient(cache_dir=tmp_path / "ghsa", token="ghp_test123")
        client.fetch("GHSA-abcd-efgh-ijkl")
        call_kwargs = mock_get.call_args[1]
        assert call_kwargs["headers"]["Authorization"] == "Bearer ghp_test123"
        assert call_kwargs["headers"]["Accept"] == "application/vnd.github+json"

    def test_no_token_omits_auth_header(self, mocker, tmp_path):
        mock_get = mocker.patch("scripts.lib.ghsa_client.httpx.Client.get",
                                return_value=mocker.MagicMock(
                                    status_code=200,
                                    json=lambda: _make_advisory(),
                                    headers={},
                                    url=httpx.URL("https://api.github.com/advisories/GHSA-abcd-efgh-ijkl"),
                                ))
        client = GHSAHTTPClient(cache_dir=tmp_path / "ghsa", token=None)
        client.fetch("GHSA-abcd-efgh-ijkl")
        call_kwargs = mock_get.call_args[1]
        assert "Authorization" not in call_kwargs["headers"]


class TestGHSAHTTPClientRedirect:
    def test_disallowed_host_sets_degraded(self, tmp_path, mocker):
        resp = mocker.MagicMock(status_code=200)
        resp.url = httpx.URL("https://evil.example.com/advisories/GHSA-abcd-efgh-ijkl")
        resp.json.return_value = _make_advisory()
        mocker.patch("scripts.lib.ghsa_client.httpx.Client.get", return_value=resp)
        client = GHSAHTTPClient(cache_dir=tmp_path / "ghsa")
        result = client.fetch("GHSA-abcd-efgh-ijkl")
        assert result is None
