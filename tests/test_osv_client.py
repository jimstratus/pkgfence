"""Tests for OSV.dev API client."""
from unittest.mock import patch, MagicMock
import json
import pytest

from scripts.lib.osv_client import OSVClient, OSVError


def test_single_query_lodash_known_vulnerable():
    """Mock the OSV response for a known-vulnerable lodash version."""
    fake_response = {
        "results": [
            {
                "vulns": [
                    {
                        "id": "GHSA-jf85-cpcp-j695",
                        "summary": "Prototype Pollution in lodash",
                        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                    }
                ]
            }
        ]
    }
    with patch("scripts.lib.osv_client.httpx.Client") as mock_client:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = fake_response
        mock_client.return_value.__enter__.return_value.post.return_value = mock_response
        client = OSVClient()
        results = client.querybatch([{"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.17.10"}])
    assert len(results) == 1
    assert len(results[0]["vulns"]) == 1
    assert results[0]["vulns"][0]["id"] == "GHSA-jf85-cpcp-j695"


def test_querybatch_rejects_missing_package():
    client = OSVClient()
    with pytest.raises(OSVError, match="package"):
        client.querybatch([{"version": "1.0"}])


def test_querybatch_rejects_missing_version():
    client = OSVClient()
    with pytest.raises(OSVError, match="version"):
        client.querybatch([{"package": {"name": "foo", "ecosystem": "npm"}}])


def test_osv_cache_hits_avoid_network(tmp_state):
    """Cached results are returned without invoking httpx."""
    client = OSVClient(cache_dir=tmp_state / "cache" / "osv", cache_ttl_hours=6)
    fake_results = [{"vulns": []}]
    queries = [{"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.17.21"}]
    # Manually populate cache
    client._cache_set(queries, fake_results)
    with patch("scripts.lib.osv_client.httpx.Client") as mock_client:
        results = client.querybatch(queries)
        mock_client.assert_not_called()
    assert results == fake_results


def test_osv_cache_readable_fallback_on_ioerror(tmp_state, monkeypatch):
    """Cache read errors fall through to live fetch (M8 critic gap)."""
    client = OSVClient(cache_dir=tmp_state / "cache" / "osv", cache_ttl_hours=6)
    queries = [{"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.17.21"}]
    # Pre-populate cache so a key exists
    client._cache_set(queries, [{"vulns": []}])
    # Now break Path.read_text to simulate cache file disappearance
    original = type(tmp_state).read_text
    def broken_read_text(self, *args, **kwargs):
        raise IOError("simulated cache disappearance")
    monkeypatch.setattr(type(tmp_state), "read_text", broken_read_text)
    # Cache lookup should fail gracefully and fall through to network
    fake_response = {"results": [{"vulns": []}]}
    with patch("scripts.lib.osv_client.httpx.Client") as mock_client:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = fake_response
        mock_client.return_value.__enter__.return_value.post.return_value = mock_response
        results = client.querybatch(queries)
    # Restored or not, the call should have produced results (either via fallback or via fresh fetch)
    assert results == [{"vulns": []}]


def test_osv_429_marks_degraded_after_max_retries(monkeypatch):
    """3x 429 in a row -> mark degraded mode and stop retrying."""
    monkeypatch.setattr("scripts.lib.osv_client.time.sleep", lambda s: None)
    client = OSVClient(max_429_retries=3)
    with patch("scripts.lib.osv_client.httpx.Client") as mock_client:
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.text = "Too Many Requests"
        mock_client.return_value.__enter__.return_value.post.return_value = mock_response
        with pytest.raises(OSVError, match="degraded"):
            client.querybatch([{"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.17.21"}])
    assert client.is_degraded is True


def test_get_vuln_returns_compact_dict(tmp_state):
    """MAL-* IDs resolve via OSV /v1/vulns/{id}."""
    fake = {
        "id": "MAL-0000-0000",
        "summary": "Malicious package",
        "details": "Exfiltrates env on install.",
        "aliases": ["CVE-2024-0000"],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [{"package": {"name": "badpkg", "ecosystem": "npm"}}],
        "published": "2024-01-01T00:00:00Z",
        "modified": "2024-06-01T00:00:00Z",
        "withdrawn": None,
    }
    with patch("scripts.lib.osv_client.httpx.Client") as mock_client:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = fake
        mock_client.return_value.__enter__.return_value.get.return_value = mock_response
        client = OSVClient(cache_dir=tmp_state / "cache" / "osv")
        result = client.get_vuln("MAL-0000-0000")
    assert result is not None
    assert result["id"] == "MAL-0000-0000"
    assert result["summary"] == "Malicious package"
    assert result["aliases"] == ["CVE-2024-0000"]


def test_get_vuln_404_returns_none(tmp_state):
    with patch("scripts.lib.osv_client.httpx.Client") as mock_client:
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_client.return_value.__enter__.return_value.get.return_value = mock_response
        client = OSVClient(cache_dir=tmp_state / "cache" / "osv")
        result = client.get_vuln("MAL-9999-9999")
    assert result is None


def test_get_vuln_cache_hit_avoids_network(tmp_state):
    client = OSVClient(cache_dir=tmp_state / "cache" / "osv", cache_ttl_hours=6)
    # Seed the per-id cache directly.
    seed = {"id": "MAL-0000-0001", "summary": "cached", "details": "",
            "aliases": [], "severity": [], "affected": [], "published": None,
            "modified": None, "withdrawn": None}
    client._write_vuln_cache(client._vuln_cache_path("MAL-0000-0001"), seed)
    with patch("scripts.lib.osv_client.httpx.Client") as mock_client:
        result = client.get_vuln("MAL-0000-0001")
        assert not mock_client.return_value.__enter__.return_value.get.called
    assert result["summary"] == "cached"


def test_get_vuln_invalid_json_returns_none(tmp_state):
    with patch("scripts.lib.osv_client.httpx.Client") as mock_client:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("bad json")
        mock_client.return_value.__enter__.return_value.get.return_value = mock_response
        client = OSVClient(cache_dir=tmp_state / "cache" / "osv")
        assert client.get_vuln("MAL-0000-0000") is None


def test_get_vuln_non_dict_returns_none(tmp_state):
    with patch("scripts.lib.osv_client.httpx.Client") as mock_client:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = ["not", "an", "object"]
        mock_client.return_value.__enter__.return_value.get.return_value = mock_response
        client = OSVClient(cache_dir=tmp_state / "cache" / "osv")
        assert client.get_vuln("MAL-0000-0000") is None
