"""Tests for CISA KEV client.
Round 2 finding: KEV has no cpe/package_name field — joins via cveID only."""
import json
from unittest.mock import patch, MagicMock

import httpx

from scripts.lib.kev_client import KEVClient


def test_kev_lookup_by_cveid_present(tmp_state):
    fake_kev = {
        "vulnerabilities": [
            {"cveID": "CVE-2024-3094", "vendorProject": "Microsoft", "product": "xz-utils"},
            {"cveID": "CVE-2025-30066", "vendorProject": "tj-actions", "product": "changed-files"},
        ]
    }
    with patch("scripts.lib.feed_cache.httpx.Client") as mock_client:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = json.dumps(fake_kev).encode("utf-8")
        mock_client.return_value.__enter__.return_value.get.return_value = mock_response
        client = KEVClient(cache_dir=tmp_state / "cache" / "kev")
        client.refresh()
        assert client.is_known_exploited("CVE-2024-3094") is True
        assert client.is_known_exploited("CVE-2025-30066") is True
        assert client.is_known_exploited("CVE-2099-99999") is False


def test_kev_marks_degraded_on_non_200(tmp_state):
    """KEV fetch returning non-200 marks the client as degraded."""
    with patch("scripts.lib.feed_cache.httpx.Client") as mock_client:
        mock_response = MagicMock()
        mock_response.status_code = 503
        mock_response.text = "Service Unavailable"
        mock_client.return_value.__enter__.return_value.get.return_value = mock_response
        client = KEVClient(cache_dir=tmp_state / "cache" / "kev")
        client.refresh()
    assert client.is_degraded is True
    # Without cache file, _known_set should be empty
    assert client.is_known_exploited("CVE-2024-3094") is False


def test_kev_marks_degraded_on_httpx_error(tmp_state):
    """Network failure during KEV fetch marks client as degraded."""
    with patch("scripts.lib.feed_cache.httpx.Client") as mock_client:
        mock_client.return_value.__enter__.return_value.get.side_effect = httpx.ConnectError("network down")
        client = KEVClient(cache_dir=tmp_state / "cache" / "kev")
        client.refresh()
    assert client.is_degraded is True


def test_corrupt_200_response_never_poisons_cache(tmp_path):
    """Issue #12A: an HTTP 200 with a non-JSON body (captive portal) must
    not be written to the cache nor marked fresh."""
    client = KEVClient(cache_dir=tmp_path)
    resp = MagicMock(status_code=200, content=b"<html>not a feed</html>")
    with patch("scripts.lib.feed_cache.httpx.Client") as mock_client:
        mock_client.return_value.__enter__.return_value.get.return_value = resp
        client.refresh()
    assert client.is_degraded
    assert not client.cache_path.exists()  # nothing poisoned


def test_degraded_lookup_does_not_retry_network_per_cve(tmp_path):
    """Issue #12B: after one failed refresh, N lookups must not trigger
    N downloads."""
    client = KEVClient(cache_dir=tmp_path)
    with patch("scripts.lib.feed_cache.httpx.Client") as mock_client:
        mock_client.return_value.__enter__.return_value.get.side_effect = (
            httpx.ConnectError("boom")
        )
        client.refresh()
        for i in range(50):
            assert client.is_known_exploited(f"CVE-2024-{i:04d}") is False
        assert mock_client.return_value.__enter__.return_value.get.call_count == 1
    assert client.is_degraded
