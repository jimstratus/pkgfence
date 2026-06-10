import gzip
import os
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import httpx
import pytest

from scripts.lib.epss_client import EPSSClient


def _make_epss_csv_gz() -> bytes:
    csv = (
        "#model_version:v2025.03.14,score_date:2026-04-10T00:00:00+0000\n"
        "cve,epss,percentile\n"
        "CVE-2024-12345,0.95432,0.99876\n"
        "CVE-2023-99999,0.00100,0.10000\n"
    )
    return gzip.compress(csv.encode("utf-8"))


def test_refresh_downloads_and_caches(tmp_path, mocker):
    cache_dir = tmp_path / "epss"
    blob = _make_epss_csv_gz()
    mock_resp = mocker.MagicMock(status_code=200, content=blob)
    mocker.patch("scripts.lib.feed_cache.httpx.Client.get", return_value=mock_resp)

    client = EPSSClient(cache_dir=cache_dir)
    client.refresh()

    assert (cache_dir / "epss_scores-current.csv.gz").exists()
    assert client.lookup("CVE-2024-12345") == (0.95432, 0.99876)


def test_lookup_returns_none_for_missing_cve(tmp_path, mocker):
    blob = _make_epss_csv_gz()
    mock_resp = mocker.MagicMock(status_code=200, content=blob)
    mocker.patch("scripts.lib.feed_cache.httpx.Client.get", return_value=mock_resp)

    client = EPSSClient(cache_dir=tmp_path / "epss")
    client.refresh()
    assert client.lookup("CVE-9999-9999") is None


def test_refresh_uses_cache_when_fresh(tmp_path, mocker):
    cache_dir = tmp_path / "epss"
    cache_dir.mkdir()
    cache_file = cache_dir / "epss_scores-current.csv.gz"
    cache_file.write_bytes(_make_epss_csv_gz())

    mock_get = mocker.patch("scripts.lib.feed_cache.httpx.Client.get")
    client = EPSSClient(cache_dir=cache_dir)
    client.refresh()

    mock_get.assert_not_called()
    assert client.lookup("CVE-2024-12345") == (0.95432, 0.99876)


def test_refresh_redownloads_when_stale(tmp_path, mocker):
    cache_dir = tmp_path / "epss"
    cache_dir.mkdir()
    cache_file = cache_dir / "epss_scores-current.csv.gz"
    cache_file.write_bytes(_make_epss_csv_gz())
    old_time = time.time() - (25 * 60 * 60)
    os.utime(cache_file, (old_time, old_time))

    mock_resp = mocker.MagicMock(status_code=200, content=_make_epss_csv_gz())
    mock_get = mocker.patch("scripts.lib.feed_cache.httpx.Client.get", return_value=mock_resp)

    client = EPSSClient(cache_dir=cache_dir)
    client.refresh()
    mock_get.assert_called_once()


def test_refresh_sets_degraded_on_http_error(tmp_path, mocker):
    mocker.patch(
        "scripts.lib.feed_cache.httpx.Client.get",
        side_effect=httpx.HTTPError("network error"),
    )
    client = EPSSClient(cache_dir=tmp_path / "epss")
    client.refresh()
    assert client.is_degraded is True
    assert client.lookup("CVE-2024-12345") is None


def test_feed_timestamp_returned_after_refresh(tmp_path, mocker):
    blob = _make_epss_csv_gz()
    mock_resp = mocker.MagicMock(status_code=200, content=blob)
    mocker.patch("scripts.lib.feed_cache.httpx.Client.get", return_value=mock_resp)

    client = EPSSClient(cache_dir=tmp_path / "epss")
    client.refresh()
    assert client.feed_timestamp is not None
    assert "T" in client.feed_timestamp  # ISO format


def test_feed_timestamp_none_when_no_cache(tmp_path):
    client = EPSSClient(cache_dir=tmp_path / "epss")
    assert client.feed_timestamp is None


def test_corrupt_200_response_never_poisons_cache(tmp_path):
    """Issue #12A: an HTTP 200 with a non-gzip body (captive portal) must
    not be written to the cache nor marked fresh."""
    client = EPSSClient(cache_dir=tmp_path)
    resp = MagicMock(status_code=200, content=b"<html>not a feed</html>")
    with patch("scripts.lib.feed_cache.httpx.Client") as mock_client:
        mock_client.return_value.__enter__.return_value.get.return_value = resp
        client.refresh()
    assert client.is_degraded
    assert not client.cache_path.exists()  # nothing poisoned


def test_degraded_lookup_does_not_retry_network_per_cve(tmp_path):
    """Issue #12B: after one failed refresh, N lookups must not trigger
    N downloads."""
    client = EPSSClient(cache_dir=tmp_path)
    with patch("scripts.lib.feed_cache.httpx.Client") as mock_client:
        mock_client.return_value.__enter__.return_value.get.side_effect = (
            httpx.ConnectError("boom")
        )
        client.refresh()
        for i in range(50):
            assert client.lookup(f"CVE-2024-{i:04d}") is None
        assert mock_client.return_value.__enter__.return_value.get.call_count == 1
    assert client.is_degraded


def test_stale_cache_fallback_is_flagged_not_degraded(tmp_path):
    """Review I2: a failed network refresh that serves an expired on-disk
    cache must set is_stale (operator-visible), not silently succeed."""
    client = EPSSClient(cache_dir=tmp_path)
    client.cache_path.write_bytes(_make_epss_csv_gz())
    old = time.time() - (client.ttl_seconds + 3600)  # past TTL
    os.utime(client.cache_path, (old, old))
    with patch("scripts.lib.feed_cache.httpx.Client") as mock_client:
        mock_client.return_value.__enter__.return_value.get.side_effect = (
            httpx.ConnectError("boom")
        )
        client.refresh()
    assert client.is_stale is True
    assert client.is_degraded is False
    assert client.lookup("CVE-2024-12345") is not None  # stale data still served


def test_empty_feed_raises_and_degrades(tmp_path):
    """Review M5: an all-rows-skipped feed (schema drift) degrades rather
    than silently enriching nothing."""
    client = EPSSClient(cache_dir=tmp_path)
    empty = gzip.compress(b"cve,epss,percentile\n")  # header only, zero rows
    resp = MagicMock(status_code=200, content=empty)
    with patch("scripts.lib.feed_cache.httpx.Client") as mock_client:
        mock_client.return_value.__enter__.return_value.get.return_value = resp
        client.refresh()
    assert client.is_degraded
    assert not client.cache_path.exists()
