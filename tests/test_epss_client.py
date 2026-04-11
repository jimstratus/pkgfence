import gzip
import os
import time
from pathlib import Path

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
    mocker.patch("scripts.lib.epss_client.httpx.Client.get", return_value=mock_resp)

    client = EPSSClient(cache_dir=cache_dir)
    client.refresh()

    assert (cache_dir / "epss_scores-current.csv.gz").exists()
    assert client.lookup("CVE-2024-12345") == (0.95432, 0.99876)


def test_lookup_returns_none_for_missing_cve(tmp_path, mocker):
    blob = _make_epss_csv_gz()
    mock_resp = mocker.MagicMock(status_code=200, content=blob)
    mocker.patch("scripts.lib.epss_client.httpx.Client.get", return_value=mock_resp)

    client = EPSSClient(cache_dir=tmp_path / "epss")
    client.refresh()
    assert client.lookup("CVE-9999-9999") is None


def test_refresh_uses_cache_when_fresh(tmp_path, mocker):
    cache_dir = tmp_path / "epss"
    cache_dir.mkdir()
    cache_file = cache_dir / "epss_scores-current.csv.gz"
    cache_file.write_bytes(_make_epss_csv_gz())

    mock_get = mocker.patch("scripts.lib.epss_client.httpx.Client.get")
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
    mock_get = mocker.patch("scripts.lib.epss_client.httpx.Client.get", return_value=mock_resp)

    client = EPSSClient(cache_dir=cache_dir)
    client.refresh()
    mock_get.assert_called_once()


def test_refresh_sets_degraded_on_http_error(tmp_path, mocker):
    mocker.patch(
        "scripts.lib.epss_client.httpx.Client.get",
        side_effect=httpx.HTTPError("network error"),
    )
    client = EPSSClient(cache_dir=tmp_path / "epss")
    client.refresh()
    assert client.is_degraded is True
    assert client.lookup("CVE-2024-12345") is None


def test_feed_timestamp_returned_after_refresh(tmp_path, mocker):
    blob = _make_epss_csv_gz()
    mock_resp = mocker.MagicMock(status_code=200, content=blob)
    mocker.patch("scripts.lib.epss_client.httpx.Client.get", return_value=mock_resp)

    client = EPSSClient(cache_dir=tmp_path / "epss")
    client.refresh()
    assert client.feed_timestamp is not None
    assert "T" in client.feed_timestamp  # ISO format


def test_feed_timestamp_none_when_no_cache(tmp_path):
    client = EPSSClient(cache_dir=tmp_path / "epss")
    assert client.feed_timestamp is None
