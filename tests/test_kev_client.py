"""Tests for CISA KEV client.
Round 2 finding: KEV has no cpe/package_name field — joins via cveID only."""
from unittest.mock import patch, MagicMock
from scripts.lib.kev_client import KEVClient


def test_kev_lookup_by_cveid_present(tmp_state):
    fake_kev = {
        "vulnerabilities": [
            {"cveID": "CVE-2024-3094", "vendorProject": "Microsoft", "product": "xz-utils"},
            {"cveID": "CVE-2025-30066", "vendorProject": "tj-actions", "product": "changed-files"},
        ]
    }
    with patch("scripts.lib.kev_client.httpx.Client") as mock_client:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = fake_kev
        mock_response.text = '{"vulnerabilities": []}'  # for cache write
        mock_client.return_value.__enter__.return_value.get.return_value = mock_response
        client = KEVClient(cache_dir=tmp_state / "cache" / "kev")
        client.refresh()
        assert client.is_known_exploited("CVE-2024-3094") is True
        assert client.is_known_exploited("CVE-2025-30066") is True
        assert client.is_known_exploited("CVE-2099-99999") is False
