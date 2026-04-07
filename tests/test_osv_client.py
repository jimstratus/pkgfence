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
