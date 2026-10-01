"""Tests for scripts/lookup_websearch.py — DDG query builder + redirect defense."""
from unittest.mock import MagicMock, patch

import httpx

from scripts.lookup_websearch import build_search_query, web_search


def test_build_search_query_cve_ghsa_package():
    assert "CVE-2019-10744" in build_search_query(
        {"type": "cve", "value": "CVE-2019-10744"}
    )
    assert "GHSA-jf85-cpcp-j695" in build_search_query(
        {"type": "ghsa", "value": "GHSA-jf85-cpcp-j695"}
    )
    q = build_search_query({
        "type": "package", "value": "npm:lodash@4.17.10",
        "name": "lodash", "ecosystem": "npm",
    })
    assert "lodash" in q and "npm" in q


def test_build_search_query_free_text_passthrough():
    assert build_search_query(
        {"type": "free_text", "value": "shai-hulud worm"}
    ) == "shai-hulud worm"


def test_web_search_parses_successful_response():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.url = MagicMock(host="api.duckduckgo.com", scheme="https")
    mock_resp.json.return_value = {
        "AbstractText": "  Lodash advisory.  ",
        "AbstractURL": "https://example.com",
        "RelatedTopics": [
            {"Text": "Topic A", "FirstURL": "https://a.example"},
            {"Text": "", "FirstURL": "https://skip"},
            {"Text": "Topic B"},
        ],
    }
    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.__exit__.return_value = False
    mock_client.get.return_value = mock_resp

    with patch("scripts.lookup_websearch.httpx.Client", return_value=mock_client):
        result = web_search("CVE-2019-10744 vulnerability")

    assert result["abstract"] == "Lodash advisory."
    assert result["abstract_url"] == "https://example.com"
    assert result["related_topics"] == [
        {"text": "Topic A", "url": "https://a.example"},
        {"text": "Topic B", "url": None},
    ]


def test_web_search_rejects_disallowed_redirect_host():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.url = MagicMock(host="evil.example", scheme="https")
    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.__exit__.return_value = False
    mock_client.get.return_value = mock_resp

    with patch("scripts.lookup_websearch.httpx.Client", return_value=mock_client):
        result = web_search("CVE-1")

    assert result == {"abstract": None, "abstract_url": None, "related_topics": []}


def test_web_search_returns_empty_on_http_error():
    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.__exit__.return_value = False
    mock_client.get.side_effect = httpx.ConnectTimeout("timeout")

    with patch("scripts.lookup_websearch.httpx.Client", return_value=mock_client):
        result = web_search("CVE-1")

    assert result["abstract"] is None
    assert result["related_topics"] == []
