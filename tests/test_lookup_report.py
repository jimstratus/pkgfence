"""Tests for scripts/lookup_report.py — markdown/JSON lookup renderers."""
import json

from scripts.lookup_report import render_lookup_json, render_lookup_markdown


def test_render_lookup_markdown_includes_advisory_and_footer():
    parsed = {"type": "cve", "value": "CVE-2019-10744"}
    advisory = {
        "kev": True,
        "epss": {"score": 0.97, "percentile": 0.99},
        "ghsa": None,  # skipped
    }
    md = render_lookup_markdown(parsed, advisory, None, 1.25, ["kev", "epss"])
    assert md.startswith("---\nlookup_id: CVE-2019-10744\n")
    assert "# Lookup: CVE-2019-10744" in md
    assert "### KEV" in md
    assert "**Actively exploited:** True" in md
    assert "### EPSS" in md
    assert "**score:** 0.97" in md
    assert "### GHSA" not in md
    assert "Sources: kev, epss" in md
    assert "1.2s" in md or "1.3s" in md


def test_render_lookup_markdown_empty_advisory():
    parsed = {"type": "cve", "value": "CVE-2099-1"}
    md = render_lookup_markdown(parsed, {}, None, 0.1, [])
    assert "_No advisory data found for CVE-2099-1._" in md


def test_render_lookup_markdown_web_section():
    parsed = {"type": "cve", "value": "CVE-2019-10744"}
    web = {
        "abstract": "Prototype pollution in lodash.",
        "abstract_url": "https://example.com/a",
        "related_topics": [
            {"text": "Analysis", "url": "https://example.com/b"},
            {"text": "No URL topic", "url": ""},
        ],
    }
    md = render_lookup_markdown(parsed, {"kev": False}, web, 0.5, ["kev", "web"])
    assert "## Web Search" in md
    assert "Prototype pollution in lodash." in md
    assert "[https://example.com/a](https://example.com/a)" in md
    assert "[Analysis](https://example.com/b)" in md
    assert "- No URL topic" in md


def test_render_lookup_json_roundtrips():
    parsed = {"type": "ghsa", "value": "GHSA-jf85-cpcp-j695"}
    advisory = {"ghsa": {"ghsa_id": "GHSA-jf85-cpcp-j695", "cve_id": "CVE-2019-10744"}}
    raw = render_lookup_json(parsed, advisory, None, 2.345, ["ghsa"])
    data = json.loads(raw)
    assert data["lookup_id"] == "GHSA-jf85-cpcp-j695"
    assert data["type"] == "ghsa"
    assert data["advisory"]["ghsa"]["cve_id"] == "CVE-2019-10744"
    assert data["web_search"] is None
    assert data["elapsed_seconds"] == 2.35
    assert data["sources_consulted"] == ["ghsa"]
