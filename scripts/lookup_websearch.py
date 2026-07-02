"""DuckDuckGo web search for pkgfence lookup mode.

No auth required. Timed out per the CLI --timeout flag (default 8s).
"""
import httpx
from scripts.lib.logger import get_logger

log = get_logger(__name__)

DDG_API = "https://api.duckduckgo.com/"


def web_search(query: str, timeout: int = 8) -> dict:
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(
                DDG_API,
                params={"q": query, "format": "json", "no_html": "1",
                        "skip_disambig": "1"},
            )
        if resp.status_code == 200:
            data = resp.json()
            return {
                "abstract": (data.get("AbstractText") or "").strip() or None,
                "abstract_url": data.get("AbstractURL"),
                "related_topics": [
                    {"text": t.get("Text", ""), "url": t.get("FirstURL")}
                    for t in (data.get("RelatedTopics") or [])
                    if t.get("Text")
                ][:8],
            }
        return {"abstract": None, "abstract_url": None, "related_topics": []}
    except (httpx.HTTPError, OSError):
        log.warning("Web search timed out or failed for query: %s", query)
        return {"abstract": None, "abstract_url": None, "related_topics": []}


def build_search_query(parsed: dict) -> str | None:
    t = parsed["type"]
    if t == "cve":
        return f"{parsed['value']} vulnerability exploit analysis"
    if t == "ghsa":
        return f"{parsed['value']} advisory github"
    if t in ("package", "purl"):
        name = parsed.get("name", parsed["value"])
        eco = parsed.get("ecosystem", "")
        return f"{name} vulnerability {eco}".strip()
    return parsed["value"]
