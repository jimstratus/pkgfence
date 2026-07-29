"""DuckDuckGo web search for pkgfence lookup mode.

No auth required. Timed out per the CLI --timeout flag (default 8s).
"""
import httpx
from scripts.lib.logger import get_logger

log = get_logger(__name__)

DDG_API = "https://api.duckduckgo.com/"
ALLOWED_HOSTS = frozenset({"api.duckduckgo.com"})


def web_search(query: str, timeout: int = 8) -> dict:
    empty = {"abstract": None, "abstract_url": None, "related_topics": []}
    try:
        with httpx.Client(
            timeout=timeout, follow_redirects=True, max_redirects=3
        ) as client:
            resp = client.get(
                DDG_API,
                params={"q": query, "format": "json", "no_html": "1",
                        "skip_disambig": "1"},
            )
        # Redirect defense (mirrors GHSAHTTPClient): DuckDuckGo may redirect
        # by query/region; only render a response that landed on the DDG API.
        url = resp.url
        host = getattr(url, "host", None)
        scheme = getattr(url, "scheme", None)
        if host not in ALLOWED_HOSTS or (
            isinstance(scheme, str) and scheme.lower() != "https"
        ):
            log.warning("Web search landed on disallowed URL %s (host=%s)",
                        url, host)
            return empty
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
        return empty
    except (httpx.HTTPError, OSError):
        log.warning("Web search timed out or failed for query: %s", query)
        return empty


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
