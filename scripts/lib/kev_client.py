"""CISA Known Exploited Vulnerabilities (KEV) client.

Round 2 finding: KEV has no cpe/package_name field — only cveID. Lookups
must go via cveID after a scanner has produced one. There are 1,558+ entries
as of April 2026 and the feed updates daily.

Feed lifecycle (TTL cache, atomic publish, degrade-once) lives in
FeedCacheClient. This class only knows the KEV URL and JSON shape.
"""
import json
from pathlib import Path

from scripts.lib.feed_cache import FeedCacheClient, DEFAULT_TTL_SECONDS

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KEVClient(FeedCacheClient):
    FEED_URL = KEV_URL
    CACHE_FILENAME = "known_exploited_vulnerabilities.json"
    TIMEOUT = 30.0

    def __init__(self, cache_dir: Path, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        super().__init__(cache_dir, ttl_seconds)
        self._known_set: set[str] = set()

    def _parse(self, path: Path) -> None:
        data = json.loads(path.read_text(encoding="utf-8"))
        known = {v["cveID"] for v in data.get("vulnerabilities", [])}
        if not known:
            raise ValueError("KEV feed parsed to zero entries")
        self._known_set = known

    def is_known_exploited(self, cve_id: str) -> bool:
        if not self._ensure_loaded():
            return False
        return cve_id in self._known_set
