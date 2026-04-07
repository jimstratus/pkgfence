"""CISA Known Exploited Vulnerabilities (KEV) client.

Round 2 finding: KEV has no cpe/package_name field — only cveID. Lookups
must go via cveID after a scanner has produced one. There are 1,558+ entries
as of April 2026 and the feed updates daily.
"""
import json
import time
from pathlib import Path
import httpx

from scripts.lib.logger import get_logger

log = get_logger(__name__)


KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_TTL_SECONDS = 24 * 60 * 60  # 24h


class KEVClient:
    def __init__(self, cache_dir: Path, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_path = self.cache_dir / "known_exploited_vulnerabilities.json"
        self.ttl_seconds = ttl_seconds
        self._known_set: set[str] = set()
        self._loaded = False
        self.is_degraded = False

    def _is_cache_fresh(self) -> bool:
        if not self.cache_path.exists():
            return False
        age = time.time() - self.cache_path.stat().st_mtime
        return age < self.ttl_seconds

    def refresh(self) -> None:
        loaded_from_network = False
        if not self._is_cache_fresh():
            try:
                with httpx.Client(timeout=30.0) as client:
                    resp = client.get(KEV_URL)
                if resp.status_code == 200:
                    self.cache_path.write_text(resp.text, encoding="utf-8")
                    # Use the live response, not a re-read of disk
                    data = resp.json()
                    self._known_set = {v["cveID"] for v in data.get("vulnerabilities", [])}
                    self._loaded = True
                    loaded_from_network = True
                else:
                    log.warning("KEV fetch returned %d, marking degraded", resp.status_code)
                    self.is_degraded = True
            except httpx.HTTPError as e:
                log.warning("KEV fetch failed: %s, marking degraded", e)
                self.is_degraded = True
        if not loaded_from_network and self.cache_path.exists():
            try:
                data = json.loads(self.cache_path.read_text(encoding="utf-8"))
                self._known_set = {v["cveID"] for v in data.get("vulnerabilities", [])}
                self._loaded = True
            except (json.JSONDecodeError, KeyError, OSError) as e:
                log.warning("KEV cache parse failed: %s", e)
                self.is_degraded = True

    def is_known_exploited(self, cve_id: str) -> bool:
        if not self._loaded:
            self.refresh()
        return cve_id in self._known_set
