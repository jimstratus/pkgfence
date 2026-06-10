"""Shared cached-feed lifecycle for the KEV and EPSS clients (issue #18.3).

Both feeds follow the same pattern: bulk download with a TTL'd on-disk cache,
parse into memory, and a degraded mode. Correctness rules (issue #12):

- A downloaded blob is parsed/validated BEFORE it is published to the cache,
  and the publish is atomic (temp file + os.replace). A corrupt HTTP 200 can
  never poison the cache or be marked fresh.
- Any parse failure marks the client degraded instead of escaping.
- Degraded trips AT MOST ONCE per run: once degraded, no further network
  attempts are made (a feed outage degrades the scan once, not per-finding).
"""
import os
import time
from pathlib import Path

import httpx

from scripts.lib.logger import get_logger

log = get_logger(__name__)

DEFAULT_TTL_SECONDS = 24 * 60 * 60  # 24h


class FeedCacheClient:
    """Base class. Subclasses set FEED_URL, CACHE_FILENAME, TIMEOUT and
    implement _parse(path) — which must raise on invalid content and only
    mutate in-memory state on success."""

    FEED_URL: str = ""
    CACHE_FILENAME: str = ""
    TIMEOUT: float = 30.0

    def __init__(self, cache_dir: Path, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_path = self.cache_dir / self.CACHE_FILENAME
        self.ttl_seconds = ttl_seconds
        self._loaded = False
        self.is_degraded = False

    def _is_cache_fresh(self) -> bool:
        if not self.cache_path.exists():
            return False
        age = time.time() - self.cache_path.stat().st_mtime
        return age < self.ttl_seconds

    def refresh(self) -> None:
        """Load the feed into memory: network if the cache is stale, else
        disk. Never raises; failure sets is_degraded. No-op once loaded or
        degraded (degrade-once)."""
        if self._loaded or self.is_degraded:
            return
        if not self._is_cache_fresh():
            tmp_path = self.cache_path.with_suffix(self.cache_path.suffix + ".tmp")
            try:
                with httpx.Client(timeout=self.TIMEOUT) as client:
                    resp = client.get(self.FEED_URL)
                if resp.status_code == 200:
                    tmp_path.write_bytes(resp.content)
                    self._parse(tmp_path)  # validate BEFORE publishing
                    os.replace(tmp_path, self.cache_path)
                    self._loaded = True
                    return
                log.warning("%s fetch returned %d",
                            type(self).__name__, resp.status_code)
            except httpx.HTTPError as e:
                log.warning("%s fetch failed: %s", type(self).__name__, e)
            except Exception as e:  # noqa: BLE001 — corrupt blob (gzip/CSV/JSON/...)
                log.warning("%s response invalid: %s", type(self).__name__, e)
            finally:
                tmp_path.unlink(missing_ok=True)
        # Fall back to whatever is on disk (fresh, or stale-but-present).
        if self.cache_path.exists():
            try:
                self._parse(self.cache_path)
                self._loaded = True
                return
            except Exception as e:  # noqa: BLE001
                log.warning("%s cache parse failed: %s", type(self).__name__, e)
        self.is_degraded = True

    def _ensure_loaded(self) -> bool:
        """Lazy-load hook for lookup methods. Returns True if data is
        available. Never triggers a second network attempt once degraded
        (issue #12B)."""
        if not self._loaded and not self.is_degraded:
            self.refresh()
        return self._loaded

    def _parse(self, path: Path) -> None:
        raise NotImplementedError
