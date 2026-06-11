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
import portalocker

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
    # Feed hosts may 301/302 to a canonical or dated URL; follow a bounded
    # chain. Subclasses pin the acceptable final host via _validate_response.
    MAX_REDIRECTS: int = 3

    def __init__(self, cache_dir: Path, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_path = self.cache_dir / self.CACHE_FILENAME
        self.ttl_seconds = ttl_seconds
        self._loaded = False
        self.is_degraded = False
        # True when a network refresh failed and we are serving an
        # expired on-disk cache. Distinct from is_degraded (no data at all)
        # so the operator still sees the feed is not current (review I2).
        self.is_stale = False

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
        network_attempted = not self._is_cache_fresh()
        if network_attempted:
            # Per-process tmp name: a concurrent run must not write the
            # tmp file another process already validated, which would
            # publish unvalidated bytes through our os.replace (review I1).
            tmp_path = self.cache_path.with_suffix(
                f"{self.cache_path.suffix}.{os.getpid()}.tmp"
            )
            try:
                with httpx.Client(
                    timeout=self.TIMEOUT,
                    follow_redirects=True,
                    max_redirects=self.MAX_REDIRECTS,
                ) as client:
                    resp = client.get(self.FEED_URL)
                if resp.status_code == 200:
                    # Reject a post-redirect landing host the subclass doesn't
                    # trust (hostile redirect chain / compromised origin, #3).
                    self._validate_response(resp)
                    tmp_path.write_bytes(resp.content)
                    self._parse(tmp_path)  # validate BEFORE publishing
                    # Serialize the publish so a concurrent run can't read a
                    # half-written cache between our truncate and rename.
                    with portalocker.Lock(
                        str(self.cache_path) + ".lock", timeout=30
                    ):
                        os.replace(tmp_path, self.cache_path)
                    self._loaded = True
                    return
                log.warning("%s fetch returned %d",
                            type(self).__name__, resp.status_code)
            except httpx.HTTPError as e:
                log.warning("%s fetch failed: %s", type(self).__name__, e)
            except Exception:  # noqa: BLE001 — corrupt blob (gzip/CSV/JSON/...)
                log.warning("%s response invalid", type(self).__name__,
                            exc_info=True)
            finally:
                tmp_path.unlink(missing_ok=True)
        # Fall back to whatever is on disk (fresh, or stale-but-present).
        if self.cache_path.exists():
            try:
                self._parse(self.cache_path)
                self._loaded = True
                # A network attempt was made and failed, yet we loaded the
                # cache → the data on disk is past its TTL (review I2).
                self.is_stale = network_attempted
                return
            except Exception:  # noqa: BLE001
                log.warning("%s cache parse failed", type(self).__name__,
                            exc_info=True)
        self.is_degraded = True

    def _ensure_loaded(self) -> bool:
        """Lazy-load hook for lookup methods. Returns True if data is
        available. Never triggers a second network attempt once degraded
        (issue #12B)."""
        if not self._loaded and not self.is_degraded:
            self.refresh()
        return self._loaded

    def _validate_response(self, response: "httpx.Response") -> None:
        """Hook: reject an untrusted post-redirect response. Default no-op
        (the feed's own host is trusted). Subclasses that follow redirects
        to a different host override this to pin an allowlist (#3). Raise
        httpx.HTTPError to mark the fetch failed/degraded."""

    def _parse(self, path: Path) -> None:
        raise NotImplementedError
