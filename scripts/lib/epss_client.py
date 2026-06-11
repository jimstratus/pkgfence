"""EPSS (Exploit Prediction Scoring System) client.

Feed lifecycle (TTL cache, atomic publish, degrade-once) lives in
FeedCacheClient. This class only knows the EPSS URL, the CSV shape, and
which redirect-target hosts are trustworthy.
"""
import csv
import datetime
import gzip
from pathlib import Path

import httpx

from scripts.lib.feed_cache import FeedCacheClient, DEFAULT_TTL_SECONDS
from scripts.lib.logger import get_logger

log = get_logger(__name__)

EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

# The empiricalsecurity.com host 302-redirects to dated CSV files on the same
# origin (e.g. epss_scores-2026-06-09.csv.gz). FeedCacheClient follows the
# redirect; we pin the final host to this allowlist to defend against a
# compromised origin or a hostile redirect chain to an attacker host (#3).
EPSS_ALLOWED_HOSTS = frozenset({"epss.empiricalsecurity.com"})


class EPSSClient(FeedCacheClient):
    FEED_URL = EPSS_URL
    CACHE_FILENAME = "epss_scores-current.csv.gz"
    TIMEOUT = 60.0

    def __init__(self, cache_dir: Path, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        super().__init__(cache_dir, ttl_seconds)
        self._scores: dict[str, tuple[float, float]] = {}

    def _validate_response(self, response: httpx.Response) -> None:
        """Reject a response whose post-redirect final URL left the EPSS host
        allowlist or dropped HTTPS — a compromised origin or hostile redirect
        chain (#3). Raises httpx.HTTPError, which FeedCacheClient.refresh()
        treats as a fetch failure (degraded/stale, never a poisoned cache)."""
        url = response.url
        host = getattr(url, "host", None)
        scheme = getattr(url, "scheme", None)
        if host not in EPSS_ALLOWED_HOSTS or (
            isinstance(scheme, str) and scheme.lower() != "https"
        ):
            log.warning(
                "EPSS feed landed on disallowed URL %s (host=%s scheme=%s)",
                url, host, scheme,
            )
            raise httpx.HTTPError(f"EPSS feed redirected to disallowed URL: {url}")

    def _parse(self, path: Path) -> None:
        """Stream-parse the gzipped CSV (never the whole blob in memory).
        Raises on gzip/CSV/encoding errors and on an empty feed."""
        scores: dict[str, tuple[float, float]] = {}
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
            # EPSS CSV has comment lines starting with # — skip them
            reader = csv.DictReader(line for line in fh if not line.startswith("#"))
            for row in reader:
                cve = (row.get("cve") or "").strip()
                try:
                    score = float(row.get("epss") or "0")
                    pct = float(row.get("percentile") or "0")
                except ValueError:
                    continue
                if cve:
                    scores[cve] = (score, pct)
        if not scores:
            raise ValueError("EPSS feed parsed to zero rows")
        self._scores = scores

    def lookup(self, cve_id: str) -> tuple[float, float] | None:
        if not self._ensure_loaded():
            return None
        return self._scores.get(cve_id)

    @property
    def feed_timestamp(self) -> str | None:
        if not self.cache_path.exists():
            return None
        mtime = self.cache_path.stat().st_mtime
        return datetime.datetime.fromtimestamp(
            mtime, tz=datetime.timezone.utc
        ).isoformat()
