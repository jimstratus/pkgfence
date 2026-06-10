"""EPSS (Exploit Prediction Scoring System) client.

Feed lifecycle (TTL cache, atomic publish, degrade-once) lives in
FeedCacheClient. This class only knows the EPSS URL and CSV shape.
"""
import csv
import datetime
import gzip
from pathlib import Path

from scripts.lib.feed_cache import FeedCacheClient, DEFAULT_TTL_SECONDS

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


class EPSSClient(FeedCacheClient):
    FEED_URL = EPSS_URL
    CACHE_FILENAME = "epss_scores-current.csv.gz"
    TIMEOUT = 60.0

    def __init__(self, cache_dir: Path, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        super().__init__(cache_dir, ttl_seconds)
        self._scores: dict[str, tuple[float, float]] = {}

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
