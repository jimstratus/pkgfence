"""EPSS (Exploit Prediction Scoring System) client.

Mirrors KEVClient pattern: bulk CSV download from FIRST.org, 24h TTL,
in-memory dict lookup keyed by CVE ID.
"""
import csv
import datetime
import gzip
import time
from pathlib import Path

import httpx

from scripts.lib.logger import get_logger

log = get_logger(__name__)

EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
DEFAULT_TTL_SECONDS = 24 * 60 * 60  # 24h

# The empiricalsecurity.com host 302-redirects to dated CSV files on the same
# origin (e.g. epss_scores-2026-06-09.csv.gz). We follow the redirect but pin
# the final URL host to this allowlist to defend against a compromised origin
# or a malicious redirect chain pointing at an attacker-controlled host.
EPSS_ALLOWED_HOSTS = frozenset({"epss.empiricalsecurity.com"})
MAX_REDIRECTS = 3


class EPSSClient:
    def __init__(self, cache_dir: Path, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_path = self.cache_dir / "epss_scores-current.csv.gz"
        self.ttl_seconds = ttl_seconds
        self._scores: dict[str, tuple[float, float]] = {}
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
                client_kwargs: dict = {
                    "timeout": 60.0,
                    "follow_redirects": True,
                    "max_redirects": MAX_REDIRECTS,
                }
                with httpx.Client(**client_kwargs) as client:
                    resp = client.get(EPSS_URL)
                self._validate_final_host(resp)
                if resp.status_code == 200:
                    self.cache_path.write_bytes(resp.content)
                    self._parse_into_memory(resp.content)
                    self._loaded = True
                    loaded_from_network = True
                else:
                    log.warning("EPSS fetch returned %d, marking degraded", resp.status_code)
                    self.is_degraded = True
            except httpx.HTTPError as e:
                log.warning("EPSS fetch failed: %s, marking degraded", e)
                self.is_degraded = True
        if not loaded_from_network and self.cache_path.exists():
            try:
                self._parse_into_memory(self.cache_path.read_bytes())
                self._loaded = True
            except (OSError, gzip.BadGzipFile, csv.Error) as e:
                log.warning("EPSS cache parse failed: %s", e)
                self.is_degraded = True

    @staticmethod
    def _validate_final_host(response: httpx.Response) -> None:
        """Reject the response if a redirect chain landed on a non-allowlisted host.

        The empiricalsecurity.com origin 302-redirects to dated CSV files on
        the same origin; any other landing host indicates either a compromised
        origin or a hostile redirect chain, so we treat it as a fetch failure.
        """
        url = response.url
        host = getattr(url, "host", None)
        scheme = getattr(url, "scheme", None)
        if host not in EPSS_ALLOWED_HOSTS or (
            isinstance(scheme, str) and scheme.lower() != "https"
        ):
            log.warning(
                "EPSS feed landed on disallowed URL %s (host=%s scheme=%s)",
                url,
                host,
                scheme,
            )
            raise httpx.HTTPError(f"EPSS feed redirected to disallowed URL: {url}")

    def _parse_into_memory(self, blob: bytes) -> None:
        decompressed = gzip.decompress(blob).decode("utf-8", errors="replace")
        # EPSS CSV has comment lines starting with # — skip them
        lines = [line for line in decompressed.splitlines() if not line.startswith("#")]
        reader = csv.DictReader(lines)
        scores: dict[str, tuple[float, float]] = {}
        for row in reader:
            cve = (row.get("cve") or "").strip()
            try:
                score = float(row.get("epss") or "0")
                pct = float(row.get("percentile") or "0")
            except ValueError:
                continue
            if cve:
                scores[cve] = (score, pct)
        self._scores = scores

    def lookup(self, cve_id: str) -> tuple[float, float] | None:
        if not self._loaded:
            self.refresh()
        return self._scores.get(cve_id)

    @property
    def feed_timestamp(self) -> str | None:
        if not self.cache_path.exists():
            return None
        mtime = self.cache_path.stat().st_mtime
        return datetime.datetime.fromtimestamp(
            mtime, tz=datetime.timezone.utc
        ).isoformat()
