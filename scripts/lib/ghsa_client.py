"""GitHub Advisory Database (GHSA) REST client.

Per-advisory lazy lookup with per-ID file caching. Not a FeedCacheClient
subclass — GHSA lookups are individual REST calls, not bulk downloads.

Token handling: checks GITHUB_TOKEN then GH_TOKEN env vars at init time.
Proceeds unauthenticated if neither is set (60 req/hr vs 5000/hr).

Rate limit exhaustion sets is_degraded = True. 3+ consecutive network
errors also degrade the client. Once degraded, no further network requests.

Cache: one JSON file per GHSA ID at cache_dir/<GHSA-id>.json. TTL defaults
to 4h (14400s). Not-found markers ({"ghsa_id": "...", "not_found": true})
prevent repeated 404 lookups.

Redirect defense: final URL host must be api.github.com (ALLOWED_HOSTS).
"""
import json
import os
import time
from pathlib import Path

import httpx

from scripts.lib.logger import get_logger

log = get_logger(__name__)

GHSA_API_BASE = "https://api.github.com/advisories"
DEFAULT_TTL_SECONDS = 4 * 60 * 60
ALLOWED_HOSTS = frozenset({"api.github.com"})


def _resolve_token() -> str | None:
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or None


class GHSAHTTPClient:
    def __init__(
        self,
        cache_dir: Path,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        token: str | None = None,
    ):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl_seconds = ttl_seconds
        self.token = token
        self.is_degraded = False
        self.is_stale = False
        self.advisories_fetched = 0
        self.advisories_cached = 0
        self._consecutive_network_errors = 0

    def fetch(self, ghsa_id: str) -> dict | None:
        if self.is_degraded:
            return None
        cache_path = self._cache_path(ghsa_id)
        if self._is_cache_fresh(cache_path):
            self.advisories_cached += 1
            return self._load_cache(cache_path)
        advisory = self._fetch_from_network(ghsa_id, cache_path)
        if advisory is not None:
            self.advisories_fetched += 1
            return advisory
        if cache_path.exists():
            self.is_stale = True
            self.advisories_cached += 1
            return self._load_cache(cache_path)
        return None

    def _cache_path(self, ghsa_id: str) -> Path:
        return self.cache_dir / f"{ghsa_id}.json"

    def _is_cache_fresh(self, cache_path: Path) -> bool:
        if not cache_path.exists():
            return False
        age = time.time() - cache_path.stat().st_mtime
        return age < self.ttl_seconds

    def _load_cache(self, cache_path: Path) -> dict | None:
        try:
            data = json.loads(cache_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        if data.get("not_found"):
            return None
        return data

    def _write_cache(self, cache_path: Path, data: dict) -> None:
        cache_path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

    def _fetch_from_network(self, ghsa_id: str, cache_path: Path) -> dict | None:
        try:
            headers = {"Accept": "application/vnd.github+json"}
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
            with httpx.Client(
                timeout=30.0, follow_redirects=True, max_redirects=3
            ) as client:
                resp = client.get(f"{GHSA_API_BASE}/{ghsa_id}", headers=headers)
            url = resp.url
            host = getattr(url, "host", None)
            scheme = getattr(url, "scheme", None)
            if host not in ALLOWED_HOSTS or (
                isinstance(scheme, str) and scheme.lower() != "https"
            ):
                log.warning(
                    "GHSA fetch landed on disallowed URL %s (host=%s)",
                    url, host,
                )
                self._consecutive_network_errors += 1
                self._check_degrade_on_errors()
                return None
            if resp.status_code == 404:
                self._write_cache(cache_path, {"ghsa_id": ghsa_id, "not_found": True})
                self._consecutive_network_errors = 0
                return None
            if resp.status_code == 200:
                data = resp.json()
                advisory = self._normalize(ghsa_id, data)
                self._write_cache(cache_path, advisory)
                self._consecutive_network_errors = 0
                return advisory
            if resp.status_code in (429, 403):
                remaining = resp.headers.get("X-RateLimit-Remaining")
                if remaining == "0":
                    log.warning(
                        "GHSA rate limit exhausted — marking client degraded"
                    )
                    self.is_degraded = True
                self._consecutive_network_errors += 1
                self._check_degrade_on_errors()
                return None
            self._consecutive_network_errors += 1
            self._check_degrade_on_errors()
            return None
        except httpx.HTTPError as e:
            log.warning("GHSA fetch failed for %s: %s", ghsa_id, e)
            self._consecutive_network_errors += 1
            self._check_degrade_on_errors()
            return None

    def _check_degrade_on_errors(self) -> None:
        if self._consecutive_network_errors >= 3:
            log.warning(
                "GHSA client degraded after %d consecutive network errors",
                self._consecutive_network_errors,
            )
            self.is_degraded = True

    def _normalize(self, ghsa_id: str, response: dict) -> dict:
        cwes_raw = response.get("cwes") or []
        cvss = response.get("cvss") or {}
        advisory = {
            "ghsa_id": ghsa_id,
            "cve_id": response.get("cve_id"),
            "summary": response.get("summary", ""),
            "description": response.get("description", ""),
            "severity": (response.get("severity") or "").lower(),
            "cvss_score": cvss.get("score"),
            "cvss_vector": cvss.get("vector_string"),
            "cwes": [c["cwe_id"] for c in cwes_raw if c.get("cwe_id")],
            "permalink": response.get("html_url")
            or f"https://github.com/advisories/{ghsa_id}",
            "published_at": response.get("published_at"),
            "updated_at": response.get("updated_at"),
            "withdrawn_at": response.get("withdrawn_at"),
        }
        return advisory
