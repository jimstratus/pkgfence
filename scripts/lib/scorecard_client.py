"""OpenSSF Scorecard REST client — per-repo health scores.

Per-repo JSON file cache. No auth required. 7d TTL (scores change slowly).
"""
import json
import time
from pathlib import Path

import httpx

from scripts.lib.logger import get_logger

log = get_logger(__name__)

SCORECARD_API = "https://api.securityscorecards.dev"
DEFAULT_TTL_SECONDS = 7 * 24 * 60 * 60


class ScorecardClient:
    def __init__(self, cache_dir: Path, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl_seconds = ttl_seconds
        self.is_degraded = False
        self.is_stale = False
        self.repos_fetched = 0
        self.repos_cached = 0
        self._consecutive_network_errors = 0

    def get_score(self, owner: str, repo: str) -> dict | None:
        if self.is_degraded:
            return None
        cache_path = self._cache_path(owner, repo)
        if self._is_cache_fresh(cache_path):
            self.repos_cached += 1
            return self._load_cache(cache_path)
        result = self._fetch_score(owner, repo, cache_path)
        if result is not None:
            self.repos_fetched += 1
            return result
        if cache_path.exists():
            self.is_stale = True
            self.repos_cached += 1
            return self._load_cache(cache_path)
        return None

    def _cache_path(self, owner: str, repo: str) -> Path:
        return self.cache_dir / owner / f"{repo}.json"

    def _is_cache_fresh(self, cache_path: Path) -> bool:
        if not cache_path.exists():
            return False
        return (time.time() - cache_path.stat().st_mtime) < self.ttl_seconds

    def _load_cache(self, cache_path: Path) -> dict | None:
        try:
            return json.loads(cache_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

    def _write_cache(self, cache_path: Path, data: dict) -> None:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

    def _fetch_score(self, owner: str, repo: str, cache_path: Path) -> dict | None:
        try:
            with httpx.Client(timeout=15.0) as client:
                resp = client.get(
                    f"{SCORECARD_API}/projects/github.com/{owner}/{repo}")
            if resp.status_code == 200:
                data = resp.json()
                result = self._normalize(data)
                self._write_cache(cache_path, result)
                self._consecutive_network_errors = 0
                return result
            if resp.status_code == 404:
                self._consecutive_network_errors = 0
                return None
            self._consecutive_network_errors += 1
            self._check_degrade()
            return None
        except httpx.HTTPError as e:
            log.warning("Scorecard fetch failed for %s/%s: %s", owner, repo, e)
            self._consecutive_network_errors += 1
            self._check_degrade()
            return None

    def _check_degrade(self) -> None:
        if self._consecutive_network_errors >= 3:
            log.warning("Scorecard client degraded after %d consecutive errors",
                        self._consecutive_network_errors)
            self.is_degraded = True

    def _normalize(self, response: dict) -> dict:
        return {
            "repo": response.get("repo", {}).get("name", ""),
            "score": response.get("score", 0.0),
            "date": response.get("date", ""),
            "checks": response.get("checks") or [],
            "badge_url": response.get("scorecard", {}).get("badge") or None,
        }
