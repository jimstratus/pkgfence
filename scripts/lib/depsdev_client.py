"""deps.dev v3alpha REST client — package metadata and transitive dependency graphs.

Per-package JSON file cache. No auth required. Free tier, no rate limits.
"""
import json
import time
from pathlib import Path

import httpx

from scripts.lib.logger import get_logger

log = get_logger(__name__)

DEPSDEV_API = "https://api.deps.dev/v3alpha"
DEFAULT_TTL_SECONDS = 24 * 60 * 60


class DepsDevClient:
    def __init__(self, cache_dir: Path, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl_seconds = ttl_seconds
        self.is_degraded = False
        self.is_stale = False
        self.packages_fetched = 0
        self.packages_cached = 0
        self._consecutive_network_errors = 0
        self._ecosystem_map = {
            "npm": "npm", "pypi": "pypi", "cargo": "cargo",
            "rubygems": "rubygems", "go": "go", "maven": "maven",
        }

    def fetch_metadata(self, ecosystem: str, name: str, version: str) -> dict | None:
        if self.is_degraded:
            return None
        cache_path = self._cache_path(ecosystem, name, version)
        if self._is_cache_fresh(cache_path):
            self.packages_cached += 1
            return self._load_cache(cache_path)
        data = self._fetch_version(ecosystem, name, version, cache_path)
        if data is not None:
            self.packages_fetched += 1
            return data
        if cache_path.exists():
            self.is_stale = True
            self.packages_cached += 1
            return self._load_cache(cache_path)
        return None

    def _cache_path(self, ecosystem: str, name: str, version: str) -> Path:
        return self.cache_dir / ecosystem / name / f"{version}.json"

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

    def _fetch_version(self, ecosystem: str, name: str, version: str,
                       cache_path: Path) -> dict | None:
        deps_eco = self._ecosystem_map.get(ecosystem)
        if not deps_eco:
            return None
        try:
            with httpx.Client(timeout=15.0) as client:
                resp = client.get(
                    f"{DEPSDEV_API}/systems/{deps_eco}/packages/{name}"
                    f"/versions/{version}")
            if resp.status_code == 200:
                data = resp.json()
                metadata = self._normalize(ecosystem, name, version, data)
                self._write_cache(cache_path, metadata)
                self._consecutive_network_errors = 0
                return metadata
            if resp.status_code == 404:
                self._consecutive_network_errors = 0
                return None
            self._consecutive_network_errors += 1
            self._check_degrade()
            return None
        except httpx.HTTPError as e:
            log.warning("deps.dev fetch failed for %s/%s@%s: %s",
                        ecosystem, name, version, e)
            self._consecutive_network_errors += 1
            self._check_degrade()
            return None

    def _check_degrade(self) -> None:
        if self._consecutive_network_errors >= 3:
            log.warning("deps.dev client degraded after %d consecutive errors",
                        self._consecutive_network_errors)
            self.is_degraded = True

    def _normalize(self, ecosystem: str, name: str, version: str,
                   response: dict) -> dict:
        links = []
        for l in response.get("links") or []:
            links.append({"label": l.get("label", ""), "url": l.get("url", "")})
        return {
            "ecosystem": ecosystem,
            "name": name,
            "version": version,
            "description": response.get("description"),
            "licenses": response.get("licenses") or [],
            "links": links,
            "is_direct": response.get("isDirect", False),
            "transitive_path": [],
            "advisories_count": len(response.get("advisoryKeys") or []),
        }
