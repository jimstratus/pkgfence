"""OSV.dev API client with file-system cache.

Round 2 finding R2-4: querybatch returns 400 if any single query in the batch
is malformed. Pre-validate locally before batching.

Round 2 finding: HTTP/2 negotiation avoids the 32 MiB response cap on HTTP/1.1.
P50 <= 500ms; no documented rate limits.

Critic gap M8: cache read errors fall through to live fetch (no silent failure).
"""
import hashlib
import json
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

import httpx

from scripts.lib.logger import get_logger

log = get_logger(__name__)


class OSVError(Exception):
    pass


OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"
_VULN_ID_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]")


def _validate_query(q: dict) -> None:
    if "package" not in q:
        raise OSVError(f"Query missing 'package': {q}")
    pkg = q["package"]
    if "name" not in pkg or "ecosystem" not in pkg:
        raise OSVError(f"Query package missing name/ecosystem: {q}")
    if "version" not in q and "commit" not in q:
        raise OSVError(f"Query missing 'version' or 'commit': {q}")


def _canonical_query_key(queries: list[dict]) -> str:
    """SHA256 of the canonical JSON encoding of the queries list.

    Sort keys so {a:1,b:2} and {b:2,a:1} produce the same hash.
    """
    canonical = json.dumps(queries, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class OSVClient:
    def __init__(
        self,
        timeout: float = 30.0,
        cache_dir: Optional[Path] = None,
        cache_ttl_hours: float = 6.0,
        max_429_retries: int = 3,
    ):
        self.timeout = timeout
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.cache_ttl_seconds = cache_ttl_hours * 3600
        self.max_429_retries = max_429_retries
        self.is_degraded = False
        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _cache_path(self, queries: list[dict]) -> Optional[Path]:
        if not self.cache_dir:
            return None
        key = _canonical_query_key(queries)
        return self.cache_dir / f"{key}.json"

    def _cache_get(self, queries: list[dict]) -> Optional[list[dict]]:
        """Return cached results if fresh; None otherwise.

        Catches IOError/OSError/JSONDecodeError/KeyError to fall through to
        live fetch on any cache I/O failure (M8 critic gap fix).
        """
        path = self._cache_path(queries)
        if not path or not path.exists():
            return None
        try:
            age = time.time() - path.stat().st_mtime
            if age > self.cache_ttl_seconds:
                return None
            data = json.loads(path.read_text(encoding="utf-8"))
            return data["results"]
        except (IOError, OSError, json.JSONDecodeError, KeyError) as e:
            log.warning("OSV cache read failed at %s: %s -- falling through to live fetch", path, e)
            return None

    def _cache_set(self, queries: list[dict], results: list[dict]) -> None:
        path = self._cache_path(queries)
        if not path:
            return
        # Atomic write (temp file + os.replace) so a concurrent run can't read
        # a half-written cache. Self-healing on parse failure regardless.
        try:
            fd, tmp = tempfile.mkstemp(prefix=".osv.", suffix=".json.tmp", dir=path.parent)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(json.dumps({"results": results}, separators=(",", ":")))
                os.replace(tmp, path)
            except Exception:
                if os.path.exists(tmp):
                    os.unlink(tmp)
                raise
        except (IOError, OSError) as e:
            log.warning("OSV cache write failed at %s: %s", path, e)

    def querybatch(self, queries: list[dict]) -> list[dict]:
        """Query OSV for a batch of (package, version) tuples.

        Pre-validates each query locally to avoid the 400-on-one-bad-query
        whole-batch failure.

        Checks file cache first if cache_dir is set; falls through to live
        fetch on cache miss or cache I/O failure.

        Returns the 'results' array from the OSV response.
        """
        for q in queries:
            _validate_query(q)
        if not queries:
            return []

        cached = self._cache_get(queries)
        if cached is not None:
            return cached

        with httpx.Client(http2=True, timeout=self.timeout) as client:
            for attempt in range(self.max_429_retries + 1):
                try:
                    resp = client.post(OSV_QUERYBATCH_URL, json={"queries": queries})
                except httpx.HTTPError as e:
                    raise OSVError(f"OSV request failed: {e}") from e
                if resp.status_code == 429:
                    if attempt < self.max_429_retries:
                        # exponential backoff: 1s, 2s, 4s
                        backoff = 2 ** attempt
                        log.warning("OSV 429 (attempt %d), backing off %ds", attempt + 1, backoff)
                        time.sleep(backoff)
                        continue
                    else:
                        self.is_degraded = True
                        raise OSVError(
                            f"OSV rate-limited after {self.max_429_retries} retries; marking feed degraded"
                        )
                break  # success or non-429 error
        if resp.status_code != 200:
            raise OSVError(f"OSV returned {resp.status_code}: {resp.text[:500]}")
        data = resp.json()
        results = data.get("results", [])
        self._cache_set(queries, results)
        return results

    def get_vuln(self, vuln_id: str) -> dict | None:
        """Fetch a vulnerability by its OSV id (MAL-..., GHSA-..., CVE-...).

        OSV is the canonical source for MAL-* malicious-package advisories,
        which are not in the GitHub Advisory Database. Per-id file cache under
        ``<cache_dir>/vulns/<id>.json`` keeps repeat lookups offline. Returns a
        compact dict or None on 404 / network failure.
        """
        cache_path = self._vuln_cache_path(vuln_id)
        if cache_path and cache_path.exists():
            try:
                age = time.time() - cache_path.stat().st_mtime
                if age < self.cache_ttl_seconds:
                    data = json.loads(cache_path.read_text(encoding="utf-8"))
                    if data.get("not_found"):
                        return None
                    return data
            except (IOError, OSError, json.JSONDecodeError) as e:
                log.warning("OSV vuln cache read failed at %s: %s", cache_path, e)

        try:
            with httpx.Client(http2=True, timeout=self.timeout) as client:
                resp = client.get(f"{OSV_VULN_URL}/{vuln_id}")
        except httpx.HTTPError as e:
            log.warning("OSV get_vuln failed for %s: %s", vuln_id, e)
            return None
        if resp.status_code == 404:
            if cache_path:
                self._write_vuln_cache(
                    cache_path, {"id": vuln_id, "not_found": True}
                )
            return None
        if resp.status_code != 200:
            return None
        try:
            data = resp.json()
        except ValueError:
            log.warning("OSV get_vuln response not valid JSON for %s", vuln_id)
            return None
        if not isinstance(data, dict):
            log.warning("OSV get_vuln response not a JSON object for %s", vuln_id)
            return None
        compact = {
            "id": data.get("id"),
            "summary": data.get("summary", ""),
            "details": data.get("details", ""),
            "aliases": data.get("aliases") or [],
            "severity": data.get("severity") or [],
            "affected": data.get("affected") or [],
            "published": data.get("published"),
            "modified": data.get("modified"),
            "withdrawn": data.get("withdrawn"),
        }
        if cache_path:
            self._write_vuln_cache(cache_path, compact)
        return compact

    def _vuln_cache_path(self, vuln_id: str) -> Optional[Path]:
        if not self.cache_dir:
            return None
        safe = _VULN_ID_SAFE_RE.sub("_", vuln_id)
        return self.cache_dir / "vulns" / f"{safe}.json"

    def _write_vuln_cache(self, path: Path, data: dict) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(data, ensure_ascii=False), encoding="utf-8"
            )
        except (IOError, OSError) as e:
            log.warning("OSV vuln cache write failed at %s: %s", path, e)
