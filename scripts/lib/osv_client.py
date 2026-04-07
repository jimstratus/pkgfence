"""OSV.dev API client.

Round 2 finding R2-4: querybatch returns 400 if any single query in the batch
is malformed. Pre-validate locally before batching.

Round 2 finding: HTTP/2 negotiation avoids the 32 MiB response cap on HTTP/1.1.
P50 <= 500ms; no documented rate limits.
"""
import httpx
from typing import Any


class OSVError(Exception):
    pass


OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"


def _validate_query(q: dict) -> None:
    if "package" not in q:
        raise OSVError(f"Query missing 'package': {q}")
    pkg = q["package"]
    if "name" not in pkg or "ecosystem" not in pkg:
        raise OSVError(f"Query package missing name/ecosystem: {q}")
    if "version" not in q and "commit" not in q:
        raise OSVError(f"Query missing 'version' or 'commit': {q}")


class OSVClient:
    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout

    def querybatch(self, queries: list[dict]) -> list[dict]:
        """Query OSV for a batch of (package, version) tuples.

        Pre-validates each query locally to avoid the 400-on-one-bad-query
        whole-batch failure.

        Returns the 'results' array from the OSV response. Each entry is
        a dict with 'vulns' (list) or empty if no vulns.
        """
        for q in queries:
            _validate_query(q)
        if not queries:
            return []
        with httpx.Client(http2=True, timeout=self.timeout) as client:
            try:
                resp = client.post(OSV_QUERYBATCH_URL, json={"queries": queries})
            except httpx.HTTPError as e:
                raise OSVError(f"OSV request failed: {e}") from e
        if resp.status_code != 200:
            raise OSVError(f"OSV returned {resp.status_code}: {resp.text[:500]}")
        data = resp.json()
        return data.get("results", [])
