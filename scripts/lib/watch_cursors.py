"""Watch cursors — track last-seen IDs per threat-intel feed.

Enables watch mode to detect new entries in KEV, GHSA, MAL feeds by
comparing current feed state against prior cursors.
"""
import json
import re
from pathlib import Path
from typing import Any

_ID_SPLIT_RE = re.compile(r"[-_]")


def _id_sort_key(identifier: str) -> tuple:
    """Sort key that orders CVE/GHSA/MAL IDs by their numeric parts.

    CVE/GHSA/MAL identifiers are not monotonic in plain string order:
    ``'CVE-2025-9999' < 'CVE-2025-10000'`` lexicographically (because ``'9' >
    '1'``), so a string max would skip every 5-digit ID after a 4-digit cursor.
    Splitting on ``-``/``_`` and coercing digit runs to int gives correct
    numeric ordering within a feed (IDs in one feed share a structure, so the
    resulting tuples are comparable).
    """
    return tuple(int(p) if p.isdigit() else p for p in _ID_SPLIT_RE.split(identifier))


def load_cursors(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def save_cursors(path: Path, cursors: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cursors, indent=2, sort_keys=True), encoding="utf-8")


def update_cursor(cursors: dict[str, Any], feed: str, last_id: str) -> dict[str, Any]:
    cursors[feed] = {"last_id": last_id}
    return cursors


def find_new_ids(
    current_ids: set[str], feed: str, cursors: dict[str, Any]
) -> set[str]:
    """Return IDs in ``current_ids`` not seen in the prior cursor.

    Set-based, not threshold-based: CISA KEV routinely adds older CVEs after
    newer ones, so feed insertion order does NOT match CVE numeric order. A
    ``last_id`` high-water mark would silently drop a newly-added
    ``CVE-2021-*`` once the cursor has reached ``CVE-2025-*``. Persisting the
    full seen set and diffing catches out-of-order additions correctly.

    Legacy cursors written with only ``last_id`` (no ``seen_ids``) are migrated
    silently: emit no new entries this one cycle so the entire feed isn't
    replayed as "new". The caller then persists ``seen_ids = current``, after
    which subsequent cycles diff correctly.
    """
    feed_cursor = cursors.get(feed, {})
    if "seen_ids" in feed_cursor:
        seen = set(feed_cursor.get("seen_ids") or [])
        if not seen:
            return current_ids
        return current_ids - seen
    if feed_cursor.get("last_id") is not None:
        # Legacy cursor shape from a prior version — migrate without replaying.
        return set()
    # No prior cursor at all: first run, everything is new.
    return current_ids
