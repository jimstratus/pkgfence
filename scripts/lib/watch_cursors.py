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
    prior = cursors.get(feed, {}).get("last_id")
    if not prior:
        return current_ids
    prior_key = _id_sort_key(prior)
    return {i for i in current_ids if _id_sort_key(i) > prior_key}
