"""Watch cursors — track last-seen IDs per threat-intel feed.

Enables watch mode to detect new entries in KEV, GHSA, MAL feeds by
comparing current feed state against prior cursors.
"""
import json
from pathlib import Path
from typing import Any


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
    return {i for i in current_ids if i > prior}
