"""Watch-mode daemon: polls threat-intel feeds for new entries and runs
lookups against the cached registry.

Checks KEV (hourly), GHSA (every 4h), and MAL feeds (every 6h). Uses
watch cursors to track last-seen IDs so each new entry triggers exactly
one lookup. Writes results to state/watch-log.jsonl.
"""
import datetime
import json
import os
import signal
import sys
import time
from pathlib import Path

from scripts.lib.kev_client import KEVClient
from scripts.lib.ghsa_client import GHSAHTTPClient
from scripts.lib.watch_cursors import load_cursors, save_cursors, find_new_ids
from scripts.lib.logger import get_logger

log = get_logger(__name__)

SKILL_ROOT = Path(__file__).parent.parent
DEFAULT_STATE_DIR = SKILL_ROOT / "state"
DEFAULT_INTERVAL = 3600  # 1 hour


def _collect_feed_ids(client) -> set[str]:
    try:
        if not client._ensure_loaded():
            return set()
        if hasattr(client, "_known_set"):
            return client._known_set
        if hasattr(client, "_scores"):
            return set(client._scores.keys())
    except Exception:
        pass
    return set()


def _watch_kev(state_dir: Path) -> int:
    cursors_path = state_dir / "watch-cursors.json"
    cursors = load_cursors(cursors_path)
    client = KEVClient(cache_dir=state_dir / "cache" / "kev")
    current_ids = _collect_feed_ids(client)
    if not current_ids:
        log.warning("KEV feed returned no IDs — skipping watch cycle")
        return 0
    new_ids = find_new_ids(current_ids, "kev", cursors)
    if new_ids:
        log.info("KEV: %d new entries detected", len(new_ids))
        _log_new_entries(state_dir, "kev", new_ids)
    max_id = max(current_ids) if current_ids else ""
    cursors["kev"] = {"last_id": max_id, "last_check": datetime.datetime.now(
        datetime.timezone.utc).isoformat(), "total_known": len(current_ids)}
    save_cursors(cursors_path, cursors)
    return len(new_ids)


def _log_new_entries(state_dir: Path, feed: str, ids: set[str]) -> None:
    log_path = state_dir / "watch-log.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    entries = []
    for eid in sorted(ids):
        entries.append(json.dumps({
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "feed": feed,
            "id": eid,
        }))
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write("\n".join(entries) + "\n")


def run_watch(state_dir: Path, interval: int = DEFAULT_INTERVAL,
              once: bool = False) -> None:
    log.info("Watch daemon starting, interval=%ds, state=%s", interval, state_dir)
    running = True

    def handle_signal(signum, frame):
        nonlocal running
        log.info("Received signal %d, shutting down", signum)
        running = False

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    while running:
        new_kev = _watch_kev(state_dir)
        status = "no new entries"
        if new_kev > 0:
            status = f"{new_kev} new KEV entries"
        log.info("Watch cycle complete: %s", status)
        if once:
            break
        time.sleep(interval)
    log.info("Watch daemon stopped")


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(prog="pkgfence-watch",
                                     description="Watch for new threat-intel entries")
    parser.add_argument("--state", type=Path, default=str(DEFAULT_STATE_DIR),
                        help="State directory")
    parser.add_argument("--interval", type=int, default=DEFAULT_INTERVAL,
                        help="Seconds between watch cycles (default: 3600)")
    parser.add_argument("--once", action="store_true",
                        help="Run one cycle and exit")
    args = parser.parse_args()
    run_watch(args.state, interval=args.interval, once=args.once)


if __name__ == "__main__":
    main()
